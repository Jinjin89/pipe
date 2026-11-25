// SPDX-License-Identifier: GPL-3.0-or-later
//go:build darwin

package webview

import (
	"errors"
	"fmt"
	"sync"
	"time"
	"unsafe"

	"pipe/internal/menubar"

	"github.com/ebitengine/purego"
	"github.com/ebitengine/purego/objc"
)

type nsPoint struct{ X, Y float64 }
type nsSize struct{ W, H float64 }
type nsRect struct {
	Origin nsPoint
	Size   nsSize
}

// objcBlock matches the 64-bit Clang/Apple Objective-C Block ABI layout
// (arm64 and amd64). invoke is at offset 16.
type objcBlock struct {
	isa      uintptr
	flags    int32
	reserved int32
	invoke   uintptr
}

const (
	windowStyleMask = uint(1 | 2 | 4 | 8) // Titled | Closable | Miniaturizable | Resizable
	backingBuffered = uint(2)             // NSBackingStoreBuffered
	viewResizeBoth  = uint(2 | 16)        // NSViewWidthSizable | NSViewHeightSizable

	policyRegular   = 0 // NSApplicationActivationPolicyRegular
	policyAccessory = 1 // NSApplicationActivationPolicyAccessory

	navPolicyCancel = 0 // WKNavigationActionPolicyCancel
	navPolicyAllow  = 1 // WKNavigationActionPolicyAllow

	defaultWidth  = 1000
	defaultHeight = 700
	minWidth      = 820
	minHeight     = 560

	provisionalRetryDelay = time.Second
)

// Window represents an open macOS WKWebView window.
type Window struct {
	origin     Origin
	initialURL string

	mu                 sync.Mutex
	win                objc.ID
	webView            objc.ID
	delegate           objc.ID
	closed             bool
	provisionalRetries int
	retryTimer         *time.Timer

	doneOnce sync.Once
	done     chan struct{}
}

var (
	initOnce    sync.Once
	initErr     error
	delegateCls objc.Class
	cbKeep      []any

	regMu   sync.Mutex
	windows = map[objc.ID]*Window{} // delegate ID -> Window
)

func sel(name string) objc.SEL { return objc.RegisterName(name) }

func nsString(s string) objc.ID {
	return objc.ID(objc.GetClass("NSString")).Send(sel("stringWithUTF8String:"), s)
}

func nsStringToGo(s objc.ID) string {
	if s == 0 {
		return ""
	}
	p := objc.Send[*byte](s, sel("UTF8String"))
	if p == nil {
		return ""
	}
	n := 0
	for n < 64<<10 && *(*byte)(unsafe.Add(unsafe.Pointer(p), n)) != 0 {
		n++
	}
	return string(unsafe.Slice(p, n))
}

func invokeDecisionHandler(handler objc.ID, policy int) {
	defer func() { recover() }()
	if handler == 0 {
		return
	}
	blk := (*objcBlock)(*(*unsafe.Pointer)(unsafe.Pointer(&handler)))
	if blk.invoke != 0 {
		purego.SyscallN(blk.invoke, uintptr(handler), uintptr(policy))
	}
}

func setupWebKit() error {
	initOnce.Do(func() {
		for _, fw := range []string{
			"/System/Library/Frameworks/AppKit.framework/AppKit",
			"/System/Library/Frameworks/Foundation.framework/Foundation",
			"/System/Library/Frameworks/WebKit.framework/WebKit",
		} {
			if _, err := purego.Dlopen(fw, purego.RTLD_GLOBAL|purego.RTLD_LAZY); err != nil {
				initErr = fmt.Errorf("webview: load %s: %w", fw, err)
				return
			}
		}
		for _, c := range []string{
			"NSApplication", "NSWindow", "NSMenu", "NSMenuItem", "NSObject", "NSString",
			"NSURL", "NSURLRequest",
			"WKWebView", "WKWebViewConfiguration", "WKWebsiteDataStore",
		} {
			if objc.GetClass(c) == 0 {
				initErr = fmt.Errorf("webview: class %s not found", c)
				return
			}
		}
		methods := []objc.MethodDef{
			{
				Cmd: sel("windowWillClose:"),
				Fn: func(self objc.ID, _ objc.SEL, note objc.ID) {
					defer func() { recover() }()
					onWindowWillClose(self)
				},
			},
			{
				Cmd: sel("webView:decidePolicyForNavigationAction:decisionHandler:"),
				Fn: func(self objc.ID, _ objc.SEL, wv, action, handler objc.ID) {
					policy := navPolicyCancel
					defer func() {
						recover()
						invokeDecisionHandler(handler, policy)
					}()
					policy = onDecideNavigation(self, action)
				},
			},
			{
				Cmd: sel("webView:didFinishNavigation:"),
				Fn: func(self objc.ID, _ objc.SEL, wv, nav objc.ID) {
					defer func() { recover() }()
					onDidFinishNavigation(self)
				},
			},
			{
				Cmd: sel("webView:didFailProvisionalNavigation:withError:"),
				Fn: func(self objc.ID, _ objc.SEL, wv, nav, errObj objc.ID) {
					defer func() { recover() }()
					onDidFailProvisional(self, errObj)
				},
			},
			{
				Cmd: sel("webViewWebContentProcessDidTerminate:"),
				Fn: func(self objc.ID, _ objc.SEL, wv objc.ID) {
					defer func() { recover() }()
					onContentProcessTerminated(self, wv)
				},
			},
			{
				Cmd: sel("webView:createWebViewWithConfiguration:forNavigationAction:windowFeatures:"),
				Fn: func(self objc.ID, _ objc.SEL, wv, cfg, action, features objc.ID) objc.ID {
					return 0 // nil: never allow popups
				},
			},
		}
		for _, m := range methods {
			cbKeep = append(cbKeep, m.Fn)
		}
		cls, err := objc.RegisterClass("PipeWebViewDelegate", objc.GetClass("NSObject"), nil, nil, methods)
		if err != nil {
			initErr = fmt.Errorf("webview: register delegate: %w", err)
			return
		}
		delegateCls = cls
	})
	return initErr
}

func lookupWindow(delegate objc.ID) *Window {
	regMu.Lock()
	w := windows[delegate]
	regMu.Unlock()
	return w
}

func onDecideNavigation(delegate, action objc.ID) int {
	w := lookupWindow(delegate)
	if w == nil || action == 0 {
		return navPolicyCancel
	}
	req := action.Send(sel("request"))
	if req == 0 {
		return navPolicyCancel
	}
	nsURL := req.Send(sel("URL"))
	if nsURL == 0 {
		return navPolicyCancel
	}
	target := nsStringToGo(nsURL.Send(sel("absoluteString")))
	if w.origin.DecideNavigation(target) {
		return navPolicyAllow
	}
	return navPolicyCancel
}

func reloadWebView(wv objc.ID, initialURL string) {
	if wv == 0 {
		return
	}
	if wv.Send(sel("URL")) != 0 {
		wv.Send(sel("reload"))
		return
	}
	cls := objc.GetClass
	if nsURL := objc.ID(cls("NSURL")).Send(sel("URLWithString:"), nsString(initialURL)); nsURL != 0 {
		req := objc.ID(cls("NSURLRequest")).Send(sel("requestWithURL:"), nsURL)
		wv.Send(sel("loadRequest:"), req)
	}
}

func onContentProcessTerminated(delegate, wv objc.ID) {
	w := lookupWindow(delegate)
	if w == nil {
		return
	}
	w.mu.Lock()
	closed := w.closed
	target := wv
	if target == 0 {
		target = w.webView
	}
	w.mu.Unlock()
	if !closed && target != 0 {
		reloadWebView(target, w.initialURL)
	}
}

func onDidFinishNavigation(delegate objc.ID) {
	w := lookupWindow(delegate)
	if w == nil {
		return
	}
	w.mu.Lock()
	w.provisionalRetries = 0
	if w.retryTimer != nil {
		w.retryTimer.Stop()
		w.retryTimer = nil
	}
	w.mu.Unlock()
}

func onDidFailProvisional(delegate, errObj objc.ID) {
	w := lookupWindow(delegate)
	if w == nil {
		return
	}
	code := 0
	if errObj != 0 {
		code = objc.Send[int](errObj, sel("code"))
	}
	w.mu.Lock()
	if w.closed || !shouldRetryProvisional(w.provisionalRetries, code) {
		w.mu.Unlock()
		return
	}
	w.provisionalRetries++
	if w.retryTimer != nil {
		w.retryTimer.Stop()
	}
	w.retryTimer = time.AfterFunc(provisionalRetryDelay, w.reloadOnMain)
	w.mu.Unlock()
}

func (w *Window) reloadOnMain() {
	_ = menubar.OnMain(func() {
		w.mu.Lock()
		wv := w.webView
		closed := w.closed
		w.mu.Unlock()
		if !closed && wv != 0 {
			reloadWebView(wv, w.initialURL)
		}
	})
}

func onWindowWillClose(delegate objc.ID) {
	regMu.Lock()
	w := windows[delegate]
	delete(windows, delegate)
	remaining := len(windows)
	regMu.Unlock()

	if w != nil {
		w.mu.Lock()
		win, wv, del, timer := w.win, w.webView, w.delegate, w.retryTimer
		w.win, w.webView, w.delegate, w.retryTimer, w.closed = 0, 0, 0, nil, true
		w.mu.Unlock()

		if timer != nil {
			timer.Stop()
		}
		if wv != 0 {
			wv.Send(sel("stopLoading"))
			wv.Send(sel("setNavigationDelegate:"), objc.ID(0))
			wv.Send(sel("setUIDelegate:"), objc.ID(0))
		}
		if win != 0 {
			win.Send(sel("setDelegate:"), objc.ID(0))
			win.Send(sel("setContentView:"), objc.ID(0))
		}
		if wv != 0 {
			wv.Send(sel("autorelease"))
		}
		if win != 0 {
			win.Send(sel("autorelease"))
		}
		if del != 0 {
			del.Send(sel("autorelease"))
		}
		w.doneOnce.Do(func() { close(w.done) })
	}

	if remaining == 0 {
		// Return to menu bar only (no Dock icon) once no Pipe window is open.
		app := objc.ID(objc.GetClass("NSApplication")).Send(sel("sharedApplication"))
		if app != 0 {
			app.Send(sel("setActivationPolicy:"), policyAccessory)
		}
	}
}

// ensureMainMenu installs standard App and Edit menu items on [NSApp mainMenu]
// so Cmd+C, Cmd+V, Cmd+X, Cmd+A, Cmd+Z, Cmd+W and Cmd+Q work inside WKWebView.
func ensureMainMenu(app objc.ID) {
	if app.Send(sel("mainMenu")) != 0 {
		return
	}
	cls := objc.GetClass
	newItem := func(title, action, key string) objc.ID {
		var a objc.SEL
		if action != "" {
			a = sel(action)
		}
		return objc.ID(cls("NSMenuItem")).Send(sel("alloc")).Send(sel("initWithTitle:action:keyEquivalent:"),
			nsString(title), a, nsString(key))
	}
	addSubmenu := func(bar objc.ID, title string, items [][3]string) {
		holder := newItem(title, "", "")
		sub := objc.ID(cls("NSMenu")).Send(sel("alloc")).Send(sel("initWithTitle:"), nsString(title))
		for _, it := range items {
			mi := newItem(it[0], it[1], it[2])
			sub.Send(sel("addItem:"), mi)
			mi.Send(sel("release"))
		}
		holder.Send(sel("setSubmenu:"), sub)
		sub.Send(sel("release"))
		bar.Send(sel("addItem:"), holder)
		holder.Send(sel("release"))
	}

	bar := objc.ID(cls("NSMenu")).Send(sel("alloc")).Send(sel("init"))
	addSubmenu(bar, "Pipe", [][3]string{
		{"Close Window", "performClose:", "w"},
		{"Quit Pipe", "terminate:", "q"},
	})
	addSubmenu(bar, "Edit", [][3]string{
		{"Undo", "undo:", "z"},
		{"Redo", "redo:", "Z"},
		{"Cut", "cut:", "x"},
		{"Copy", "copy:", "c"},
		{"Paste", "paste:", "v"},
		{"Select All", "selectAll:", "a"},
	})
	app.Send(sel("setMainMenu:"), bar)
	bar.Send(sel("release"))
}

// Open creates and shows a macOS WKWebView window locked to rawURL's loopback
// HTTP origin. It runs all AppKit and WebKit calls on menubar's main thread.
func Open(rawURL string, opt Options) (*Window, error) {
	origin, err := ParseOrigin(rawURL)
	if err != nil {
		return nil, err
	}
	if opt.Title == "" {
		opt.Title = "Pipe"
	}
	if opt.Width <= 0 {
		opt.Width = defaultWidth
	}
	if opt.Height <= 0 {
		opt.Height = defaultHeight
	}

	w := &Window{origin: origin, initialURL: rawURL, done: make(chan struct{})}
	var openErr error
	if err := menubar.OnMain(func() {
		defer func() {
			if r := recover(); r != nil {
				openErr = fmt.Errorf("webview: %v", r)
			}
		}()
		openErr = w.openOnMain(rawURL, opt)
	}); err != nil {
		return nil, err
	}
	if openErr != nil {
		return nil, openErr
	}
	return w, nil
}

func (w *Window) openOnMain(rawURL string, opt Options) error {
	if err := setupWebKit(); err != nil {
		return err
	}
	cls := objc.GetClass
	app := objc.ID(cls("NSApplication")).Send(sel("sharedApplication"))
	if app == 0 {
		return errors.New("webview: no NSApplication")
	}
	ensureMainMenu(app)

	nsURL := objc.ID(cls("NSURL")).Send(sel("URLWithString:"), nsString(rawURL))
	if nsURL == 0 {
		return errors.New("webview: invalid NSURL")
	}

	cfg := objc.ID(cls("WKWebViewConfiguration")).Send(sel("alloc")).Send(sel("init"))
	if cfg == 0 {
		return errors.New("webview: no WKWebViewConfiguration")
	}
	store := objc.ID(cls("WKWebsiteDataStore")).Send(sel("nonPersistentDataStore"))
	if store != 0 {
		cfg.Send(sel("setWebsiteDataStore:"), store)
	}
	if prefs := cfg.Send(sel("preferences")); prefs != 0 {
		prefs.Send(sel("setJavaScriptCanOpenWindowsAutomatically:"), false)
	}

	frame := nsRect{Size: nsSize{W: float64(opt.Width), H: float64(opt.Height)}}
	wv := objc.ID(cls("WKWebView")).Send(sel("alloc")).Send(sel("initWithFrame:configuration:"), frame, cfg)
	cfg.Send(sel("release"))
	if wv == 0 {
		return errors.New("webview: no WKWebView")
	}
	wv.Send(sel("setAutoresizingMask:"), viewResizeBoth)
	// Developer extras stay off; on macOS 13.3+ also keep Web Inspector off.
	if objc.Send[bool](wv, sel("respondsToSelector:"), sel("setInspectable:")) {
		wv.Send(sel("setInspectable:"), false)
	}

	win := objc.ID(cls("NSWindow")).Send(sel("alloc")).Send(sel("initWithContentRect:styleMask:backing:defer:"),
		frame, windowStyleMask, backingBuffered, false)
	if win == 0 {
		wv.Send(sel("release"))
		return errors.New("webview: no NSWindow")
	}
	win.Send(sel("setReleasedWhenClosed:"), false)
	win.Send(sel("setTitle:"), nsString(opt.Title))
	win.Send(sel("setContentMinSize:"), nsSize{W: minWidth, H: minHeight})
	win.Send(sel("center"))

	del := objc.ID(delegateCls).Send(sel("alloc")).Send(sel("init"))
	if del == 0 {
		win.Send(sel("release"))
		wv.Send(sel("release"))
		return errors.New("webview: no delegate")
	}

	ok := false
	defer func() {
		if ok {
			return
		}
		regMu.Lock()
		delete(windows, del)
		regMu.Unlock()
		w.mu.Lock()
		w.win, w.webView, w.delegate, w.closed = 0, 0, 0, true
		w.mu.Unlock()
		wv.Send(sel("setNavigationDelegate:"), objc.ID(0))
		wv.Send(sel("setUIDelegate:"), objc.ID(0))
		win.Send(sel("setDelegate:"), objc.ID(0))
		win.Send(sel("setContentView:"), objc.ID(0))
		wv.Send(sel("release"))
		win.Send(sel("release"))
		del.Send(sel("release"))
	}()

	w.mu.Lock()
	w.win, w.webView, w.delegate = win, wv, del
	w.mu.Unlock()

	regMu.Lock()
	windows[del] = w
	regMu.Unlock()

	wv.Send(sel("setNavigationDelegate:"), del)
	wv.Send(sel("setUIDelegate:"), del)
	win.Send(sel("setDelegate:"), del)
	win.Send(sel("setContentView:"), wv)

	req := objc.ID(cls("NSURLRequest")).Send(sel("requestWithURL:"), nsURL)
	wv.Send(sel("loadRequest:"), req)

	app.Send(sel("setActivationPolicy:"), policyRegular)
	win.Send(sel("makeKeyAndOrderFront:"), objc.ID(0))
	app.Send(sel("activateIgnoringOtherApps:"), true)
	ok = true
	return nil
}

// Focus brings the window to the front, un-minimizing it if needed.
func (w *Window) Focus() {
	if w == nil {
		return
	}
	_ = menubar.OnMain(func() {
		w.mu.Lock()
		win := w.win
		w.mu.Unlock()
		if win == 0 {
			return
		}
		if objc.Send[bool](win, sel("isMiniaturized")) {
			win.Send(sel("deminiaturize:"), objc.ID(0))
		}
		app := objc.ID(objc.GetClass("NSApplication")).Send(sel("sharedApplication"))
		if app != 0 {
			app.Send(sel("setActivationPolicy:"), policyRegular)
		}
		win.Send(sel("makeKeyAndOrderFront:"), objc.ID(0))
		if app != 0 {
			app.Send(sel("activateIgnoringOtherApps:"), true)
		}
	})
}

// Close closes the window. It is safe to call more than once.
func (w *Window) Close() {
	if w == nil {
		return
	}
	_ = menubar.OnMain(func() {
		w.mu.Lock()
		win := w.win
		w.mu.Unlock()
		if win != 0 {
			win.Send(sel("close"))
		}
	})
}

// Done is closed once the window has closed.
func (w *Window) Done() <-chan struct{} { return w.done }
