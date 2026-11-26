// SPDX-License-Identifier: GPL-3.0-or-later
//go:build darwin

package menubar

import (
	_ "embed"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/ebitengine/purego/objc"
)

//go:embed icon_on.png
var iconOnPNG []byte

//go:embed icon_off.png
var iconOffPNG []byte

type nsPoint struct{ X, Y float64 }
type nsSize struct{ W, H float64 }

// Menu item tags tell the items of one kind apart.
const (
	tagMode = 100 // + index in modes
	tagTier = 200 // + index in tiers
)

var (
	modes = []string{"smart", "global", "direct"}
	tiers = []string{"auto", "fast", "stealth", "rescue"}
)

// ui is everything that lives for one Run (one Run per process).
type ui struct {
	act   Actions
	cache atomic.Pointer[State]

	app, delegate, statusItem, button, menu objc.ID
	imgOn, imgOff, titleItem                objc.ID
	commonModes                             objc.ID // NSArray: perform on the main thread even while the menu is open
	opened                                  chan struct{}

	// touched on the main thread only
	lastIcon, lastTip string

	pendingTerminate atomic.Bool
}

const (
	loopIdle = iota
	loopStarting
	loopRunning
	loopEnded

	loopStartTimeout = 10 * time.Second
)

var (
	cur     atomic.Pointer[ui]
	stopped atomic.Bool // Stop was called (maybe before Run)

	loopMu      sync.Mutex
	loopState   int
	loopReady   chan struct{}
	loopDone    chan struct{}
	readyClosed bool

	dispOnce       sync.Once
	dispErr        error
	dispatchAsyncF uintptr
	mainQueue      uintptr
	stopCB         uintptr
	mainTaskCB     uintptr

	mainMu    sync.Mutex
	mainNext  uintptr
	mainTasks = map[uintptr]func(){}

	cbKeep []any // strong references to Go callbacks (purego keeps them too)
)

// fallback is the slowest the menu refreshes: it catches a session that died
// without telling anyone.
const fallback = 30 * time.Second

func sel(name string) objc.SEL { return objc.RegisterName(name) }

func nsString(s string) objc.ID {
	return objc.ID(objc.GetClass("NSString")).Send(sel("stringWithUTF8String:"), s)
}

func setupDispatch() error {
	dispOnce.Do(func() {
		lib, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_GLOBAL|purego.RTLD_LAZY)
		if err != nil {
			dispErr = fmt.Errorf("menu bar: libSystem: %w", err)
			return
		}
		if dispatchAsyncF, err = purego.Dlsym(lib, "dispatch_async_f"); err != nil {
			dispErr = fmt.Errorf("menu bar: dispatch_async_f: %w", err)
			return
		}
		// _dispatch_main_q is a data symbol; dispatch_get_main_queue() is its address.
		if mainQueue, err = purego.Dlsym(lib, "_dispatch_main_q"); err != nil {
			dispErr = fmt.Errorf("menu bar: _dispatch_main_q: %w", err)
			return
		}
		stopCB = purego.NewCallback(stopOnMain)
		mainTaskCB = purego.NewCallback(runMainTask)
	})
	return dispErr
}

func runMainTask(id uintptr) {
	mainMu.Lock()
	fn := mainTasks[id]
	delete(mainTasks, id)
	mainMu.Unlock()
	if fn == nil {
		return
	}
	pool := objc.ID(objc.GetClass("NSAutoreleasePool")).Send(sel("alloc")).Send(sel("init"))
	defer func() {
		recover()
		pool.Send(sel("drain"))
	}()
	fn()
}

func enqueueMain(fn func()) {
	mainMu.Lock()
	mainNext++
	id := mainNext
	mainTasks[id] = fn
	mainMu.Unlock()
	purego.SyscallN(dispatchAsyncF, mainQueue, id, mainTaskCB)
}

// Starting marks that Run is about to be called so concurrent OnMain callers
// wait for the Cocoa loop instead of failing prematurely. The returned cancel
// function unblocks waiters if Run is never entered (e.g. startup aborted).
func Starting() func() {
	loopMu.Lock()
	if loopState == loopIdle {
		loopState = loopStarting
		loopReady = make(chan struct{})
		loopDone = make(chan struct{})
		readyClosed = false
	}
	loopMu.Unlock()
	return func() {
		loopMu.Lock()
		if loopState == loopStarting {
			loopState = loopEnded
			if !readyClosed {
				close(loopReady)
				readyClosed = true
			}
			close(loopDone)
		}
		loopMu.Unlock()
	}
}

// OnMain runs fn synchronously on the Cocoa main thread owned by Run.
// If Run has started (or is starting) but is not yet ready, OnMain waits up to
// 10 s for it to become ready or fail. It returns an error immediately when
// the loop never started, failed, or has stopped.
func OnMain(fn func()) error {
	loopMu.Lock()
	state, ready, loopEnd := loopState, loopReady, loopDone
	loopMu.Unlock()

	if state == loopStarting {
		t := time.NewTimer(loopStartTimeout)
		select {
		case <-ready:
			t.Stop()
		case <-loopEnd:
			t.Stop()
			return errors.New("cocoa main loop is not running")
		case <-t.C:
			return errors.New("cocoa main loop start timed out")
		}
		loopMu.Lock()
		state, loopEnd = loopState, loopDone
		loopMu.Unlock()
	}

	if state != loopRunning || cur.Load() == nil || stopped.Load() {
		return errors.New("cocoa main loop is not running")
	}
	if err := setupDispatch(); err != nil {
		return err
	}
	if cls := objc.GetClass("NSThread"); cls != 0 && objc.Send[bool](objc.ID(cls), sel("isMainThread")) {
		fn()
		return nil
	}
	done := make(chan struct{})
	enqueueMain(func() {
		defer close(done)
		fn()
	})
	select {
	case <-done:
		return nil
	case <-loopEnd:
		return errors.New("cocoa main loop stopped")
	}
}

// Run takes over the main thread and runs the Cocoa event loop until Stop.
// The caller's goroutine must be locked to the main thread.
func Run(act Actions) (err error) {
	loopMu.Lock()
	if loopState == loopIdle {
		loopState = loopStarting
		loopReady = make(chan struct{})
		loopDone = make(chan struct{})
		readyClosed = false
	}
	loopMu.Unlock()

	var u *ui
	var pollDone chan struct{}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("menu bar: %v", r)
		}
		if pollDone != nil {
			close(pollDone)
		}
		cur.Store(nil)
		loopMu.Lock()
		if loopState != loopEnded {
			loopState = loopEnded
			if loopReady != nil && !readyClosed {
				close(loopReady)
				readyClosed = true
			}
			if loopDone != nil {
				close(loopDone)
			}
		}
		loopMu.Unlock()
		if u != nil && u.app != 0 {
			defer func() { recover() }()
			pool := objc.ID(objc.GetClass("NSAutoreleasePool")).Send(sel("alloc")).Send(sel("init"))
			u.app.Send(sel("setDelegate:"), objc.ID(0))
			if u.statusItem != 0 {
				objc.ID(objc.GetClass("NSStatusBar")).Send(sel("systemStatusBar")).Send(sel("removeStatusItem:"), u.statusItem)
			}
			pool.Send(sel("drain"))
		}
	}()
	if stopped.Load() {
		return nil
	}
	if act.State == nil {
		return errors.New("menu bar: no State func")
	}
	if _, e := purego.Dlopen("/System/Library/Frameworks/AppKit.framework/AppKit", purego.RTLD_GLOBAL|purego.RTLD_LAZY); e != nil {
		return fmt.Errorf("menu bar: AppKit: %w", e)
	}
	if _, e := purego.Dlopen("/System/Library/Frameworks/Foundation.framework/Foundation", purego.RTLD_GLOBAL|purego.RTLD_LAZY); e != nil {
		return fmt.Errorf("menu bar: Foundation: %w", e)
	}
	if e := setupDispatch(); e != nil {
		return e
	}
	for _, c := range []string{"NSApplication", "NSStatusBar", "NSMenu", "NSMenuItem", "NSImage", "NSData", "NSArray", "NSEvent", "NSAutoreleasePool", "NSObject", "NSString"} {
		if objc.GetClass(c) == 0 {
			return fmt.Errorf("menu bar: class %s not found", c)
		}
	}

	u = &ui{act: act, opened: make(chan struct{}, 1)}
	pool := objc.ID(objc.GetClass("NSAutoreleasePool")).Send(sel("alloc")).Send(sel("init"))
	if e := u.setup(); e != nil {
		pool.Send(sel("drain"))
		return e
	}
	cur.Store(u)

	// State never runs on the main thread: a goroutine fetches it when asked.
	// Wait briefly for the first value so the first paint is right.
	pollDone = make(chan struct{})
	first := make(chan struct{})
	go u.watch(pollDone, first)
	select {
	case <-first:
	case <-time.After(300 * time.Millisecond):
	}
	u.refresh()
	pool.Send(sel("drain"))

	if stopped.Load() {
		return nil
	}
	loopMu.Lock()
	loopState = loopRunning
	if !readyClosed {
		close(loopReady)
		readyClosed = true
	}
	loopMu.Unlock()

	u.app.Send(sel("run")) // returns after stopOnMain
	return nil
}

// watch fetches State when something changed, when the menu opened, and every
// fallback. It sleeps otherwise.
func (u *ui) watch(done <-chan struct{}, first chan<- struct{}) {
	t := time.NewTimer(fallback)
	defer t.Stop()
	for {
		func() {
			defer func() { recover() }() // a panicking State must not kill the app
			s := u.act.State()
			u.cache.Store(&s)
		}()
		if first != nil {
			close(first)
			first = nil
		}
		u.onMain("pipeTick:")
		select {
		case <-done:
			return
		case <-u.act.Changes:
		case <-u.opened:
		case <-t.C:
		}
		if !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
		t.Reset(fallback)
	}
}

// onMain runs a delegate method on the main thread, also while the menu is
// open (the common run loop modes include menu tracking).
func (u *ui) onMain(method string) {
	u.delegate.Send(sel("performSelectorOnMainThread:withObject:waitUntilDone:modes:"), sel(method), objc.ID(0), false, u.commonModes)
}

// Stop ends Run. It is safe from any goroutine, and a Stop before Run makes
// Run return nil at once.
func Stop() {
	stopped.Store(true)
	if setupDispatch() != nil {
		return
	}
	// Cocoa work belongs to the main thread, which sits in [NSApp run] and
	// services the main queue. If Run isn't running, the block never runs and
	// Run sees the stopped flag instead.
	purego.SyscallN(dispatchAsyncF, mainQueue, 0, stopCB)
}

// CancelPendingTermination releases AppKit's logout wait after Quit fails.
func CancelPendingTermination() {
	if u := cur.Load(); u != nil && u.pendingTerminate.Load() {
		enqueueMain(func() {
			if cur.Load() == u {
				u.replyToPendingTermination(false)
			}
		})
	}
}

// replyToPendingTermination runs on the Cocoa main thread.
func (u *ui) replyToPendingTermination(allow bool) bool {
	if !u.pendingTerminate.Swap(false) {
		return false
	}
	u.app.Send(sel("replyToApplicationShouldTerminate:"), allow)
	return true
}

// stopOnMain runs on the main thread via the main queue.
func stopOnMain(ctx uintptr) {
	defer func() { recover() }()
	u := cur.Load()
	if u == nil {
		return
	}
	if u.replyToPendingTermination(true) {
		return
	}
	u.app.Send(sel("stop:"), objc.ID(0))
	// stop: only takes effect after the next event; post a dummy one so the
	// loop wakes up and [NSApp run] returns.
	ev := objc.ID(objc.GetClass("NSEvent")).Send(sel("otherEventWithType:location:modifierFlags:timestamp:windowNumber:context:subtype:data1:data2:"),
		uint(15), // NSEventTypeApplicationDefined
		nsPoint{}, uint(0), float64(0), 0, objc.ID(0), int16(0), 0, 0)
	u.app.Send(sel("postEvent:atStart:"), ev, true)
}

func (u *ui) setup() error {
	cls := objc.GetClass
	u.app = objc.ID(cls("NSApplication")).Send(sel("sharedApplication"))
	if u.app == 0 {
		return errors.New("menu bar: no NSApplication")
	}
	u.app.Send(sel("setActivationPolicy:"), 1) // accessory: no Dock icon

	// One delegate class: app delegate, menu delegate, timer and item target.
	// BOOL results are returned as ID (a full register) which is fine for
	// BOOL; BOOL arguments are taken as uintptr and ignored.
	call := func(f func()) { defer func() { recover() }(); f() }
	methods := []objc.MethodDef{
		{Cmd: sel("applicationShouldHandleReopen:hasVisibleWindows:"), Fn: func(self objc.ID, _ objc.SEL, app objc.ID, vis uintptr) objc.ID {
			if u.act.Open != nil {
				go u.act.Open()
			}
			return 0 // NO: we show the window ourselves
		}},
		{Cmd: sel("applicationShouldTerminate:"), Fn: func(self objc.ID, _ objc.SEL, app objc.ID) objc.ID {
			// Logout/shutdown. Quit cleanly, and answer once Stop comes.
			if u.act.Quit == nil || stopped.Load() {
				return 1 // NSTerminateNow
			}
			if u.pendingTerminate.CompareAndSwap(false, true) {
				go u.act.Quit()
			}
			return 2 // NSTerminateLater
		}},
		{Cmd: sel("menuNeedsUpdate:"), Fn: func(self objc.ID, _ objc.SEL, m objc.ID) {
			call(u.rebuildMenu) // from the cache, then the open menu gets fresh values (the latency)
			select {
			case u.opened <- struct{}{}:
			default:
			}
		}},
		{Cmd: sel("pipeTick:"), Fn: func(self objc.ID, _ objc.SEL, t objc.ID) { call(u.refresh) }},
		{Cmd: sel("pipeConnect:"), Fn: func(self objc.ID, _ objc.SEL, it objc.ID) {
			if canDisconnect(u.current().Status) {
				if u.act.Disconnect != nil {
					go u.act.Disconnect()
				}
			} else if u.act.Connect != nil {
				go u.act.Connect()
			}
		}},
		{Cmd: sel("pipeMode:"), Fn: func(self objc.ID, _ objc.SEL, it objc.ID) {
			i := objc.Send[int](it, sel("tag")) - tagMode
			if i >= 0 && i < len(modes) && u.act.SetMode != nil {
				go u.act.SetMode(modes[i])
			}
		}},
		{Cmd: sel("pipeTier:"), Fn: func(self objc.ID, _ objc.SEL, it objc.ID) {
			i := objc.Send[int](it, sel("tag")) - tagTier
			if i >= 0 && i < len(tiers) && u.act.SetTier != nil {
				go u.act.SetTier(tiers[i])
			}
		}},
		{Cmd: sel("pipeTUN:"), Fn: func(self objc.ID, _ objc.SEL, it objc.ID) {
			if u.act.SetTUN != nil {
				on := !u.current().TUN // the item shows the current value; toggle it
				go u.act.SetTUN(on)
			}
		}},
		{Cmd: sel("pipeProxy:"), Fn: func(self objc.ID, _ objc.SEL, it objc.ID) {
			if u.act.SetSystemProxy != nil {
				on := !u.current().SystemProxy
				go u.act.SetSystemProxy(on)
			}
		}},
		{Cmd: sel("pipeOpen:"), Fn: func(self objc.ID, _ objc.SEL, it objc.ID) {
			if u.act.Open != nil {
				go u.act.Open()
			}
		}},
		{Cmd: sel("pipeQuit:"), Fn: func(self objc.ID, _ objc.SEL, it objc.ID) {
			if u.act.Quit != nil {
				go u.act.Quit()
			}
		}},
	}
	for _, m := range methods {
		cbKeep = append(cbKeep, m.Fn)
	}
	dc, err := objc.RegisterClass("PipeMenuDelegate", cls("NSObject"), nil, nil, methods)
	if err != nil {
		return fmt.Errorf("menu bar: %w", err)
	}
	u.delegate = objc.ID(dc).Send(sel("alloc")).Send(sel("init"))
	u.app.Send(sel("setDelegate:"), u.delegate)

	// Template images: macOS tints them for light/dark menu bars.
	mk := func(png []byte) objc.ID {
		data := objc.ID(cls("NSData")).Send(sel("dataWithBytes:length:"), unsafe.Pointer(&png[0]), uint(len(png)))
		img := objc.ID(cls("NSImage")).Send(sel("alloc")).Send(sel("initWithData:"), data)
		if img == 0 {
			return 0
		}
		img.Send(sel("setTemplate:"), true)
		img.Send(sel("setSize:"), nsSize{18, 18}) // 36 px PNG shown at 18 pt
		return img
	}
	u.imgOn, u.imgOff = mk(iconOnPNG), mk(iconOffPNG)
	if u.imgOn == 0 || u.imgOff == 0 {
		return errors.New("menu bar: icon images didn't load")
	}

	bar := objc.ID(cls("NSStatusBar")).Send(sel("systemStatusBar"))
	// NSVariableStatusItemLength is -1; the argument is a CGFloat.
	u.statusItem = bar.Send(sel("statusItemWithLength:"), float64(-1))
	if u.statusItem == 0 {
		return errors.New("menu bar: no status item")
	}
	u.statusItem.Send(sel("retain"))
	u.button = u.statusItem.Send(sel("button"))
	if u.button == 0 {
		return errors.New("menu bar: status item has no button")
	}
	u.menu = objc.ID(cls("NSMenu")).Send(sel("alloc")).Send(sel("initWithTitle:"), nsString("Pipe"))
	u.menu.Send(sel("setAutoenablesItems:"), false) // we set enabled by hand
	u.menu.Send(sel("setDelegate:"), u.delegate)
	u.statusItem.Send(sel("setMenu:"), u.menu)
	u.commonModes = objc.ID(cls("NSArray")).Send(sel("arrayWithObject:"), nsString("kCFRunLoopCommonModes"))
	u.commonModes.Send(sel("retain"))
	u.rebuildMenu()
	return nil
}

func (u *ui) current() State {
	if s := u.cache.Load(); s != nil {
		return *s
	}
	return State{Status: "off", Title: "Not connected"}
}

func canDisconnect(status string) bool {
	return status == "on" || status == "connecting" || status == "paused"
}

// refresh updates the icon, tooltip and menu title from the cache (main thread).
func (u *ui) refresh() {
	s := u.current()
	if u.titleItem != 0 {
		u.titleItem.Send(sel("setTitle:"), nsString(menuTitle(s)))
	}
	icon := "off"
	if s.Status == "on" {
		icon = "on"
	}
	dim := s.Status == "connecting"
	key := icon
	if dim {
		key += "-dim"
	}
	if key != u.lastIcon {
		u.lastIcon = key
		img := u.imgOff
		if icon == "on" {
			img = u.imgOn
		}
		u.button.Send(sel("setImage:"), img)
		// setAppearsDisabled: is on NSStatusBarButton; skip if this macOS lacks it.
		if objc.Send[bool](u.button, sel("respondsToSelector:"), sel("setAppearsDisabled:")) {
			u.button.Send(sel("setAppearsDisabled:"), dim)
		}
	}
	tip := s.Tooltip
	if tip == "" {
		tip = s.Title
	}
	if tip != u.lastTip {
		u.lastTip = tip
		u.button.Send(sel("setToolTip:"), nsString(tip))
	}
}

// rebuildMenu refills the menu from the cache. It runs from menuNeedsUpdate:
// just before the menu shows, and once at setup.
func (u *ui) rebuildMenu() {
	s := u.current()
	m := u.menu
	m.Send(sel("removeAllItems"))

	add := func(menu objc.ID, label, action, key string, tag int, checked, enabled bool) objc.ID {
		var a objc.SEL
		if action != "" {
			a = sel(action)
		}
		it := objc.ID(objc.GetClass("NSMenuItem")).Send(sel("alloc")).Send(sel("initWithTitle:action:keyEquivalent:"),
			nsString(label), a, nsString(key))
		if action != "" {
			it.Send(sel("setTarget:"), u.delegate)
		}
		it.Send(sel("setTag:"), tag)
		if checked {
			it.Send(sel("setState:"), 1) // NSControlStateValueOn
		}
		it.Send(sel("setEnabled:"), enabled)
		menu.Send(sel("addItem:"), it)
		it.Send(sel("release")) // the menu keeps it
		return it
	}
	sep := func() {
		m.Send(sel("addItem:"), objc.ID(objc.GetClass("NSMenuItem")).Send(sel("separatorItem")))
	}
	submenu := func(label string) objc.ID {
		parent := add(m, label, "", "", 0, false, true)
		sub := objc.ID(objc.GetClass("NSMenu")).Send(sel("alloc")).Send(sel("initWithTitle:"), nsString(label))
		sub.Send(sel("setAutoenablesItems:"), false)
		parent.Send(sel("setSubmenu:"), sub)
		sub.Send(sel("release"))
		return sub
	}

	u.titleItem = add(m, menuTitle(s), "", "", 0, false, false)
	sep()
	if canDisconnect(s.Status) {
		add(m, "Disconnect", "pipeConnect:", "", 1, false, true)
	} else {
		add(m, "Connect", "pipeConnect:", "", 1, false, true)
	}
	sep()
	ms := submenu("Mode")
	for i, v := range modes {
		add(ms, Capital(v), "pipeMode:", "", tagMode+i, s.Mode == v, true)
	}
	ts := submenu("Route")
	for i, v := range tiers {
		if v == "rescue" && !s.Rescue {
			continue
		}
		add(ts, Capital(v), "pipeTier:", "", tagTier+i, s.Tier == v, true)
	}
	sep()
	if s.TUNAvailable {
		add(m, "TUN (all apps)", "pipeTUN:", "", 2, s.TUN, true)
	}
	add(m, "System proxy", "pipeProxy:", "", 3, s.SystemProxy, !s.TUN)
	sep()
	add(m, "Open Pipe…", "pipeOpen:", "", 4, false, true)
	add(m, "Quit Pipe", "pipeQuit:", "q", 5, false, true)
}
