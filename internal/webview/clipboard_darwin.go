// SPDX-License-Identifier: GPL-3.0-or-later

package webview

import (
	"errors"
	"strings"

	"pipe/internal/menubar"

	"github.com/ebitengine/purego/objc"
)

// CopySensitive marks the text as concealed and transient for pasteboard consumers.
func CopySensitive(text string) error {
	if strings.ContainsRune(text, 0) {
		return errors.New("invalid pasteboard text")
	}
	var copyErr error
	if err := menubar.OnMain(func() {
		pool := objc.ID(objc.GetClass("NSAutoreleasePool")).Send(sel("new"))
		defer pool.Send(sel("drain"))
		pb := objc.ID(objc.GetClass("NSPasteboard")).Send(sel("generalPasteboard"))
		item := objc.ID(objc.GetClass("NSPasteboardItem")).Send(sel("new"))
		defer item.Send(sel("release"))
		emptyData := objc.ID(objc.GetClass("NSData")).Send(sel("data"))
		for _, marker := range []string{"org.nspasteboard.ConcealedType", "org.nspasteboard.TransientType"} {
			if !objc.Send[bool](item, sel("setData:forType:"), emptyData, nsString(marker)) {
				copyErr = errors.New("could not mark the sensitive pasteboard item")
				return
			}
		}
		if !objc.Send[bool](item, sel("setString:forType:"), nsString(text), nsString("public.utf8-plain-text")) {
			copyErr = errors.New("could not create the pasteboard item")
			return
		}
		items := objc.ID(objc.GetClass("NSArray")).Send(sel("arrayWithObject:"), item)
		pb.Send(sel("clearContents"))
		if !objc.Send[bool](pb, sel("writeObjects:"), items) {
			copyErr = errors.New("could not write the pasteboard item")
		}
	}); err != nil {
		return err
	}
	return copyErr
}
