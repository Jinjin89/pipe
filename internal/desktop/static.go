// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:ui
var uiFiles embed.FS

func staticHandler() http.Handler {
	sub, err := fs.Sub(uiFiles, "ui")
	if err != nil {
		panic(err)
	}
	return http.FileServerFS(sub)
}
