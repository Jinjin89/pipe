// SPDX-License-Identifier: GPL-3.0-or-later

package desktop

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// browserCandidates lists Chromium-family executables in preference order.
func browserCandidates(goos string, getenv func(string) string) (paths []string, names []string) {
	switch goos {
	case "windows":
		for _, root := range []string{getenv("ProgramFiles(x86)"), getenv("ProgramFiles"), getenv("LocalAppData")} {
			if root == "" {
				continue
			}
			paths = append(paths,
				filepath.Join(root, `Microsoft\Edge\Application\msedge.exe`),
				filepath.Join(root, `Google\Chrome\Application\chrome.exe`),
				filepath.Join(root, `BraveSoftware\Brave-Browser\Application\brave.exe`),
				filepath.Join(root, `Chromium\Application\chrome.exe`))
		}
		names = []string{"msedge.exe", "chrome.exe", "brave.exe"}
	case "darwin":
		apps := []string{"Google Chrome", "Microsoft Edge", "Chromium", "Brave Browser"}
		for _, base := range []string{"/Applications", filepath.Join(getenv("HOME"), "Applications")} {
			for _, app := range apps {
				paths = append(paths, filepath.Join(base, app+".app", "Contents", "MacOS", app))
			}
		}
	default:
		names = []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
			"microsoft-edge", "microsoft-edge-stable", "brave-browser", "brave"}
	}
	return paths, names
}

// findBrowser returns the first installed browser, or "" if none.
func findBrowser(goos string, getenv func(string) string, exists func(string) bool, lookPath func(string) (string, error)) string {
	paths, names := browserCandidates(goos, getenv)
	for _, p := range paths {
		if exists(p) {
			return p
		}
	}
	for _, n := range names {
		if p, err := lookPath(n); err == nil {
			return p
		}
	}
	return ""
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func browserArgs(url, profileDir string) []string {
	return []string{
		"--app=" + url,
		"--user-data-dir=" + profileDir,
		"--no-first-run", "--no-default-browser-check", "--disable-extensions",
		"--no-proxy-server", "--window-size=1040,700",
	}
}

// startWindow launches the app window. It returns nil, nil when no Chromium
// browser exists (the caller then opens the default browser).
func startWindow(url, profileDir string) (*exec.Cmd, error) {
	browser := findBrowser(runtime.GOOS, os.Getenv, fileExists, exec.LookPath)
	if browser == "" {
		return nil, nil
	}
	if err := os.MkdirAll(profileDir, 0700); err != nil {
		return nil, err
	}
	cmd := exec.Command(browser, browserArgs(url, profileDir)...)
	configureWindowCmd(cmd)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

// openDefaultBrowser opens url in the user's default browser.
func openDefaultBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	configureWindowCmd(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait()
	return nil
}
