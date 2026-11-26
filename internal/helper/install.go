// SPDX-License-Identifier: GPL-3.0-or-later

package helper

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"pipe/internal/localfile"
	"pipe/internal/sysdns"
	"pipe/internal/update"
	"pipe/internal/version"
)

// UnitName is the systemd unit (Linux).
const UnitName = "pipe-helper.service"

// RenderPlist returns the LaunchDaemon for the helper binary at binary.
func RenderPlist(binary string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + Label + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>`)
	xmlEscape(&b, binary)
	b.WriteString(`</string>
		<string>helper</string>
		<string>run</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
</dict>
</plist>
`)
	return b.String()
}

func xmlEscape(b *strings.Builder, s string) {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	b.WriteString(r.Replace(s))
}

// RenderUnit returns the systemd unit for the helper binary at binary.
func RenderUnit(binary string) string {
	return `[Unit]
Description=Pipe Helper (TUN for the Pipe app)
After=network.target

[Service]
ExecStart=` + systemdQuote(binary) + ` helper run
Restart=always
RestartSec=2
RuntimeDirectory=pipe-helper
NoNewPrivileges=yes
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
`
}

func systemdQuote(s string) string {
	if !strings.ContainsAny(s, " \t\"'\\") {
		return s
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// env is everything install and remove touch outside the paths, so tests can
// run them against a temp dir with a fake command runner.
type env struct {
	paths   Paths
	svcctl  string // absolute path of launchctl or systemctl; root never searches $PATH
	exe     func() (string, error)
	run     func(name string, args ...string) error
	chown   func(f *os.File) error // makes the file root-owned
	trusted bool
}

var helperDNSArmedPath = sysdns.ArmedPath
var restoreHelperDNS = func() error { return sysdns.NewDefault().Restore() }

// The GUI passes the running image's digest as data to an OS-owned shell.
// Each parent is checked before creating or opening anything below it.
const stageHelperScript = `
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
umask 077
source=$1
digest=$2
directory=$3
uid=$4
platform=$5

protected_dir() {
    [ -d "$1" ] && [ ! -L "$1" ] && [ -O "$1" ] || return 1
    case "$platform" in
        darwin)
            mode=$(stat -f '%Lp' "$1") || return 1
            perm=$(ls -ld -- "$1" | awk '{print $1}') || return 1
            case "$perm" in *+) return 1 ;; esac
            ;;
        linux) mode=$(stat -c '%a' "$1") || return 1 ;;
        *) return 1 ;;
    esac
    [ "$((0$mode & 022))" -eq 0 ]
}

protected_dir /
case "$directory" in /*) ;; *) exit 1 ;; esac
parent=''
remaining=${directory#/}
while [ -n "$remaining" ]; do
    component=${remaining%%/*}
    case "$component" in ''|.|..) exit 1 ;; esac
    parent=$parent/$component
    if [ ! -e "$parent" ] && [ ! -L "$parent" ]; then
        mkdir -m 0755 "$parent"
    fi
    if ! protected_dir "$parent"; then
        echo "The Pipe Helper directory needs root-only write access." >&2
        exit 1
    fi
    [ "$component" != "$remaining" ] || break
    remaining=${remaining#*/}
done

staged=$(mktemp "$directory/pipe-helper-stage.XXXXXXXX")
trap 'rm -f -- "$staged"' 0
trap 'exit 1' HUP INT TERM
chmod 0700 "$staged"
if [ "$platform" = darwin ]; then
    chmod -N "$staged" 2>/dev/null || true
    case "$(ls -ld -- "$staged" | awk '{print $1}')" in *+) exit 1 ;; esac
fi
[ -f "$source" ]
cat < "$source" > "$staged"
case "$platform" in
    darwin) actual=$(env -i /usr/bin/shasum -a 256 < "$staged") ;;
    linux) actual=$(sha256sum < "$staged") ;;
esac
if [ "${actual%% *}" != "$digest" ]; then
    echo "The Pipe executable changed before it could be installed." >&2
    exit 1
fi
chown 0:0 "$staged"
chmod 0755 "$staged"
"$staged" helper install --uid "$uid"
`

func realEnv() (env, error) {
	p, ok := PathsFor(runtime.GOOS)
	if !ok {
		return env{}, errors.New("Pipe Helper isn't available on this system.")
	}
	ctl := "/bin/launchctl"
	if runtime.GOOS != "darwin" {
		ctl = "/usr/bin/systemctl"
		if _, err := os.Stat(ctl); err != nil {
			ctl = "/bin/systemctl"
		}
	}
	return env{
		trusted: true,
		paths:   p,
		svcctl:  ctl,
		exe: func() (string, error) {
			exe, err := os.Executable()
			if err != nil {
				return "", err
			}
			return filepath.EvalSymlinks(exe)
		},
		run: func(name string, args ...string) error {
			out, err := exec.Command(name, args...).CombinedOutput()
			if err != nil {
				return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
			}
			return nil
		},
		chown: func(f *os.File) error { return f.Chown(0, 0) },
	}, nil
}

func checkUID(uid int) error {
	if uid <= 0 {
		return errors.New("The user id must be greater than 0.")
	}
	if _, err := user.LookupId(strconv.Itoa(uid)); err != nil {
		return fmt.Errorf("There is no user with id %d.", uid)
	}
	return nil
}

// InstallService installs or upgrades Pipe Helper. It needs root.
func InstallService(uid int) error {
	if err := checkUID(uid); err != nil {
		return err
	}
	e, err := realEnv()
	if err != nil {
		return err
	}
	return install(e, runtime.GOOS, uid)
}

// RemoveService stops Pipe Helper and deletes its files. It needs root.
func RemoveService() error {
	e, err := realEnv()
	if err != nil {
		return err
	}
	return remove(e, runtime.GOOS)
}

func install(e env, goos string, uid int) error {
	exe, err := e.exe()
	if err != nil {
		return err
	}
	open := os.Open
	if e.trusted {
		open = localfile.OpenTrustedRunningImage
	}
	in, err := open(exe)
	if err != nil {
		return err
	}
	defer in.Close()
	p := e.paths
	mkdir := func(path string) error { return os.MkdirAll(path, 0755) }
	if e.trusted {
		mkdir = localfile.MakeTrustedDirectory
	}
	for _, f := range []string{p.Binary, p.Owner, p.Service} {
		if err := mkdir(filepath.Dir(f)); err != nil {
			return err
		}
	}
	if err := rejectNewerHelper(p.Binary); err != nil {
		return err
	}
	if e.trusted {
		if err := localfile.InstallTrustedExecutable(in, p.Binary); err != nil {
			return err
		}
	} else if err := writeRoot(e, p.Binary, 0o755, in); err != nil {
		return err
	}
	if err := writeRoot(e, p.Owner, 0o644, strings.NewReader(strconv.Itoa(uid)+"\n")); err != nil {
		return err
	}
	if goos == "darwin" {
		if err := writeRoot(e, p.Service, 0o644, strings.NewReader(RenderPlist(p.Binary))); err != nil {
			return err
		}
		e.run(e.svcctl, "bootout", "system/"+Label) // not loaded yet is fine
		return e.run(e.svcctl, "bootstrap", "system", p.Service)
	}
	if err := writeRoot(e, p.Service, 0o644, strings.NewReader(RenderUnit(p.Binary))); err != nil {
		return err
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", UnitName}, {"restart", UnitName}} {
		if err := e.run(e.svcctl, args...); err != nil {
			return err
		}
	}
	return nil
}

func rejectNewerHelper(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(info, opened) {
		return errors.New("The installed Pipe Helper changed. Try again.")
	}
	if _, _, installed, ok := version.ScanIdentity(f); ok {
		if order, comparable := update.CompareVersions(installed, version.Version); comparable && order > 0 {
			return ErrNewer
		}
	}
	return nil
}

func remove(e env, goos string) error {
	p := e.paths
	if goos == "darwin" {
		e.run(e.svcctl, "bootout", "system/"+Label)
		if err := restoreHelperDNS(); err != nil {
			return fmt.Errorf("restore system DNS before removing helper: %w", err)
		}
		if err := os.Remove(helperDNSArmedPath()); err != nil && !os.IsNotExist(err) {
			return err
		}
	} else {
		e.run(e.svcctl, "disable", "--now", UnitName)
	}
	var first error
	for _, path := range []string{p.Service, p.Binary, p.Owner, p.Socket} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) && first == nil {
			first = err
		}
	}
	os.Remove(filepath.Dir(p.Owner)) // only succeeds when empty
	if goos != "darwin" {
		e.run(e.svcctl, "daemon-reload")
	}
	return first
}

// writeRoot writes r to path as a root-owned file of the given mode: temp
// file in the same directory, chmod and chown on the open file, fsync, rename.
func writeRoot(e env, path string, mode os.FileMode, r io.Reader) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".pipe-helper-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op after the rename
	defer tmp.Close()
	for _, step := range []func() error{
		func() error { _, err := io.Copy(tmp, r); return err },
		func() error { return e.chown(tmp) },
		func() error { return tmp.Chmod(mode) },
		tmp.Sync,
		tmp.Close,
	} {
		if err := step(); err != nil {
			return err
		}
	}
	return os.Rename(tmp.Name(), path)
}
