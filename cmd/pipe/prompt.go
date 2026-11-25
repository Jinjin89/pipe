// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// terminalSecretReader prompts for DNS provider credentials on the terminal.
// It returns nil when stdin is not a terminal.
func terminalSecretReader() func(provider string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil
	}
	return func(provider string) ([]byte, error) {
		interrupted, stop := guardTerminal(fd)
		defer stop()
		type result struct {
			out []byte
			err error
		}
		// A blocked terminal read cannot be cancelled, so read in a goroutine
		// and return as soon as the signal arrives.
		done := make(chan result, 1)
		go func() {
			out, err := readSecrets(fd, provider)
			done <- result{out, err}
		}()
		select {
		case <-interrupted:
			return nil, errors.New("interrupted")
		case r := <-done:
			return r.out, r.err
		}
	}
}

func readSecrets(fd int, provider string) ([]byte, error) {
	switch provider {
	case "alidns":
		fmt.Fprint(os.Stderr, "AccessKey ID: ")
		id, err := readVisibleLine(fd)
		if err != nil {
			return nil, err
		}
		fmt.Fprint(os.Stderr, "AccessKey Secret: ")
		secret, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, err
		}
		out := []byte("access_key_id=" + id + "\naccess_key_secret=" + strings.TrimSpace(string(secret)) + "\n")
		clear(secret)
		return out, nil
	case "cloudflare":
		fmt.Fprint(os.Stderr, "Cloudflare API token: ")
		token, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, err
		}
		out := append([]byte(strings.TrimSpace(string(token))), '\n')
		clear(token)
		return out, nil
	}
	return nil, errors.New("unsupported HTTPS proxy DNS provider")
}

func readVisibleLine(fd int) (string, error) {
	var line []byte
	buf := make([]byte, 1)
	for len(line) <= 4096 {
		n, err := os.Stdin.Read(buf)
		if n == 1 {
			if buf[0] == '\n' {
				return strings.TrimSpace(string(line)), nil
			}
			line = append(line, buf[0])
		}
		if err != nil {
			if len(line) > 0 {
				return strings.TrimSpace(string(line)), nil
			}
			return "", err
		}
	}
	return "", errors.New("input is too long")
}

// guardTerminal restores the terminal on SIGINT or SIGTERM and closes the
// returned channel, so the caller can return an error and run its defers. The
// second result stops the notifier.
func guardTerminal(fd int) (<-chan struct{}, func()) {
	interrupted := make(chan struct{})
	state, err := term.GetState(fd)
	if err != nil {
		return interrupted, func() {}
	}
	signals := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-signals:
			_ = term.Restore(fd, state)
			fmt.Fprintln(os.Stderr)
			close(interrupted)
		case <-done:
		}
	}()
	return interrupted, func() {
		signal.Stop(signals)
		close(done)
	}
}
