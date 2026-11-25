// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !linux || android

package relay

import (
	"context"
	"errors"
)

var errPlatform = errors.New("pipe relay requires Linux")

func Add(context.Context, string, Request, string, string) (string, string, string, error) {
	return "", "", "", errPlatform
}
func Apply(context.Context, string) error            { return errPlatform }
func Remove(context.Context, string, string) error   { return errPlatform }
func Status(context.Context, string) (string, error) { return "", errPlatform }
