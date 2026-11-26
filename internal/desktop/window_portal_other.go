// SPDX-License-Identifier: GPL-3.0-or-later
//go:build !linux || android

package desktop

import "errors"

func openBootstrapPortal(string) error { return errors.ErrUnsupported }
