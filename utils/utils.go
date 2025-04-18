/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package utils

import (
	"os"
)

func LogError(err error) {
	os.Stderr.WriteString(err.Error() + "\n")
}
