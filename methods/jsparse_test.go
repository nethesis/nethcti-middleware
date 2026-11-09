/*
 * Copyright (C) 2026 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJSParseInt(t *testing.T) {
	cases := map[string]string{
		"12":                           "12",
		" \u2028\u00a0\ufeff\u3000-7x": "-7",
		"+0x1F":                        "31",
		"-0":                           "0",
		"0x":                           "NaN",
		"1e3":                          "1",
		".5":                           "NaN",
		"":                             "NaN",
		"abc":                          "NaN",
		"99999999999999999999":         "100000000000000000000",
		strings.Repeat("1", 400):       "Infinity",
		"0xFFFFFFFFFFFFFFFFF":          "295147905179352830000",
		"\u180e5":                      "NaN",
		"18446744073709549568":         "18446744073709550000",
	}
	for input, expected := range cases {
		assert.Equal(t, expected, jsNumberToString(jsParseInt(input)), input)
	}
}

func TestJSDecodeURIComponent(t *testing.T) {
	valid := map[string]string{
		"a%20b":        "a b",
		"%C3%A8":       "è",
		"%F0%9F%98%80": "😀",
		"plain":        "plain",
	}
	for input, expected := range valid {
		decoded, ok := jsDecodeURIComponent(input)
		assert.True(t, ok, input)
		assert.Equal(t, expected, decoded, input)
	}

	for _, input := range []string{"%zz", "%", "%C3", "%ED%A0%80", "%2"} {
		_, ok := jsDecodeURIComponent(input)
		assert.False(t, ok, input)
	}
}
