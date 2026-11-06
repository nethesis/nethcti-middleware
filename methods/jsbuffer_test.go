/*
 * Copyright (C) 2026 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecodeBase64LikeNode(t *testing.T) {
	cases := map[string]string{
		"QUJD":      "414243",
		"QUJDRA==":  "41424344",
		"QUJDRA":    "41424344",
		"QU JD\nRA": "41424344",
		"QU=JD":     "41",
		"QUJD=QUJD": "414243",
		"-_-_":      "fbffbf",
		"ŁUJD":      "014243",
		"QUĽJD":     "41",
		"Q":         "",
		"QQ":        "41",
		"QUJDR":     "414243",
		"":          "",
		"!!QUJD!!":  "414243",
		"QUJDRA===": "41424344",
		"QUŁJ":      "414009",
	}
	for input, expected := range cases {
		assert.Equal(t, expected, hex.EncodeToString(decodeBase64LikeNode(input)), input)
	}

	large := strings.Repeat("QUJD", 2000)
	assert.Equal(t, strings.Repeat("ABC", 2000), string(decodeBase64LikeNode(large)))
}

func TestDecodeUTF8LikeNode(t *testing.T) {
	cases := map[string]string{
		"e28241":   "\uFFFDA",
		"eda080":   "\uFFFD\uFFFD\uFFFD",
		"f09f9880": "😀",
		"c0af":     "\uFFFD\uFFFD",
		"ff41":     "\uFFFDA",
		"e282":     "\uFFFD",
		"efbbbf41": "\uFEFFA",
		"f4908080": "\uFFFD\uFFFD\uFFFD\uFFFD",
	}
	for input, expected := range cases {
		data, err := hex.DecodeString(input)
		assert.NoError(t, err)
		assert.Equal(t, expected, decodeUTF8LikeNode(data), input)
	}
}

func TestCESU8RoundTrip(t *testing.T) {
	assert.Equal(t, "45eda0bdedb88078", hex.EncodeToString([]byte(encodeCESU8("E😀x"))))
	assert.Equal(t, "41c3a9e282ac", hex.EncodeToString([]byte(encodeCESU8("Aé€"))))

	cases := map[string]string{
		"45eda0bdedb88078": `"E😀x"`,
		"41eda0bd42":       `"A\ud83dB"`,
		"edb880efbbbf":     `"\ude00` + "\uFEFF" + `"`,
		"efbbbf424f4d":     `"BOM"`,
		"22095c0a7f":       `"\"\t\\\n` + "\x7f" + `"`,
		"c080":             `"\u0000"`,
		"e2":               `"0` + "\uFFFD" + `"`,
	}
	for input, expected := range cases {
		data, err := hex.DecodeString(input)
		assert.NoError(t, err)
		var buffer bytes.Buffer
		writeJSStringUTF16(&buffer, decodeCESU8LikeMysql2(string(data)))
		assert.Equal(t, expected, buffer.String(), input)
	}
}
