/*
 * Copyright (C) 2026 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"math"
	"math/big"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

func isJSWhitespace(char rune) bool {
	switch char {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0x00a0, 0x2028, 0x2029, 0xfeff:
		return true
	}
	return unicode.Is(unicode.Zs, char)
}

func jsParseInt(value string) float64 {
	value = strings.TrimLeftFunc(value, isJSWhitespace)

	sign := 1.0
	if value != "" && (value[0] == '+' || value[0] == '-') {
		if value[0] == '-' {
			sign = -1
		}
		value = value[1:]
	}

	radix := 10
	if len(value) >= 2 && value[0] == '0' && (value[1] == 'x' || value[1] == 'X') {
		radix = 16
		value = value[2:]
	}

	end := 0
	for end < len(value) && isDigitInRadix(value[end], radix) {
		end++
	}
	if end == 0 {
		return math.NaN()
	}
	digits := value[:end]

	if radix == 10 {
		number, err := strconv.ParseFloat(digits, 64)
		if err != nil && !math.IsInf(number, 0) {
			return math.NaN()
		}
		return sign * number
	}

	integer, _ := new(big.Int).SetString(digits, radix)
	number, _ := new(big.Float).SetInt(integer).Float64()
	return sign * number
}

func isDigitInRadix(char byte, radix int) bool {
	if char >= '0' && char <= '9' {
		return true
	}
	if radix == 16 {
		lower := char | 0x20
		return lower >= 'a' && lower <= 'f'
	}
	return false
}

func jsNumberToString(value float64) string {
	switch {
	case math.IsNaN(value):
		return "NaN"
	case math.IsInf(value, 1):
		return "Infinity"
	case math.IsInf(value, -1):
		return "-Infinity"
	case value == 0:
		return "0"
	}

	absolute := math.Abs(value)
	if absolute >= 1e21 || absolute < 1e-6 {
		formatted := strconv.FormatFloat(value, 'e', -1, 64)
		mantissa, exponent, _ := strings.Cut(formatted, "e")
		return mantissa + "e" + exponent[:1] + strings.TrimLeft(exponent[1:], "0")
	}

	return strconv.FormatFloat(value, 'f', -1, 64)
}

func jsDecodeURIComponent(value string) (string, bool) {
	if !strings.Contains(value, "%") {
		return value, true
	}

	decoded := make([]byte, 0, len(value))
	for i := 0; i < len(value); i++ {
		if value[i] != '%' {
			decoded = append(decoded, value[i])
			continue
		}
		if i+2 >= len(value) {
			return "", false
		}
		high, highOK := hexValue(value[i+1])
		low, lowOK := hexValue(value[i+2])
		if !highOK || !lowOK {
			return "", false
		}
		decoded = append(decoded, high<<4|low)
		i += 2
	}

	if !utf8.Valid(decoded) {
		return "", false
	}
	return string(decoded), true
}

func hexValue(char byte) (byte, bool) {
	switch {
	case char >= '0' && char <= '9':
		return char - '0', true
	case char >= 'a' && char <= 'f':
		return char - 'a' + 10, true
	case char >= 'A' && char <= 'F':
		return char - 'A' + 10, true
	}
	return 0, false
}
