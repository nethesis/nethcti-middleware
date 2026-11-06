/*
 * Copyright (C) 2026 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"bytes"
	"strings"
	"unicode/utf16"
)

const nodeBufferPoolHalf = 4096

var nodeUnbase64Table = func() [256]byte {
	var table [256]byte
	for i := range table {
		table[i] = 255
	}
	for i, c := range "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" {
		table[c] = byte(i)
	}
	table['-'] = 62
	table['_'] = 63
	return table
}()

func decodeBase64LikeNode(value string) []byte {
	src := utf16.Encode([]rune(value))

	padded := len(src)
	if padded > 0 && src[padded-1] == '=' {
		padded--
	}
	if padded > 1 && src[padded-1] == '=' {
		padded--
	}
	dstlen := padded * 3 >> 2
	if dstlen >= nodeBufferPoolHalf {
		dstlen = nodeBase64DecodedSizeFast(len(src))
	}

	dst := make([]byte, dstlen)
	return dst[:nodeBase64Decode(dst, src)]
}

func nodeBase64DecodedSizeFast(size int) int {
	if size < 2 {
		return 0
	}
	return size/4*3 + (size%4+1)/2
}

func nodeBase64DecodedSize(src []uint16) int {
	size := len(src)
	if size < 2 {
		return 0
	}
	if src[size-1] == '=' {
		size--
		if src[size-1] == '=' {
			size--
		}
	}
	return nodeBase64DecodedSizeFast(size)
}

func nodeUnbase64(c uint16) byte {
	return nodeUnbase64Table[byte(c)]
}

func nodeBase64Decode(dst []byte, src []uint16) int {
	dstlen := len(dst)
	srclen := len(src)
	available := nodeBase64DecodedSize(src)
	if dstlen < available {
		available = dstlen
	}
	maxK := available / 3 * 3
	maxI := srclen / 4 * 4
	i, k := 0, 0
	for i < maxI && k < maxK {
		a := nodeUnbase64(src[i])
		b := nodeUnbase64(src[i+1])
		c := nodeUnbase64(src[i+2])
		d := nodeUnbase64(src[i+3])
		if (a|b|c|d)&0x80 != 0 {
			if !nodeBase64DecodeGroupSlow(dst, src, &i, &k) {
				return k
			}
			maxI = i + (srclen-i)/4*4
			continue
		}
		dst[k] = a<<2 | b>>4
		dst[k+1] = b<<4 | c>>2
		dst[k+2] = c<<6 | d
		i += 4
		k += 3
	}
	if i < srclen && k < dstlen {
		nodeBase64DecodeGroupSlow(dst, src, &i, &k)
	}
	return k
}

func nodeBase64DecodeGroupSlow(dst []byte, src []uint16, i, k *int) bool {
	var hi, lo byte
	next := func() bool {
		for {
			c := byte(src[*i])
			lo = nodeUnbase64Table[c]
			*i++
			if lo < 64 {
				return true
			}
			if c == '=' || *i >= len(src) {
				return false
			}
		}
	}
	guard := func() bool {
		if *i >= len(src) || *k >= len(dst) {
			return false
		}
		hi = lo
		return true
	}

	if !next() || !guard() {
		return false
	}
	if !next() {
		return false
	}
	dst[*k] = (hi&0x3F)<<2 | (lo&0x30)>>4
	*k++
	if !guard() || !next() {
		return false
	}
	dst[*k] = (hi&0x0F)<<4 | (lo&0x3C)>>2
	*k++
	if !guard() || !next() {
		return false
	}
	dst[*k] = (hi&0x03)<<6 | lo&0x3F
	*k++
	return guard()
}

func encodeCESU8(value string) string {
	var builder strings.Builder
	builder.Grow(len(value))
	for _, char := range value {
		if char > 0xFFFF {
			high, low := utf16.EncodeRune(char)
			writeCESU8Unit(&builder, uint16(high))
			writeCESU8Unit(&builder, uint16(low))
			continue
		}
		writeCESU8Unit(&builder, uint16(char))
	}
	return builder.String()
}

func writeCESU8Unit(builder *strings.Builder, unit uint16) {
	switch {
	case unit < 0x80:
		builder.WriteByte(byte(unit))
	case unit < 0x800:
		builder.WriteByte(byte(0xC0 + unit>>6))
		builder.WriteByte(byte(0x80 + unit&0x3F))
	default:
		builder.WriteByte(byte(0xE0 + unit>>12))
		builder.WriteByte(byte(0x80 + (unit>>6)&0x3F))
		builder.WriteByte(byte(0x80 + unit&0x3F))
	}
}

func decodeCESU8LikeMysql2(value string) []uint16 {
	units := make([]uint16, 0, len(value))
	var acc uint32
	contBytes, accBytes := 0, 0
	for i := 0; i < len(value); i++ {
		current := value[i]
		if current&0xC0 != 0x80 {
			if contBytes > 0 {
				units = append(units, 0xFFFD)
				contBytes = 0
			}
			switch {
			case current < 0x80:
				units = append(units, uint16(current))
			case current < 0xE0:
				acc, contBytes, accBytes = uint32(current&0x1F), 1, 1
			case current < 0xF0:
				acc, contBytes, accBytes = uint32(current&0x0F), 2, 1
			default:
				units = append(units, 0xFFFD)
			}
			continue
		}

		if contBytes == 0 {
			units = append(units, 0xFFFD)
			continue
		}
		acc = acc<<6 | uint32(current&0x3F)
		contBytes--
		accBytes++
		if contBytes == 0 {
			if (accBytes == 2 && acc < 0x80 && acc > 0) || (accBytes == 3 && acc < 0x800) {
				units = append(units, 0xFFFD)
			} else {
				units = append(units, uint16(acc))
			}
		}
	}

	if len(units) > 0 && units[0] == 0xFEFF {
		units = units[1:]
	}
	if contBytes > 0 {
		units = append(units, '0', 0xFFFD)
	}
	return units
}

func writeJSStringUTF16(buffer *bytes.Buffer, units []uint16) {
	const hexDigits = "0123456789abcdef"

	buffer.WriteByte('"')
	for i := 0; i < len(units); i++ {
		unit := units[i]
		switch {
		case unit == '"':
			buffer.WriteString(`\"`)
		case unit == '\\':
			buffer.WriteString(`\\`)
		case unit == '\b':
			buffer.WriteString(`\b`)
		case unit == '\f':
			buffer.WriteString(`\f`)
		case unit == '\n':
			buffer.WriteString(`\n`)
		case unit == '\r':
			buffer.WriteString(`\r`)
		case unit == '\t':
			buffer.WriteString(`\t`)
		case unit < 0x20:
			buffer.WriteString(`\u00`)
			buffer.WriteByte(hexDigits[unit>>4])
			buffer.WriteByte(hexDigits[unit&0xF])
		case utf16.IsSurrogate(rune(unit)):
			if unit < 0xDC00 && i+1 < len(units) && units[i+1] >= 0xDC00 && units[i+1] <= 0xDFFF {
				buffer.WriteRune(utf16.DecodeRune(rune(unit), rune(units[i+1])))
				i++
				continue
			}
			buffer.WriteString(`\u`)
			buffer.WriteByte(hexDigits[unit>>12])
			buffer.WriteByte(hexDigits[unit>>8&0xF])
			buffer.WriteByte(hexDigits[unit>>4&0xF])
			buffer.WriteByte(hexDigits[unit&0xF])
		default:
			buffer.WriteRune(rune(unit))
		}
	}
	buffer.WriteByte('"')
}

func decodeUTF8LikeNode(data []byte) string {
	var builder strings.Builder
	builder.Grow(len(data))

	var codePoint rune
	needed, seen := 0, 0
	lower, upper := byte(0x80), byte(0xBF)
	for i := 0; i < len(data); {
		c := data[i]
		if needed == 0 {
			i++
			switch {
			case c <= 0x7F:
				builder.WriteByte(c)
			case c >= 0xC2 && c <= 0xDF:
				needed, codePoint = 1, rune(c&0x1F)
			case c >= 0xE0 && c <= 0xEF:
				if c == 0xE0 {
					lower = 0xA0
				}
				if c == 0xED {
					upper = 0x9F
				}
				needed, codePoint = 2, rune(c&0x0F)
			case c >= 0xF0 && c <= 0xF4:
				if c == 0xF0 {
					lower = 0x90
				}
				if c == 0xF4 {
					upper = 0x8F
				}
				needed, codePoint = 3, rune(c&0x07)
			default:
				builder.WriteRune(0xFFFD)
			}
			continue
		}

		if c < lower || c > upper {
			codePoint, needed, seen = 0, 0, 0
			lower, upper = 0x80, 0xBF
			builder.WriteRune(0xFFFD)
			continue
		}

		lower, upper = 0x80, 0xBF
		codePoint = codePoint<<6 | rune(c&0x3F)
		seen++
		i++
		if seen == needed {
			builder.WriteRune(codePoint)
			codePoint, needed, seen = 0, 0, 0
		}
	}
	if needed != 0 {
		builder.WriteRune(0xFFFD)
	}

	return builder.String()
}
