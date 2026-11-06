/*
 * Copyright (C) 2026 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
)

type jsNodeKind int

const (
	jsNodeNull jsNodeKind = iota
	jsNodeBool
	jsNodeNumber
	jsNodeString
	jsNodeArray
	jsNodeObject
)

type jsNode struct {
	kind   jsNodeKind
	text   string
	keys   []string
	values []*jsNode
}

func normalizeJSONLikeJavaScript(raw []byte) ([]byte, error) {
	node, err := parseJSNode(raw)
	if err != nil {
		return nil, err
	}

	var buffer bytes.Buffer
	writeJSNode(&buffer, node)
	return buffer.Bytes(), nil
}

func parseJSNode(raw []byte) (*jsNode, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()

	node, err := decodeJSNode(decoder)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("unexpected data after JSON value")
	}

	return node, nil
}

func decodeJSNode(decoder *json.Decoder) (*jsNode, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}

	switch value := token.(type) {
	case nil:
		return &jsNode{kind: jsNodeNull}, nil
	case bool:
		return &jsNode{kind: jsNodeBool, text: strconv.FormatBool(value)}, nil
	case json.Number:
		return &jsNode{kind: jsNodeNumber, text: jsNumberString(value)}, nil
	case string:
		return &jsNode{kind: jsNodeString, text: value}, nil
	case json.Delim:
		switch value {
		case '[':
			node := &jsNode{kind: jsNodeArray}
			for decoder.More() {
				item, err := decodeJSNode(decoder)
				if err != nil {
					return nil, err
				}
				node.values = append(node.values, item)
			}
			if _, err := decoder.Token(); err != nil {
				return nil, err
			}
			return node, nil
		case '{':
			node := &jsNode{kind: jsNodeObject}
			positions := map[string]int{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				key, _ := keyToken.(string)
				item, err := decodeJSNode(decoder)
				if err != nil {
					return nil, err
				}
				if index, exists := positions[key]; exists {
					node.values[index] = item
					continue
				}
				positions[key] = len(node.keys)
				node.keys = append(node.keys, key)
				node.values = append(node.values, item)
			}
			if _, err := decoder.Token(); err != nil {
				return nil, err
			}

			order := jsPropertyOrder(len(node.keys), func(i int) string { return node.keys[i] })
			keys := make([]string, len(order))
			values := make([]*jsNode, len(order))
			for i, index := range order {
				keys[i] = node.keys[index]
				values[i] = node.values[index]
			}
			node.keys = keys
			node.values = values
			return node, nil
		}
	}

	return nil, fmt.Errorf("unexpected JSON token %v", token)
}

func writeJSNode(buffer *bytes.Buffer, node *jsNode) {
	switch node.kind {
	case jsNodeNull:
		buffer.WriteString("null")
	case jsNodeBool, jsNodeNumber:
		buffer.WriteString(node.text)
	case jsNodeString:
		writeJSString(buffer, node.text)
	case jsNodeArray:
		buffer.WriteByte('[')
		for i, item := range node.values {
			if i > 0 {
				buffer.WriteByte(',')
			}
			writeJSNode(buffer, item)
		}
		buffer.WriteByte(']')
	case jsNodeObject:
		buffer.WriteByte('{')
		for i, key := range node.keys {
			if i > 0 {
				buffer.WriteByte(',')
			}
			writeJSString(buffer, key)
			buffer.WriteByte(':')
			writeJSNode(buffer, node.values[i])
		}
		buffer.WriteByte('}')
	}
}

func writeJSString(buffer *bytes.Buffer, value string) {
	const hexDigits = "0123456789abcdef"

	buffer.WriteByte('"')
	for _, char := range value {
		switch char {
		case '"':
			buffer.WriteString(`\"`)
		case '\\':
			buffer.WriteString(`\\`)
		case '\b':
			buffer.WriteString(`\b`)
		case '\f':
			buffer.WriteString(`\f`)
		case '\n':
			buffer.WriteString(`\n`)
		case '\r':
			buffer.WriteString(`\r`)
		case '\t':
			buffer.WriteString(`\t`)
		default:
			if char < 0x20 {
				buffer.WriteString(`\u00`)
				buffer.WriteByte(hexDigits[char>>4])
				buffer.WriteByte(hexDigits[char&0xf])
				continue
			}
			buffer.WriteRune(char)
		}
	}
	buffer.WriteByte('"')
}

func jsNumberString(number json.Number) string {
	value, err := strconv.ParseFloat(number.String(), 64)
	if err != nil || math.IsInf(value, 0) || math.IsNaN(value) {
		return "null"
	}
	if value == 0 {
		return "0"
	}

	absolute := math.Abs(value)
	if absolute >= 1e21 || absolute < 1e-6 {
		formatted := strconv.FormatFloat(value, 'e', -1, 64)
		mantissa, exponent, _ := strings.Cut(formatted, "e")
		sign := exponent[:1]
		digits := strings.TrimLeft(exponent[1:], "0")
		return mantissa + "e" + sign + digits
	}

	return strconv.FormatFloat(value, 'f', -1, 64)
}

func jsPropertyOrder(count int, keyAt func(int) string) []int {
	indexKeys := make([]int, 0)
	otherKeys := make([]int, 0, count)
	for i := 0; i < count; i++ {
		if _, ok := jsArrayIndex(keyAt(i)); ok {
			indexKeys = append(indexKeys, i)
		} else {
			otherKeys = append(otherKeys, i)
		}
	}

	sort.SliceStable(indexKeys, func(a, b int) bool {
		left, _ := jsArrayIndex(keyAt(indexKeys[a]))
		right, _ := jsArrayIndex(keyAt(indexKeys[b]))
		return left < right
	})

	return append(indexKeys, otherKeys...)
}

func jsArrayIndex(key string) (uint64, bool) {
	if key == "" || (len(key) > 1 && key[0] == '0') {
		return 0, false
	}
	for _, char := range key {
		if char < '0' || char > '9' {
			return 0, false
		}
	}
	value, err := strconv.ParseUint(key, 10, 64)
	if err != nil || value >= 4294967295 {
		return 0, false
	}
	return value, true
}
