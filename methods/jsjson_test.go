/*
 * Copyright (C) 2026 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeJSONLikeJavaScript(t *testing.T) {
	cases := map[string]string{
		`{"b":1,"a":2}`:                            `{"b":1,"a":2}`,
		`{"b":1,"10":2,"2":3,"01":4}`:              `{"2":3,"10":2,"b":1,"01":4}`,
		`{"a":1,"b":2,"a":3}`:                      `{"a":3,"b":2}`,
		`{ "x" : [ 1 , { "z":null, "y":true } ] }`: `{"x":[1,{"z":null,"y":true}]}`,
		`[1.0, -0, 1e21, 1.5e-7, 0.000001, 123456789012345678901234, 2.50]`: `[1,0,1e+21,1.5e-7,0.000001,1.2345678901234569e+23,2.5]`,
		`"a\"b\\c\n\t\u0001\u001f é/<>&"`:                                   `"a\"b\\c\n\t\u0001\u001f` + " " + `é/<>&"`,
		`false`:                                                             `false`,
		`null`:                                                              `null`,
	}

	for input, expected := range cases {
		output, err := normalizeJSONLikeJavaScript([]byte(input))
		require.NoError(t, err, input)
		assert.Equal(t, expected, string(output), input)
	}
}

func TestNormalizeJSONLikeJavaScript_RejectsInvalidJSON(t *testing.T) {
	for _, input := range []string{`{"a":`, `{"a":1} {}`, ``, `nope`} {
		_, err := normalizeJSONLikeJavaScript([]byte(input))
		assert.Error(t, err, input)
	}
}
