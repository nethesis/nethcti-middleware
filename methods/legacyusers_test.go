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

func TestParseLegacyUsersVoicemails(t *testing.T) {
	cases := map[string]map[string][]string{
		`{"alice":{"name":"A","endpoints":{"voicemail":{"201":{}}}},"bob":{"name":"B","endpoints":{"voicemail":{}}}}`:           {"alice": {"201"}, "bob": nil},
		`{"Alice":{"name":"A","endpoints":{"voicemail":{"202":{}}}},"alice":{"name":"a","endpoints":{"voicemail":{"201":{}}}}}`: {"alice": {"202"}},
		`{"alice":{"name":"a","endpoints":{"voicemail":{"202":{}}}},"Alice":{"name":"A","endpoints":{"voicemail":{"201":{}}}}}`: {"alice": {"201"}},
		`{"alice":{"name":"A","endpoints":{"voicemail":{"201":{}}}},"bob":{"endpoints":{}},"carl":{"name":"C"}}`:                {"alice": nil},
		`{"alice":{"name":"A","endpoints":{"voicemail":{"201":{}}}},"0":null}`:                                                  {},
		`{"a":{"name":"A","endpoints":{"voicemail":{"201":true}}},"b":{"name":"B","endpoints":{"voicemail":{"202":null,"9":"x","1":[]}}},"c":{"name":"C","endpoints":{"voicemail":["x",{}]}},"d":{"name":"D","endpoints":{"voicemail":"201"}},"e":{"name":"E","endpoints":["voicemail"]}}`: {
			"a": nil, "b": {"1"}, "c": nil, "d": nil, "e": nil,
		},
		`{"alice":{"name":"A","endpoints":{"voicemail":{"201":{}}}},"alice":{"name":"A","endpoints":{"voicemail":{"202":{},"203":{}}}}}`: {"alice": {"202", "203"}},
		`[{"name":"A","endpoints":{"voicemail":{"201":{}}}}]`:                                                                            {"0": {"201"}},
		`"alice"`: {},
		`null`:    {},
		`{"__proto__":{"name":"A"},"bob":{"name":"B","endpoints":{"voicemail":{"202":{}}}}}`: {"bob": {"202"}},
	}
	for input, expected := range cases {
		users, err := parseLegacyUsers([]byte(input))
		require.NoError(t, err, input)
		voicemails := map[string][]string{}
		for name, user := range users {
			voicemails[name] = user.voicemails
		}
		assert.Equal(t, expected, voicemails, input)
	}

	_, err := parseLegacyUsers([]byte(`{"alice":`))
	assert.Error(t, err)
}

func TestParseLegacyUsersExtensions(t *testing.T) {
	cases := map[string][]legacyUserExtension{
		`{"mainextension":{"201":{}},"extension":{"201":{"type":"webrtc"},"91201":{"type":"mobile"},"93201":{"type":"physical"},"92201":{"type":"nethlink"}}}`: {
			{id: "201", kind: "webrtc"}, {id: "91201", kind: "mobile"}, {id: "92201", kind: "nethlink"}, {id: "93201", kind: "physical"},
		},
		`{"mainextension":{"201":{}},"extension":{"93201":{"type":"physical"}}}`: {{id: "201"}, {id: "93201", kind: "physical"}},
		`{"mainextension":{"b":{},"a":{}},"extension":{"c":{"type":"physical"},"a":{"type":"webrtc"}}}`: {
			{id: "b"}, {id: "a", kind: "webrtc"}, {id: "c", kind: "physical"},
		},
		`{"mainextension":{"1":{},"2":5,"3":{}},"extension":{"4":{"type":"unknown"},"5":{"type":"physical"},"6":{"type":5},"7":{"type":"physical"}}}`: {
			{id: "1"}, {id: "5", kind: "physical"},
		},
		`{"extension":{"4":{"type":"physical"},"5":null,"6":{"type":"physical"}}}`:                {{id: "4", kind: "physical"}},
		`{"extension":{"4":{"type":"physical"},"5":"x","6":{"type":"physical"}}}`:                 {{id: "4", kind: "physical"}},
		`{"extension":{"4":{"type":"physical"},"5":{"type":"toString"},"6":{"type":"physical"}}}`: {{id: "4", kind: "physical"}},
		`{"extension":["x"]}`:                    {},
		`{"mainextension":null,"extension":"x"}`: {},
	}
	for endpoints, expected := range cases {
		users, err := parseLegacyUsers([]byte(`{"alice":{"name":"A","endpoints":` + endpoints + `}}`))
		require.NoError(t, err, endpoints)
		assert.Equal(t, expected, users["alice"].extensions, endpoints)
	}
}
