/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import "testing"

func TestEnrichRingGroupRows_UnansweredShowsGroupName(t *testing.T) {
	// A ring-group call nobody answered: a single CDR row with dst=600 (the group
	// number) and NO ANSWER. The destination must become the group NAME.
	rows := []map[string]interface{}{
		{"linkedid": "L1", "uniqueid": "u1", "src": "202", "dst": "600", "dstchannel": "PJSIP/201-00000014", "disposition": "NO ANSWER", "dst_cnam": ""},
	}
	enrichRingGroupRows(rows, map[string]string{"600": "Test RG"})

	if rows[0]["dst"] != "600" {
		t.Fatalf("expected dst to stay the group number 600, got %v", rows[0]["dst"])
	}
	if rows[0]["dst_cnam"] != "Test RG" {
		t.Fatalf("expected dst_cnam = group name, got %v", rows[0]["dst_cnam"])
	}
	if rows[0]["ringGroupName"] != "Test RG" {
		t.Fatalf("expected ringGroupName marker, got %v", rows[0]["ringGroupName"])
	}
}

func TestEnrichRingGroupRows_AnsweredShowsWhoAnswered(t *testing.T) {
	// A ring-group call answered by member 201: dst=600, ANSWERED, dstchannel points
	// to 201. The destination must become the answering member, not the group.
	rows := []map[string]interface{}{
		{"linkedid": "L1", "uniqueid": "u1", "src": "202", "dst": "600", "dstchannel": "PJSIP/201-00000012", "disposition": "ANSWERED", "dst_cnam": ""},
	}
	enrichRingGroupRows(rows, map[string]string{"600": "Test RG"})

	if rows[0]["dst"] != "201" {
		t.Fatalf("expected dst = who answered (201), got %v", rows[0]["dst"])
	}
	if rows[0]["ringGroupName"] != "Test RG" {
		t.Fatalf("expected ringGroupName marker kept for answered call, got %v", rows[0]["ringGroupName"])
	}
}

func TestEnrichRingGroupRows_NonGroupRowsUntouched(t *testing.T) {
	// A normal direct call to 201 must not be altered.
	rows := []map[string]interface{}{
		{"dst": "201", "dstchannel": "PJSIP/201-1", "disposition": "ANSWERED", "dst_cnam": "Andrea"},
	}
	enrichRingGroupRows(rows, map[string]string{"600": "Test RG"})

	if rows[0]["dst"] != "201" || rows[0]["dst_cnam"] != "Andrea" {
		t.Fatalf("non-group row was modified: %v", rows[0])
	}
	if _, marked := rows[0]["ringGroupName"]; marked {
		t.Fatalf("non-group row must not get a ringGroupName marker")
	}
}

func TestEnrichRingGroupRows_EmptyMapNoop(t *testing.T) {
	rows := []map[string]interface{}{
		{"dst": "600", "disposition": "NO ANSWER"},
	}
	enrichRingGroupRows(rows, map[string]string{})
	if _, marked := rows[0]["ringGroupName"]; marked {
		t.Fatalf("no ring groups configured must be a no-op")
	}
}

func TestExtensionFromChannel(t *testing.T) {
	cases := map[string]string{
		"PJSIP/201-00000012":            "201",
		"SIP/202-abcd":                  "202",
		"Local/203@from-internal-0001;1": "203",
		"PJSIP/trunk-name-1":            "", // non-numeric endpoint
		"":                             "",
		"garbage":                      "",
	}
	for in, want := range cases {
		if got := extensionFromChannel(in); got != want {
			t.Fatalf("extensionFromChannel(%q) = %q, want %q", in, got, want)
		}
	}
}
