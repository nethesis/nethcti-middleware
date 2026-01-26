/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package summary

import (
	"context"
	"testing"
	"time"

	"github.com/nethesis/nethcti-middleware/configuration"
)

func TestStartSummaryWatchBroadcastsAndStops(t *testing.T) {
	configuration.Config.SatellitePgSQLHost = "test"
	configuration.Config.SatellitePgSQLPort = "3306"
	configuration.Config.SatellitePgSQLDB = "test"
	configuration.Config.SatellitePgSQLUser = "test"

	originalFetch := fetchSummaryFunc
	originalNotify := notifySummaryFunc
	defer func() {
		fetchSummaryFunc = originalFetch
		notifySummaryFunc = originalNotify
		resetWatcher()
	}()

	called := 0
	fetchSummaryFunc = func(uniqueID string) (string, bool, error) {
		called++
		if called >= 1 {
			return "summary text", true, nil
		}
		return "", false, nil
	}

	ch := make(chan SummaryMessage, 1)
	notifySummaryFunc = func(msg SummaryMessage) {
		ch <- msg
	}

	if !StartSummaryWatch("abc123") {
		t.Fatalf("expected watcher to start")
	}

	select {
	case msg := <-ch:
		if msg.UniqueID != "abc123" {
			t.Fatalf("unexpected uniqueid: %s", msg.UniqueID)
		}
		if msg.Summary != "summary text" {
			t.Fatalf("unexpected summary: %s", msg.Summary)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timeout waiting for summary broadcast")
	}
}

func TestStartSummaryWatchIsIdempotent(t *testing.T) {
	configuration.Config.SatellitePgSQLHost = "test"
	configuration.Config.SatellitePgSQLPort = "3306"
	configuration.Config.SatellitePgSQLDB = "test"
	configuration.Config.SatellitePgSQLUser = "test"

	originalFetch := fetchSummaryFunc
	originalNotify := notifySummaryFunc
	defer func() {
		fetchSummaryFunc = originalFetch
		notifySummaryFunc = originalNotify
		resetWatcher()
	}()

	fetchSummaryFunc = func(uniqueID string) (string, bool, error) {
		return "", false, nil
	}
	notifySummaryFunc = func(msg SummaryMessage) {}

	if !StartSummaryWatch("dup123") {
		t.Fatalf("expected watcher to start")
	}

	if StartSummaryWatch("dup123") {
		t.Fatalf("expected duplicate watcher to be rejected")
	}
}

func resetWatcher() {
	summaryWatcher.mutex.Lock()
	for _, cancel := range summaryWatcher.active {
		cancel()
	}
	summaryWatcher.active = map[string]context.CancelFunc{}
	summaryWatcher.mutex.Unlock()
}
