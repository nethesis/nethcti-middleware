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

	originalInterval := summaryPollInterval
	summaryPollInterval = 10 * time.Millisecond
	originalTimeout := summaryWatchTimeout
	summaryWatchTimeout = time.Second

	originalFetch := fetchSummaryFunc
	originalWatchStatus := fetchSummaryWatchStatusFunc
	originalNotify := notifySummaryFunc
	defer func() {
		fetchSummaryFunc = originalFetch
		fetchSummaryWatchStatusFunc = originalWatchStatus
		notifySummaryFunc = originalNotify
		summaryPollInterval = originalInterval
		summaryWatchTimeout = originalTimeout
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
	fetchSummaryWatchStatusFunc = func(uniqueID string) (bool, error) {
		return false, nil
	}

	ch := make(chan SummaryMessage, 1)
	notifySummaryFunc = func(msg SummaryMessage) {
		ch <- msg
	}

	if !StartSummaryWatch("abc123", "alice") {
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
		if msg.Username != "alice" {
			t.Fatalf("unexpected username: %s", msg.Username)
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

	originalInterval := summaryPollInterval
	summaryPollInterval = 10 * time.Millisecond
	originalTimeout := summaryWatchTimeout
	summaryWatchTimeout = time.Second

	originalFetch := fetchSummaryFunc
	originalWatchStatus := fetchSummaryWatchStatusFunc
	originalNotify := notifySummaryFunc
	defer func() {
		fetchSummaryFunc = originalFetch
		fetchSummaryWatchStatusFunc = originalWatchStatus
		notifySummaryFunc = originalNotify
		summaryPollInterval = originalInterval
		summaryWatchTimeout = originalTimeout
		resetWatcher()
	}()

	fetchSummaryFunc = func(uniqueID string) (string, bool, error) {
		return "", false, nil
	}
	fetchSummaryWatchStatusFunc = func(uniqueID string) (bool, error) {
		return true, nil
	}
	notifySummaryFunc = func(msg SummaryMessage) {}

	if !StartSummaryWatch("dup123", "alice") {
		t.Fatalf("expected watcher to start")
	}

	if StartSummaryWatch("dup123", "alice") {
		t.Fatalf("expected duplicate watcher to be rejected")
	}

	if !StartSummaryWatch("dup123", "bob") {
		t.Fatalf("expected same uniqueid for another user to be allowed")
	}

	time.Sleep(50 * time.Millisecond)
}

func TestStartSummaryWatchPollsImmediately(t *testing.T) {
	configuration.Config.SatellitePgSQLHost = "test"
	configuration.Config.SatellitePgSQLPort = "3306"
	configuration.Config.SatellitePgSQLDB = "test"
	configuration.Config.SatellitePgSQLUser = "test"

	originalInterval := summaryPollInterval
	summaryPollInterval = time.Hour
	originalTimeout := summaryWatchTimeout
	summaryWatchTimeout = time.Second

	originalFetch := fetchSummaryFunc
	originalWatchStatus := fetchSummaryWatchStatusFunc
	originalNotify := notifySummaryFunc
	defer func() {
		fetchSummaryFunc = originalFetch
		fetchSummaryWatchStatusFunc = originalWatchStatus
		notifySummaryFunc = originalNotify
		summaryPollInterval = originalInterval
		summaryWatchTimeout = originalTimeout
		resetWatcher()
	}()

	fetchSummaryFunc = func(uniqueID string) (string, bool, error) {
		return "ready now", true, nil
	}
	fetchSummaryWatchStatusFunc = func(uniqueID string) (bool, error) {
		return false, nil
	}

	ch := make(chan SummaryMessage, 1)
	notifySummaryFunc = func(msg SummaryMessage) {
		ch <- msg
	}

	if !StartSummaryWatch("instant123", "alice") {
		t.Fatalf("expected watcher to start")
	}

	select {
	case msg := <-ch:
		if msg.UniqueID != "instant123" {
			t.Fatalf("unexpected uniqueid: %s", msg.UniqueID)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for immediate summary broadcast")
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

func TestStartSummaryWatchStopsWhenSummaryCannotBeProduced(t *testing.T) {
	configuration.Config.SatellitePgSQLHost = "test"
	configuration.Config.SatellitePgSQLPort = "3306"
	configuration.Config.SatellitePgSQLDB = "test"
	configuration.Config.SatellitePgSQLUser = "test"

	originalInterval := summaryPollInterval
	summaryPollInterval = 10 * time.Millisecond
	originalTimeout := summaryWatchTimeout
	summaryWatchTimeout = time.Second

	originalFetch := fetchSummaryFunc
	originalWatchStatus := fetchSummaryWatchStatusFunc
	originalNotify := notifySummaryFunc
	defer func() {
		fetchSummaryFunc = originalFetch
		fetchSummaryWatchStatusFunc = originalWatchStatus
		notifySummaryFunc = originalNotify
		summaryPollInterval = originalInterval
		summaryWatchTimeout = originalTimeout
		resetWatcher()
	}()

	fetchSummaryFunc = func(uniqueID string) (string, bool, error) {
		return "", false, nil
	}
	fetchSummaryWatchStatusFunc = func(uniqueID string) (bool, error) {
		return true, nil
	}

	notified := false
	notifySummaryFunc = func(msg SummaryMessage) {
		notified = true
	}

	if !StartSummaryWatch("silent123", "alice") {
		t.Fatalf("expected watcher to start")
	}

	time.Sleep(50 * time.Millisecond)

	if notified {
		t.Fatalf("did not expect summary notification")
	}

	summaryWatcher.mutex.Lock()
	_, stillActive := summaryWatcher.active["alice:silent123"]
	summaryWatcher.mutex.Unlock()
	if stillActive {
		t.Fatalf("expected watcher to stop when summary cannot be produced")
	}
}
