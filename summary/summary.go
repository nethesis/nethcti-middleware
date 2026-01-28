/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package summary

import (
	"context"
	"database/sql"
	"strings"
	"sync"
	"time"

	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/db"
	"github.com/nethesis/nethcti-middleware/logs"
)

// SummaryMessage represents the payload sent over WebSocket when a summary is available.
type SummaryMessage struct {
	UniqueID string `json:"uniqueid"`
	Summary  string `json:"summary"`
}

type watcher struct {
	mutex  sync.Mutex
	active map[string]context.CancelFunc
}

var summaryWatcher = &watcher{active: make(map[string]context.CancelFunc)}

var fetchSummaryFunc = fetchSummaryFromDB

type notifyFunc func(SummaryMessage)

var notifySummaryFunc notifyFunc = func(SummaryMessage) {}

var summaryPollInterval = 5 * time.Second

// StartSummaryWatch registers a watcher for the given unique ID.
// It returns true if a new watcher was started, false if already active or misconfigured.
func StartSummaryWatch(uniqueID string) bool {
	cleanUniqueID := strings.TrimSpace(uniqueID)
	if cleanUniqueID == "" {
		return false
	}

	if !IsSatelliteDBConfigured() {
		logs.Log("[ERROR][SUMMARY] Satellite DB configuration missing; cannot start watcher")
		return false
	}

	summaryWatcher.mutex.Lock()
	if _, exists := summaryWatcher.active[cleanUniqueID]; exists {
		summaryWatcher.mutex.Unlock()
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	summaryWatcher.active[cleanUniqueID] = cancel
	summaryWatcher.mutex.Unlock()

	go summaryWatcher.watch(ctx, cleanUniqueID)
	return true
}

// IsSatelliteDBConfigured checks whether the satellite DB configuration is present.
func IsSatelliteDBConfigured() bool {
	return configuration.Config.SatellitePgSQLHost != "" &&
		configuration.Config.SatellitePgSQLPort != "" &&
		configuration.Config.SatellitePgSQLDB != "" &&
		configuration.Config.SatellitePgSQLUser != ""
}

// SetSummaryNotifier sets the callback used to deliver summary notifications.
func SetSummaryNotifier(fn notifyFunc) {
	if fn == nil {
		notifySummaryFunc = func(SummaryMessage) {}
		return
	}
	notifySummaryFunc = fn
}

func (w *watcher) watch(ctx context.Context, uniqueID string) {
	ticker := time.NewTicker(summaryPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.remove(uniqueID)
			logs.Log("[INFO][SUMMARY] Watch timeout reached for uniqueid: " + uniqueID)
			return
		case <-ticker.C:
			summaryText, found, err := fetchSummaryFunc(uniqueID)
			if err != nil {
				logs.Log("[ERROR][SUMMARY] Failed to fetch summary for uniqueid " + uniqueID + ": " + err.Error())
				continue
			}
			if found {
				notifySummaryFunc(SummaryMessage{
					UniqueID: uniqueID,
					Summary:  summaryText,
				})
				w.remove(uniqueID)
				logs.Log("[INFO][SUMMARY] Summary found for uniqueid: " + uniqueID)
				return
			}
		}
	}
}

func (w *watcher) remove(uniqueID string) {
	w.mutex.Lock()
	if cancel, exists := w.active[uniqueID]; exists {
		delete(w.active, uniqueID)
		cancel()
	}
	w.mutex.Unlock()
}

func fetchSummaryFromDB(uniqueID string) (string, bool, error) {
	database := db.GetSatelliteDB()
	if database == nil {
		return "", false, sql.ErrConnDone
	}

	queryCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var summary sql.NullString
	query := "SELECT summary FROM transcripts WHERE uniqueid = $1 LIMIT 1"
	err := database.QueryRowContext(queryCtx, query, uniqueID).Scan(&summary)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", false, nil
		}
		return "", false, err
	}

	if !summary.Valid || strings.TrimSpace(summary.String) == "" {
		return "", false, nil
	}

	return summary.String, true, nil
}
