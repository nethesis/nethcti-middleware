/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"net/http"
	"strings"

	"github.com/fatih/structs"
	"github.com/gin-gonic/gin"
	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/models"
	"github.com/nethesis/nethcti-middleware/summary"
)

type SummaryWatchRequest struct {
	UniqueID string `json:"uniqueid"`
}

// WatchCallSummary starts watching for a summary in the satellite transcripts table.
func WatchCallSummary(c *gin.Context) {
	var req SummaryWatchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(models.StatusBadRequest{
			Code:    http.StatusBadRequest,
			Message: "invalid request payload",
			Data:    err.Error(),
		}))
		return
	}

	uniqueID := strings.TrimSpace(req.UniqueID)
	if uniqueID == "" {
		c.JSON(http.StatusBadRequest, structs.Map(models.StatusBadRequest{
			Code:    http.StatusBadRequest,
			Message: "uniqueid is required",
			Data:    nil,
		}))
		return
	}

	if !summary.IsSatelliteDBConfigured() {
		c.JSON(http.StatusServiceUnavailable, structs.Map(models.StatusServiceUnavailable{
			Code:    http.StatusServiceUnavailable,
			Message: "satellite database not configured",
			Data:    nil,
		}))
		return
	}

	started := summary.StartSummaryWatch(uniqueID)
	if !started {
		logs.Log("[INFO][SUMMARY] Watch already active or configuration missing for uniqueid: " + uniqueID)
		c.JSON(http.StatusOK, structs.Map(models.StatusOK{
			Code:    http.StatusOK,
			Message: "watch already active or unavailable",
			Data: gin.H{
				"uniqueid": uniqueID,
			},
		}))
		return
	}

	logs.Log("[INFO][SUMMARY] Watch started for uniqueid: " + uniqueID)
	c.JSON(http.StatusAccepted, structs.Map(models.StatusOK{
		Code:    http.StatusAccepted,
		Message: "watch started",
		Data: gin.H{
			"uniqueid": uniqueID,
		},
	}))
}
