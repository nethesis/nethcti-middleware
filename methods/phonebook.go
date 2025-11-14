/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"

	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/store"
)

// PhonebookImportResponse represents the response from a CSV import
type PhonebookImportResponse struct {
	Message       string   `json:"message"`
	TotalRows     int      `json:"total_rows"`
	ImportedRows  int      `json:"imported_rows"`
	FailedRows    int      `json:"failed_rows"`
	SkippedRows   int      `json:"skipped_rows"`
	ErrorMessages []string `json:"error_messages,omitempty"`
}

// ImportPhonebookCSV handles CSV phonebook imports.
// Supports all phonebook fields: name (required), and optional: type, workemail, homeemail, workphone, homephone,
// cellphone, fax, title, company, notes, homestreet, homepob, homecity, homeprovince, homepostalcode, homecountry,
// workstreet, workpob, workcity, workprovince, workpostalcode, workcountry, url, extension, speeddial_num.
// The handler requires JWT authentication and associates imports with the authenticated user.
func ImportPhonebookCSV(c *gin.Context) {
	// Extract user from JWT claims
	claims := jwt.ExtractClaims(c)
	username, ok := claims["id"].(string)
	if !ok || username == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid user in token"})
		return
	}

	// Get the uploaded file
	file, _, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "file required", "error": err.Error()})
		return
	}
	defer file.Close()

	// Parse CSV
	reader := csv.NewReader(file)

	// Read header
	header, err := reader.Read()
	if err != nil {
		logs.Log("[PHONEBOOK] CSV header read error: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid CSV file", "error": err.Error()})
		return
	}

	// Validate header format: must have at least "name"
	if len(header) < 1 {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "CSV must have at least 'name' column",
		})
		return
	}

	// Build column index map (case-insensitive)
	columnIndices := make(map[string]int)
	for i, col := range header {
		colLower := strings.ToLower(strings.TrimSpace(col))
		columnIndices[colLower] = i
	}

	// Validate required "name" column
	if _, hasName := columnIndices["name"]; !hasName {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "CSV must have 'name' column",
		})
		return
	}

	// Parse and import records
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var entries []*store.PhonebookEntry
	var errorMessages []string
	totalRows := 0
	skippedRows := 0

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			logs.Log("[PHONEBOOK] CSV read error: " + err.Error())
			errorMessages = append(errorMessages, fmt.Sprintf("Row %d: %s", totalRows+2, err.Error()))
			continue
		}

		totalRows++

		// Helper function to safely extract field value from record
		getField := func(fieldName string) string {
			if idx, ok := columnIndices[fieldName]; ok && idx < len(record) {
				return strings.TrimSpace(record[idx])
			}
			return ""
		}

		// Extract and validate name (required)
		name := getField("name")
		if name == "" {
			skippedRows++
			errorMessages = append(errorMessages, fmt.Sprintf("Row %d: name is empty", totalRows+1))
			continue
		}

		// Extract type and validate (must be 'private' or 'public', default to 'private')
		entryType := getField("type")
		if entryType == "" {
			entryType = "private"
		} else {
			entryType = strings.ToLower(entryType)
			if entryType != "private" && entryType != "public" {
				skippedRows++
				errorMessages = append(errorMessages, fmt.Sprintf("Row %d: invalid type '%s' (must be 'private' or 'public')", totalRows+1, getField("type")))
				continue
			}
		}

		// Extract all available fields
		entry := &store.PhonebookEntry{
			OwnerID:        username,
			Name:           name,
			Type:           entryType,
			WorkEmail:      getField("workemail"),
			HomeEmail:      getField("homeemail"),
			WorkPhone:      getField("workphone"),
			HomePhone:      getField("homephone"),
			CellPhone:      getField("cellphone"),
			Fax:            getField("fax"),
			Title:          getField("title"),
			Company:        getField("company"),
			Notes:          getField("notes"),
			HomeStreet:     getField("homestreet"),
			HomePOB:        getField("homepob"),
			HomeCity:       getField("homecity"),
			HomeProvince:   getField("homeprovince"),
			HomePostalCode: getField("homepostalcode"),
			HomeCountry:    getField("homecountry"),
			WorkStreet:     getField("workstreet"),
			WorkPOB:        getField("workpob"),
			WorkCity:       getField("workcity"),
			WorkProvince:   getField("workprovince"),
			WorkPostalCode: getField("workpostalcode"),
			WorkCountry:    getField("workcountry"),
			URL:            getField("url"),
			Extension:      getField("extension"),
			SpeedDialNum:   getField("speeddial_num"),
		}

		entries = append(entries, entry)
	}

	// Perform batch import
	successful, failed, err := store.BatchInsertPhonebookEntries(ctx, entries)
	if err != nil {
		logs.Log("[PHONEBOOK] Batch import error: " + err.Error())
		errorMessages = append(errorMessages, "Database error: "+err.Error())
	}

	response := PhonebookImportResponse{
		Message:       "phonebook import completed",
		TotalRows:     totalRows,
		ImportedRows:  successful,
		FailedRows:    failed,
		SkippedRows:   skippedRows,
		ErrorMessages: errorMessages,
	}

	c.JSON(http.StatusOK, response)
}
