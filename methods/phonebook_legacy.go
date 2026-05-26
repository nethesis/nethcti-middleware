/*
 * Copyright (C) 2026 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/store"
)

type legacyPhonebookOperatorGroup struct {
	Users []string `json:"users"`
}

var (
	errInvalidSharedGroups     = errors.New("invalid shared groups")
	errForbiddenSharedGroups   = errors.New("forbidden shared groups")
	errLegacySessionUnavailable = errors.New("legacy session unavailable")

	fetchPhonebookOperatorGroupsFunc = fetchPhonebookOperatorGroupsFromV1
	getPhonebookEntryByIDFunc        = store.GetPhonebookEntryByID
	createPhonebookEntryFunc         = store.CreatePhonebookEntry
	updatePhonebookEntryFieldsFunc   = store.UpdatePhonebookEntryFields
	deletePhonebookEntryByIDFunc     = store.DeletePhonebookEntryByID
	searchLegacyPhonebookFunc        = store.SearchLegacyPhonebook
	listLegacyPhonebookFunc          = store.ListLegacyPhonebook
	getUserCapabilitiesFunc          = store.GetUserCapabilities
)

var legacyPhonebookWritableFields = []string{
	"name",
	"homeemail",
	"workemail",
	"homephone",
	"workphone",
	"cellphone",
	"fax",
	"title",
	"company",
	"notes",
	"homestreet",
	"homepob",
	"homecity",
	"homeprovince",
	"homepostalcode",
	"homecountry",
	"workstreet",
	"workpob",
	"workcity",
	"workprovince",
	"workpostalcode",
	"workcountry",
	"url",
	"extension",
	"speeddial_num",
}

// SearchLegacyPhonebook serves the legacy union search route from middleware.
func SearchLegacyPhonebook(c *gin.Context) {
	username, err := getUsernameFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "unauthorized"})
		return
	}

	userGroups, err := getUserGroupNames(username)
	if err != nil {
		writePhonebookGroupLookupError(c, err)
		return
	}

	query, err := buildLegacyPhonebookQuery(c, username, userGroups)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	query.Term = c.Param("term")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := searchLegacyPhonebookFunc(ctx, query)
	if err != nil {
		logs.Log("[ERROR][PHONEBOOK] Failed to search phonebook: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to search phonebook"})
		return
	}

	c.JSON(http.StatusOK, result)
}

// ListLegacyPhonebook serves the legacy alphabetical list route from middleware.
func ListLegacyPhonebook(c *gin.Context) {
	username, err := getUsernameFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "unauthorized"})
		return
	}

	userGroups, err := getUserGroupNames(username)
	if err != nil {
		writePhonebookGroupLookupError(c, err)
		return
	}

	query, err := buildLegacyPhonebookQuery(c, username, userGroups)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := listLegacyPhonebookFunc(ctx, query)
	if err != nil {
		logs.Log("[ERROR][PHONEBOOK] Failed to list phonebook: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to list phonebook"})
		return
	}

	c.JSON(http.StatusOK, result)
}

// GetLegacyCTIPhonebookContact serves the legacy CTI phonebook detail route from middleware.
func GetLegacyCTIPhonebookContact(c *gin.Context) {
	username, err := getUsernameFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "unauthorized"})
		return
	}

	contactID, err := strconv.ParseInt(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid contact id"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	contact, err := getPhonebookEntryByIDFunc(ctx, contactID)
	if err != nil {
		logs.Log("[ERROR][PHONEBOOK] Failed to load CTI phonebook contact: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to retrieve phonebook contact"})
		return
	}

	if contact == nil {
		c.JSON(http.StatusOK, gin.H{})
		return
	}

	userGroups := []string{}
	if contact.OwnerID != username && store.HasGroupTypePrefix(contact.Type) {
		userGroups, err = getUserGroupNames(username)
		if err != nil {
			writePhonebookGroupLookupError(c, err)
			return
		}
	}

	if !canReadCtiContact(username, contact, userGroups) {
		c.JSON(http.StatusForbidden, gin.H{"message": "forbidden"})
		return
	}

	c.JSON(http.StatusOK, legacyPhonebookEntryResponse(contact))
}

// CreateLegacyCTIPhonebookContact creates a legacy CTI phonebook contact from middleware.
func CreateLegacyCTIPhonebookContact(c *gin.Context) {
	username, err := getUsernameFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "unauthorized"})
		return
	}

	payload, err := decodeLegacyPhonebookPayload(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid request payload"})
		return
	}

	contactTypeValue, ok := payload["type"].(string)
	if !ok || strings.TrimSpace(contactTypeValue) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "type is required"})
		return
	}

	nameValue, ok := payload["name"].(string)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"message": "name is required"})
		return
	}

	contactType, err := normalizeRequestedContactType(username, contactTypeValue)
	if err != nil {
		writePhonebookValidationError(c, err)
		return
	}

	if !canWriteContactType(username, contactType) {
		c.JSON(http.StatusForbidden, gin.H{"message": "forbidden"})
		return
	}

	entry := &store.PhonebookEntry{
		OwnerID: username,
		Type:    contactType,
		Name:    nameValue,
	}

	for _, fieldName := range legacyPhonebookWritableFields {
		value, present, err := extractNullableLegacyString(payload, fieldName)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "invalid request payload"})
			return
		}
		if !present || value == nil {
			continue
		}

		assignPhonebookEntryField(entry, fieldName, value.(string))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := createPhonebookEntryFunc(ctx, entry); err != nil {
		logs.Log("[ERROR][PHONEBOOK] Failed to create CTI phonebook contact: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to create phonebook contact"})
		return
	}

	c.Status(http.StatusCreated)
	c.Writer.WriteHeaderNow()
}

// UpdateLegacyCTIPhonebookContact updates a legacy CTI phonebook contact from middleware.
func UpdateLegacyCTIPhonebookContact(c *gin.Context) {
	username, err := getUsernameFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "unauthorized"})
		return
	}

	payload, err := decodeLegacyPhonebookPayload(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid request payload"})
		return
	}

	contactID, err := parseLegacyPhonebookID(payload["id"])
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid contact id"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	existingContact, err := getPhonebookEntryByIDFunc(ctx, contactID)
	if err != nil {
		logs.Log("[ERROR][PHONEBOOK] Failed to load CTI phonebook contact before update: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to retrieve phonebook contact"})
		return
	}

	if existingContact == nil {
		c.JSON(http.StatusForbidden, gin.H{"message": "forbidden"})
		return
	}

	updateFields, err := extractLegacyPhonebookUpdateFields(payload)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid request payload"})
		return
	}

	nextType := existingContact.Type
	if rawType, present := payload["type"]; present {
		rawTypeString, ok := rawType.(string)
		if !ok || strings.TrimSpace(rawTypeString) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"message": "invalid contact type"})
			return
		}

		nextType, err = normalizeRequestedContactType(username, rawTypeString)
		if err != nil {
			writePhonebookValidationError(c, err)
			return
		}
		updateFields["type"] = nextType
	}

	if !canWriteExistingContact(username, existingContact, nextType) {
		c.JSON(http.StatusForbidden, gin.H{"message": "forbidden"})
		return
	}

	if len(updateFields) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"message": "no fields to update"})
		return
	}

	if err := updatePhonebookEntryFieldsFunc(ctx, contactID, updateFields); err != nil {
		logs.Log("[ERROR][PHONEBOOK] Failed to update CTI phonebook contact: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to update phonebook contact"})
		return
	}

	c.Status(http.StatusOK)
	c.Writer.WriteHeaderNow()
}

// DeleteLegacyCTIPhonebookContact deletes a legacy CTI phonebook contact from middleware.
func DeleteLegacyCTIPhonebookContact(c *gin.Context) {
	username, err := getUsernameFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "unauthorized"})
		return
	}

	payload, err := decodeLegacyPhonebookPayload(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid request payload"})
		return
	}

	contactID, err := parseLegacyPhonebookID(payload["id"])
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid contact id"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	existingContact, err := getPhonebookEntryByIDFunc(ctx, contactID)
	if err != nil {
		logs.Log("[ERROR][PHONEBOOK] Failed to load CTI phonebook contact before delete: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to retrieve phonebook contact"})
		return
	}

	if existingContact == nil || !canWriteExistingContact(username, existingContact, "") {
		c.JSON(http.StatusForbidden, gin.H{"message": "forbidden"})
		return
	}

	if err := deletePhonebookEntryByIDFunc(ctx, contactID); err != nil {
		logs.Log("[ERROR][PHONEBOOK] Failed to delete CTI phonebook contact: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to delete phonebook contact"})
		return
	}

	c.Status(http.StatusOK)
	c.Writer.WriteHeaderNow()
}

func fetchPhonebookOperatorGroupsFromV1(username string) (map[string]legacyPhonebookOperatorGroup, error) {
	userSession := store.UserSessions[username]
	if userSession == nil || strings.TrimSpace(userSession.NethCTIToken) == "" {
		return nil, errLegacySessionUnavailable
	}
	if configuration.Config.V1ApiEndpoint == "" {
		return nil, fmt.Errorf("V1 API endpoint not configured")
	}

	requestURL := configuration.Config.V1Protocol + "://" + configuration.Config.V1ApiEndpoint + configuration.Config.V1ApiPath + "/astproxy/opgroups"
	httpReq, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", userSession.NethCTIToken)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		bodyText := strings.TrimSpace(string(bodyBytes))
		if bodyText == "" {
			return nil, fmt.Errorf("unexpected V1 response status: %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("unexpected V1 response status: %d: %s", resp.StatusCode, bodyText)
	}

	var groups map[string]legacyPhonebookOperatorGroup
	if err := json.NewDecoder(resp.Body).Decode(&groups); err != nil {
		return nil, err
	}
	if groups == nil {
		groups = map[string]legacyPhonebookOperatorGroup{}
	}

	return groups, nil
}

func getUserGroupNames(username string) ([]string, error) {
	capabilities, err := getUserCapabilitiesFunc(username)
	if err != nil {
		return nil, err
	}

	allGroups, err := fetchPhonebookOperatorGroupsFunc(username)
	if err != nil {
		return nil, err
	}

	return computeVisibleGroupNames(username, capabilities, allGroups), nil
}

func computeVisibleGroupNames(username string, capabilities map[string]bool, allGroups map[string]legacyPhonebookOperatorGroup) []string {
	groupNames := make([]string, 0, len(allGroups))
	for groupName := range allGroups {
		groupNames = append(groupNames, groupName)
	}
	sort.Strings(groupNames)

	if store.CanSeeAllOperatorGroups(capabilities) {
		return groupNames
	}

	allowedGroupIDs := store.GetAllowedOperatorGroupIDs(capabilities)
	allowedGroupSet := make(map[string]struct{}, len(allowedGroupIDs))
	for _, groupID := range allowedGroupIDs {
		allowedGroupSet[groupID] = struct{}{}
	}

	visibleGroups := make([]string, 0, len(groupNames))
	for _, groupName := range groupNames {
		groupPermissionID := store.GetGroupPermissionID(groupName)
		_, explicitlyAllowed := allowedGroupSet[groupPermissionID]
		belongsToGroup := containsString(allGroups[groupName].Users, username)
		if explicitlyAllowed || belongsToGroup {
			visibleGroups = append(visibleGroups, groupName)
		}
	}

	return visibleGroups
}

func normalizeRequestedContactType(username, rawType string) (string, error) {
	contactType := normalizeLegacyContactType(rawType)
	if store.IsReservedContactType(contactType) {
		return contactType, nil
	}

	sharedGroups, err := validateSharedGroupsPayload(username, rawType)
	if err != nil {
		return "", err
	}

	return store.EncodeSharedGroupsType(sharedGroups), nil
}

func normalizeLegacyContactType(contactType string) string {
	trimmed := strings.TrimSpace(contactType)
	lowerContactType := strings.ToLower(trimmed)
	if lowerContactType == "private" || lowerContactType == "public" || lowerContactType == "speeddial" {
		return lowerContactType
	}

	return trimmed
}

func normalizeSharedGroupsPayload(rawValue any) []string {
	stringValue, ok := rawValue.(string)
	if !ok {
		return nil
	}

	trimmed := strings.TrimSpace(stringValue)
	if trimmed == "" {
		return []string{}
	}

	if strings.HasPrefix(trimmed, "[") || strings.HasPrefix(trimmed, "{") {
		var parsed any
		if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
			return nil
		}

		switch typed := parsed.(type) {
		case []any:
			groups := make([]string, 0, len(typed))
			for _, rawGroup := range typed {
				groupName, ok := rawGroup.(string)
				if !ok {
					return nil
				}
				groups = append(groups, groupName)
			}
			return store.NormalizeSharedGroups(groups)
		case map[string]any:
			keys := make([]string, 0, len(typed))
			for key := range typed {
				keys = append(keys, key)
			}
			sort.Strings(keys)

			groups := make([]string, 0, len(keys))
			for _, key := range keys {
				groupName, ok := typed[key].(string)
				if !ok {
					return nil
				}
				groups = append(groups, groupName)
			}
			return store.NormalizeSharedGroups(groups)
		default:
			return nil
		}
	}

	return store.GetSharedGroupsFromType(trimmed)
}

func validateSharedGroupsPayload(username string, rawValue any) ([]string, error) {
	sharedGroups := normalizeSharedGroupsPayload(rawValue)
	if len(sharedGroups) == 0 {
		return nil, errInvalidSharedGroups
	}

	for _, groupName := range sharedGroups {
		if !store.IsValidSharedGroupName(groupName) {
			return nil, errInvalidSharedGroups
		}
	}

	if store.GetPhonebookPermissionLevel(username) >= 2 {
		return sharedGroups, nil
	}

	userGroups, err := getUserGroupNames(username)
	if err != nil {
		return nil, err
	}

	for _, groupName := range sharedGroups {
		if !containsString(userGroups, groupName) {
			return nil, errForbiddenSharedGroups
		}
	}

	return sharedGroups, nil
}

func canReadPrivateContacts(username string) bool {
	permissionLevel := store.GetPhonebookPermissionLevel(username)
	return permissionLevel >= 0
}

func getContactWriteVisibility(contactType string) string {
	if contactType == "private" || contactType == "speeddial" {
		return "private"
	}
	if store.HasGroupTypePrefix(contactType) {
		return "group"
	}

	return "public"
}

func canWriteContactType(username, contactType string) bool {
	permissionLevel := store.GetPhonebookPermissionLevel(username)
	visibility := getContactWriteVisibility(contactType)
	return permissionLevel >= 2 || (permissionLevel >= 1 && visibility == "private")
}

func canWriteExistingContact(username string, contact *store.PhonebookEntry, nextType string) bool {
	if contact == nil {
		return false
	}
	if store.GetPhonebookPermissionLevel(username) >= 2 {
		return true
	}

	targetType := nextType
	if targetType == "" {
		targetType = contact.Type
	}

	return contact.OwnerID == username && canWriteContactType(username, contact.Type) && canWriteContactType(username, targetType)
}

func isGroupContactVisible(contact *store.PhonebookEntry, username string, userGroups []string) bool {
	if contact == nil || contact.OwnerID == username {
		return false
	}

	sharedGroups := store.GetSharedGroupsFromType(contact.Type)
	if len(sharedGroups) == 0 {
		return false
	}

	for _, groupName := range userGroups {
		if containsString(sharedGroups, groupName) {
			return true
		}
	}

	return false
}

func canReadCtiContact(username string, contact *store.PhonebookEntry, userGroups []string) bool {
	if contact == nil {
		return true
	}
	if contact.Type == "public" || isGroupContactVisible(contact, username, userGroups) {
		return true
	}

	return contact.OwnerID == username && canReadPrivateContacts(username)
}

func decodeLegacyPhonebookPayload(c *gin.Context) (map[string]any, error) {
	var payload map[string]any
	if err := c.ShouldBindJSON(&payload); err != nil {
		return nil, err
	}
	if payload == nil {
		return nil, errors.New("empty payload")
	}

	return payload, nil
}

func buildLegacyPhonebookQuery(c *gin.Context, username string, userGroups []string) (store.LegacyPhonebookQuery, error) {
	query := store.LegacyPhonebookQuery{
		Username:               username,
		UserGroups:             userGroups,
		View:                   strings.TrimSpace(c.Query("view")),
		Visibility:             firstNonEmpty(strings.TrimSpace(c.Query("visibility")), strings.TrimSpace(c.Query("sharing"))),
		IncludePrivateContacts: canReadPrivateContacts(username),
	}

	limitRaw := strings.TrimSpace(c.Query("limit"))
	offsetRaw := strings.TrimSpace(c.Query("offset"))
	if limitRaw == "" && offsetRaw == "" {
		return query, nil
	}

	if limitRaw == "" {
		return store.LegacyPhonebookQuery{}, errors.New("invalid limit")
	}

	limit, err := strconv.Atoi(limitRaw)
	if err != nil || limit < 0 {
		return store.LegacyPhonebookQuery{}, errors.New("invalid limit")
	}

	offset := 0
	if offsetRaw != "" {
		offset, err = strconv.Atoi(offsetRaw)
		if err != nil || offset < 0 {
			return store.LegacyPhonebookQuery{}, errors.New("invalid offset")
		}
	}

	query.Limit = limit
	query.Offset = offset
	query.ApplyPagination = true
	return query, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}

	return ""
}

func parseLegacyPhonebookID(rawValue any) (int64, error) {
	switch typedValue := rawValue.(type) {
	case string:
		return strconv.ParseInt(strings.TrimSpace(typedValue), 10, 64)
	case float64:
		return int64(typedValue), nil
	case json.Number:
		return typedValue.Int64()
	default:
		return 0, fmt.Errorf("invalid id type")
	}
}

func extractLegacyPhonebookUpdateFields(payload map[string]any) (map[string]any, error) {
	fields := make(map[string]any)
	for _, fieldName := range legacyPhonebookWritableFields {
		value, present, err := extractNullableLegacyString(payload, fieldName)
		if err != nil {
			return nil, err
		}
		if present {
			fields[fieldName] = value
		}
	}

	return fields, nil
}

func extractNullableLegacyString(payload map[string]any, fieldName string) (any, bool, error) {
	rawValue, present := payload[fieldName]
	if !present {
		return nil, false, nil
	}
	if rawValue == nil {
		return nil, true, nil
	}

	stringValue, ok := rawValue.(string)
	if !ok {
		return nil, false, fmt.Errorf("invalid %s field", fieldName)
	}

	return stringValue, true, nil
}

func assignPhonebookEntryField(entry *store.PhonebookEntry, fieldName, value string) {
	switch fieldName {
	case "name":
		entry.Name = value
	case "homeemail":
		entry.HomeEmail = value
	case "workemail":
		entry.WorkEmail = value
	case "homephone":
		entry.HomePhone = value
	case "workphone":
		entry.WorkPhone = value
	case "cellphone":
		entry.CellPhone = value
	case "fax":
		entry.Fax = value
	case "title":
		entry.Title = value
	case "company":
		entry.Company = value
	case "notes":
		entry.Notes = value
	case "homestreet":
		entry.HomeStreet = value
	case "homepob":
		entry.HomePOB = value
	case "homecity":
		entry.HomeCity = value
	case "homeprovince":
		entry.HomeProvince = value
	case "homepostalcode":
		entry.HomePostalCode = value
	case "homecountry":
		entry.HomeCountry = value
	case "workstreet":
		entry.WorkStreet = value
	case "workpob":
		entry.WorkPOB = value
	case "workcity":
		entry.WorkCity = value
	case "workprovince":
		entry.WorkProvince = value
	case "workpostalcode":
		entry.WorkPostalCode = value
	case "workcountry":
		entry.WorkCountry = value
	case "url":
		entry.URL = value
	case "extension":
		entry.Extension = value
	case "speeddial_num":
		entry.SpeedDialNum = value
	}
}

func legacyPhonebookEntryResponse(entry *store.PhonebookEntry) gin.H {
	if entry == nil {
		return gin.H{}
	}

	return gin.H{
		"id":             entry.ID,
		"owner_id":       entry.OwnerID,
		"type":           entry.Type,
		"homeemail":      entry.HomeEmail,
		"workemail":      entry.WorkEmail,
		"homephone":      entry.HomePhone,
		"workphone":      entry.WorkPhone,
		"cellphone":      entry.CellPhone,
		"fax":            entry.Fax,
		"title":          entry.Title,
		"company":        entry.Company,
		"notes":          entry.Notes,
		"name":           entry.Name,
		"homestreet":     entry.HomeStreet,
		"homepob":        entry.HomePOB,
		"homecity":       entry.HomeCity,
		"homeprovince":   entry.HomeProvince,
		"homepostalcode": entry.HomePostalCode,
		"homecountry":    entry.HomeCountry,
		"workstreet":     entry.WorkStreet,
		"workpob":        entry.WorkPOB,
		"workcity":       entry.WorkCity,
		"workprovince":   entry.WorkProvince,
		"workpostalcode": entry.WorkPostalCode,
		"workcountry":    entry.WorkCountry,
		"url":            entry.URL,
		"extension":      entry.Extension,
		"speeddial_num":  entry.SpeedDialNum,
		"source":         "cti",
	}
}

func writePhonebookValidationError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, errInvalidSharedGroups):
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid shared groups"})
	case errors.Is(err, errForbiddenSharedGroups):
		c.JSON(http.StatusForbidden, gin.H{"message": "forbidden"})
	case errors.Is(err, errLegacySessionUnavailable):
		c.JSON(http.StatusUnauthorized, gin.H{"message": "user session not found"})
	default:
		logs.Log("[ERROR][PHONEBOOK] Group validation failed: " + err.Error())
		c.JSON(http.StatusBadGateway, gin.H{"message": "failed to resolve operator groups"})
	}
}

func writePhonebookGroupLookupError(c *gin.Context, err error) {
	if errors.Is(err, errLegacySessionUnavailable) {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "user session not found"})
		return
	}

	logs.Log("[ERROR][PHONEBOOK] Failed to resolve operator groups: " + err.Error())
	c.JSON(http.StatusBadGateway, gin.H{"message": "failed to resolve operator groups"})
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}

	return false
}