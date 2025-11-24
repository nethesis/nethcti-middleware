/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package socket

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/mqtt"
)

// UserConnection represents a WebSocket connection with user data
type UserConnection struct {
	Conn                 *websocket.Conn
	Username             string
	DisplayName          string
	PhoneNumbers         []string
	AccessKeyId          string
	TranscriptionEnabled bool
}

// ConnectionManager manages all active WebSocket connections
type ConnectionManager struct {
	connections map[*websocket.Conn]*UserConnection
	mutex       sync.RWMutex
}

var connManager = &ConnectionManager{
	connections: make(map[*websocket.Conn]*UserConnection),
}

// GetConnectionManager returns the global connection manager instance
func GetConnectionManager() *ConnectionManager {
	return connManager
}

// AddConnection adds a new connection to the manager
func (cm *ConnectionManager) AddConnection(conn *websocket.Conn, user *UserConnection) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	user.Conn = conn
	cm.connections[conn] = user
}

// RemoveConnection removes a connection from the manager
func (cm *ConnectionManager) RemoveConnection(conn *websocket.Conn) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	delete(cm.connections, conn)
}

// GetConnection gets connection data for a specific connection
func (cm *ConnectionManager) GetConnection(conn *websocket.Conn) (*UserConnection, bool) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	user, exists := cm.connections[conn]
	return user, exists
}

// GetAllConnections returns all active connections
func (cm *ConnectionManager) GetAllConnections() map[*websocket.Conn]*UserConnection {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	result := make(map[*websocket.Conn]*UserConnection)
	for conn, user := range cm.connections {
		result[conn] = user
	}
	return result
}

// IsAuthorizedForTranscription checks if a user is authorized to receive a transcription
func (cm *ConnectionManager) IsAuthorizedForTranscription(conn *websocket.Conn, speakerName, speakerNumber, counterpartName, counterpartNumber string) bool {
	user, exists := cm.GetConnection(conn)
	if !exists {
		return false
	}

	// Check if the user matches the speaker
	if user.DisplayName == speakerName {
		return true
	}

	for _, number := range user.PhoneNumbers {
		if number == speakerNumber {
			return true
		}
	}

	// Check if the user matches the counterpart
	if user.DisplayName == counterpartName {
		return true
	}

	for _, number := range user.PhoneNumbers {
		if number == counterpartNumber {
			return true
		}
	}

	return false
}

// BroadcastMQTTMessage sends an MQTT message to all authorized connections
func (cm *ConnectionManager) BroadcastMQTTMessage(messageType string, data interface{}) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	for conn, user := range cm.connections {
		// Check authorization for transcription messages
		if messageType == "satellite/transcription" {
			// Skip if transcription is not enabled for this user
			if !user.TranscriptionEnabled {
				continue
			}

			// Try to parse as different types
			if transcriptionMsg, ok := data.(mqtt.TranscriptionMessage); ok {
				speakerName := transcriptionMsg.SpeakerName
				speakerNumber := transcriptionMsg.SpeakerNumber
				counterpartName := transcriptionMsg.SpeakerCounterpartName
				counterpartNumber := transcriptionMsg.SpeakerCounterpartNumber

				// Apply authorization - check if user is involved in the conversation
				if speakerName != "" || speakerNumber != "" || counterpartName != "" || counterpartNumber != "" {
					// Skip if user is not authorized for this transcription
					if !cm.IsAuthorizedForTranscription(conn, speakerName, speakerNumber, counterpartName, counterpartNumber) {
						continue
					}
				}
			} else if transcriptionData, ok := data.(map[string]interface{}); ok {
				speakerName, speakerNameOk := transcriptionData["speaker_name"].(string)
				speakerNumber, speakerNumberOk := transcriptionData["speaker_number"].(string)
				counterpartName, counterpartNameOk := transcriptionData["speaker_counterpart_name"].(string)
				counterpartNumber, counterpartNumberOk := transcriptionData["speaker_counterpart_number"].(string)

				// Only apply authorization if we have conversation info
				if speakerNameOk || speakerNumberOk || counterpartNameOk || counterpartNumberOk {
					// Skip if user is not authorized for this transcription
					if !cm.IsAuthorizedForTranscription(conn, speakerName, speakerNumber, counterpartName, counterpartNumber) {
						continue
					}
				}
			} else if jsonData, ok := data.(string); ok {
				// Try to parse JSON string
				var transcriptionData map[string]interface{}
				if err := json.Unmarshal([]byte(jsonData), &transcriptionData); err == nil {
					speakerName, speakerNameOk := transcriptionData["speaker_name"].(string)
					speakerNumber, speakerNumberOk := transcriptionData["speaker_number"].(string)
					counterpartName, counterpartNameOk := transcriptionData["speaker_counterpart_name"].(string)
					counterpartNumber, counterpartNumberOk := transcriptionData["speaker_counterpart_number"].(string)

					// Only apply authorization if we have conversation info
					if speakerNameOk || speakerNumberOk || counterpartNameOk || counterpartNumberOk {
						// Skip if user is not authorized for this transcription
						if !cm.IsAuthorizedForTranscription(conn, speakerName, speakerNumber, counterpartName, counterpartNumber) {
							continue
						}
					}
				} else {
					logs.Log(fmt.Sprintf("[ERROR][BROADCAST] Failed to parse JSON string: %v", err))
				}
			}
		}

		// Send message to this connection
		go func(conn *websocket.Conn, user *UserConnection) {
			// Convert to socket.io format: 42["transcription", {...}]
			socketIOPayload, err := json.Marshal([]interface{}{messageType, data})
			if err != nil {
				logs.Log(fmt.Sprintf("[ERROR][BROADCAST] Failed to marshal message: %v", err))
				return
			}

			finalMsg := append([]byte("42"), socketIOPayload...)

			// Send message (ignore errors, connection will be cleaned up elsewhere)
			conn.WriteMessage(websocket.TextMessage, finalMsg)
		}(conn, user)
	}
}

// BroadcastToUser sends a WebSocket message to all connections for a specific user
func (cm *ConnectionManager) BroadcastToUser(username string, messageType string, data interface{}) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	for conn, user := range cm.connections {
		// Only send to connections of the specified user
		if user.Username != username {
			continue
		}

		// Send message to this connection
		go func(conn *websocket.Conn, user *UserConnection) {
			// Convert to socket.io format: 42["messageType", {...}]
			socketIOPayload, err := json.Marshal([]interface{}{messageType, data})
			if err != nil {
				logs.Log(fmt.Sprintf("[ERROR][BROADCAST] Failed to marshal message for user %s: %v", username, err))
				return
			}

			finalMsg := append([]byte("42"), socketIOPayload...)

			// Send message (ignore errors, connection will be cleaned up elsewhere)
			if err := conn.WriteMessage(websocket.TextMessage, finalMsg); err != nil {
				logs.Log(fmt.Sprintf("[WARN][BROADCAST] Failed to send message to user %s: %v", username, err))
			}
		}(conn, user)
	}
}

// BroadcastGlobal sends a WebSocket message to all connected clients without authorization checks
func (cm *ConnectionManager) BroadcastGlobal(messageType string, data interface{}) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	for conn, user := range cm.connections {
		// Send message to this connection
		go func(conn *websocket.Conn, user *UserConnection) {
			// Convert to socket.io format: 42["messageType", {...}]
			socketIOPayload, err := json.Marshal([]interface{}{messageType, data})
			if err != nil {
				logs.Log(fmt.Sprintf("[ERROR][BROADCAST] Failed to marshal message: %v", err))
				return
			}

			finalMsg := append([]byte("42"), socketIOPayload...)

			// Send message (ignore errors, connection will be cleaned up elsewhere)
			if err := conn.WriteMessage(websocket.TextMessage, finalMsg); err != nil {
				logs.Log(fmt.Sprintf("[WARN][BROADCAST] Failed to send global message: %v", err))
			}
		}(conn, user)
	}
}
