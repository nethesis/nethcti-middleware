package socket

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/methods"
	"github.com/nethesis/nethcti-middleware/mqtt"
	"github.com/nethesis/nethcti-middleware/store"
)

var mqttChannel chan mqtt.WebSocketMessage

// SetMQTTChannel sets the MQTT channel for forwarding messages to WebSocket clients
func SetMQTTChannel(ch chan mqtt.WebSocketMessage) {
	mqttChannel = ch
	// Start global MQTT message handler
	go handleMQTTMessages()
}

// handleMQTTMessages processes MQTT messages and broadcasts them to authorized connections
func handleMQTTMessages() {
	for mqttMsg := range mqttChannel {
		connManager.BroadcastMQTTMessage(mqttMsg.Type, mqttMsg.Data)
	}
}

func WsProxyHandler(c *gin.Context) {
	protocol := "wss"
	if configuration.Config.V1Protocol == "http" {
		protocol = "ws"
	}

	// Upgrade client connection
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	clientConn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		c.String(http.StatusInternalServerError, "WebSocket upgrade failed: %v", err)
		return
	}
	defer clientConn.Close()
	defer connManager.RemoveConnection(clientConn)

	// Connect to backend
	backendURL := url.URL{
		Scheme:   protocol,
		Host:     configuration.Config.V1WsEndpoint,
		Path:     configuration.Config.V1WsPath + "/",
		RawQuery: c.Request.URL.RawQuery,
	}
	backendConn, _, err := websocket.DefaultDialer.Dial(backendURL.String(), nil)
	if err != nil {
		c.String(http.StatusBadGateway, "Failed to connect to backend WebSocket: %v", err)
		return
	}
	defer backendConn.Close()

	errc := make(chan error, 3)

	// Client → Backend
	go func() {
		for {
			msgType, msg, err := clientConn.ReadMessage()
			if err != nil {
				errc <- err
				return
			}

			// Intercept transcription control messages
			if msgType == websocket.TextMessage {
				msgStr := string(msg)

				if strings.HasPrefix(msgStr, "42[\"start_transcription\"") {
					if user, exists := connManager.GetConnection(clientConn); exists {
						if !user.TranscriptionEnabled {
							user.TranscriptionEnabled = true
							logs.Log(fmt.Sprintf("[INFO][WS] Transcription enabled for user %s", user.Username))
						}
					}
					continue // Don't forward to backend
				}

				if strings.HasPrefix(msgStr, "42[\"stop_transcription\"") {
					if user, exists := connManager.GetConnection(clientConn); exists {
						if user.TranscriptionEnabled {
							user.TranscriptionEnabled = false
							logs.Log(fmt.Sprintf("[INFO][WS] Transcription disabled for user %s", user.Username))
						}
					}
					continue // Don't forward to backend
				}
			}

			// Intercept socket.io login message type: 42["login", {...}]
			if msgType == websocket.TextMessage && strings.HasPrefix(string(msg), "42[\"login\"") {
				var payload []interface{}
				if err := json.Unmarshal(msg[2:], &payload); err == nil && len(payload) > 1 {
					// payload[0] should be "login", payload[1] the JSON
					if loginData, ok := payload[1].(map[string]interface{}); ok {
						// Check if accessKeyId exists and is valid
						accessKeyId, ok := loginData["accessKeyId"].(string)
						if ok {
							session, sessionExists := store.UserSessions[accessKeyId]
							apiKeyExists := methods.AuthenticateAPIKey(accessKeyId, loginData["token"].(string))

							if sessionExists {
								// Extract only the token from the string "username:token"
								tokenParts := strings.SplitN(session.NethCTIToken, ":", 2)[1]
								if tokenParts != "" {
									loginData["token"] = tokenParts

									// Get real user info from API
									userInfo, err := methods.GetUserInfo(session.NethCTIToken)
									displayName := session.Username
									phoneNumbers := []string{}

									if err == nil && userInfo != nil {
										displayName = userInfo.DisplayName
										phoneNumbers = userInfo.PhoneNumbers
									} else {
										logs.Log(fmt.Sprintf("[ERROR][WS] Failed to get user info for %s: %v", session.Username, err))
									}

									// Register the connection with user data
									user := &UserConnection{
										Username:             session.Username,
										AccessKeyId:          accessKeyId,
										DisplayName:          displayName,
										PhoneNumbers:         phoneNumbers,
										TranscriptionEnabled: false,
									}
									connManager.AddConnection(clientConn, user)

									// Re-encode the message
									newPayload, _ := json.Marshal([]interface{}{payload[0], loginData})
									msg = append([]byte("42"), newPayload...)
								}
							} else if apiKeyExists {
								// Get the full phone island token (username:token format)
								phoneIslandTokenFull, err := methods.GetPhoneIslandToken(loginData["token"].(string), false)

								if err == nil && phoneIslandTokenFull != "" {
									// Extract username and token
									parts := strings.SplitN(phoneIslandTokenFull, ":", 2)
									username := "api_user"
									phoneIslandToken := phoneIslandTokenFull

									if len(parts) == 2 {
										username = parts[0]
										phoneIslandToken = parts[1]
									} else {
										logs.Log("[WARNING][WS] Could not extract username from phone island token, using api_user")
									}

									loginData["token"] = phoneIslandToken

									// For API key users, try to get user info using the phone island token
									userInfo, err := methods.GetUserInfo(phoneIslandTokenFull)

									displayName := username
									phoneNumbers := []string{}

									if err == nil && userInfo != nil {
										username = userInfo.Username
										displayName = userInfo.DisplayName
										phoneNumbers = userInfo.PhoneNumbers
									} else {
										logs.Log(fmt.Sprintf("[ERROR][WS] Failed to get API key user info: %v", err))
									}

									// Register the connection with API key user data
									user := &UserConnection{
										Username:             username,
										AccessKeyId:          accessKeyId,
										DisplayName:          displayName,
										PhoneNumbers:         phoneNumbers,
										TranscriptionEnabled: false,
									}
									connManager.AddConnection(clientConn, user)

									// Re-encode the message
									newPayload, _ := json.Marshal([]interface{}{payload[0], loginData})
									msg = append([]byte("42"), newPayload...)
								} else {
									logs.Log(fmt.Sprintf("[ERROR][WS] Failed to get phone island token: %v", err))
								}
							}
						}
					}
				}
			}

			err = backendConn.WriteMessage(msgType, msg)
			if err != nil {
				errc <- err
				return
			}
		}
	}()

	// Backend → Client
	go func() {
		for {
			msgType, msg, err := backendConn.ReadMessage()
			if err != nil {
				errc <- err
				return
			}

			err = clientConn.WriteMessage(msgType, msg)
			if err != nil {
				errc <- err
				return
			}
		}
	}()

	<-errc
}
