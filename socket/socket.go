package socket

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/methods"
	"github.com/nethesis/nethcti-middleware/store"
)

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

	errc := make(chan error, 2)

	// Client → Backend
	go func() {
		for {
			msgType, msg, err := clientConn.ReadMessage()
			if err != nil {
				errc <- err
				return
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

									// Re-encode the message
									newPayload, _ := json.Marshal([]interface{}{payload[0], loginData})
									msg = append([]byte("42"), newPayload...)
								}
							} else if apiKeyExists {
								phoneIslandToken, err := methods.GetPhoneIslandToken(loginData["token"].(string), true)
								if err == nil && phoneIslandToken != "" {
									loginData["token"] = phoneIslandToken

									// Re-encode the message
									newPayload, _ := json.Marshal([]interface{}{payload[0], loginData})
									msg = append([]byte("42"), newPayload...)
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
