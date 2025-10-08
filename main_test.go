/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/nethesis/nethcti-middleware/models"
	"github.com/nethesis/nethcti-middleware/store"
	"github.com/nethesis/nethcti-middleware/utils"
	"github.com/gorilla/websocket"
	"github.com/pion/rtp"
	"crypto/rand"
	"strconv"
	"sync"
	"flag"
)

// Global variables for test server URLs and mock server
var testServerURL string
var mockNetCTI *httptest.Server
var jb         *bool

// TestMain sets up the test environment once for all tests
func TestMain(m *testing.M) {
	jb = flag.Bool("jb", false, "jitter buffer test")
	flag.Parse()
	// Setup test environment and dependencies
	setupTestEnvironment()

	// Run all tests
	code := m.Run()

	// Cleanup after all tests
	cleanupTestEnvironment()

	// Exit with the same code as the tests
	os.Exit(code)
}

// Global test setup - starts actual main server once
func setupTestEnvironment() {
	gin.SetMode(gin.TestMode)

	// Start mock NetCTI server first
	mockNetCTI = mockNetCTIServer()
	mockURL := strings.TrimPrefix(mockNetCTI.URL, "http://")

	// Set environment variables for the middleware
	os.Setenv("NETHVOICE_MIDDLEWARE_LISTEN_ADDRESS", "127.0.0.1:8899")
	os.Setenv("NETHVOICE_MIDDLEWARE_V1_PROTOCOL", "http")
	os.Setenv("NETHVOICE_MIDDLEWARE_V1_API_ENDPOINT", mockURL)
	os.Setenv("NETHVOICE_MIDDLEWARE_V1_WS_ENDPOINT", mockURL)
	os.Setenv("NETHVOICE_MIDDLEWARE_V1_API_PATH", "/webrest")
	os.Setenv("NETHVOICE_MIDDLEWARE_V1_WS_PATH", "/socket.io")
	os.Setenv("NETHVOICE_MIDDLEWARE_SECRET_JWT", "test-secret-key-for-jwt-tokens")
	os.Setenv("NETHVOICE_MIDDLEWARE_SECRETS_DIR", "/tmp/test-secrets/nethcti")
	os.Setenv("NETHVOICE_MIDDLEWARE_ISSUER_2FA", "NetCTI-Test")
	os.Setenv("NETHVOICE_MIDDLEWARE_SENSITIVE_LIST", "password,secret")
	os.Setenv("RTP_PROXY_ADDR", "127.0.0.1")
	os.Setenv("RTP_PROXY_PORT", "5004")
	
	if *jb {
		os.Setenv("JITTER_BUFFER", "on")
		os.Setenv("PLAYBACK_RATE", "1500")
	}

	// Create test secrets directory
	os.MkdirAll(os.Getenv("NETHVOICE_MIDDLEWARE_SECRETS_DIR"), 0700)

	// Start the actual main server in a goroutine
	go func() {
		main()
	}()

	// Set test server URL
	testServerURL = "http://127.0.0.1:8899"

	// Give server time to fully start
	time.Sleep(2 * time.Second)
}

// Mock NetCTI server for testing
func mockNetCTIServer() *httptest.Server {
	// This mock server simulates the NetCTI backend for authentication and user info
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/webrest/authentication/login":
			var loginData map[string]string
			json.NewDecoder(r.Body).Decode(&loginData)

			// Simulate Digest authentication challenge for correct credentials
			if loginData["username"] == "testuser" && loginData["password"] == "testpass" {
				w.Header().Set("Www-Authenticate", `Digest realm="test", nonce="test123", qop="auth"`)
				w.WriteHeader(http.StatusUnauthorized)
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		case "/webrest/user/me":
			auth := r.Header.Get("Authorization")
			if strings.Contains(auth, "testuser") {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"username": "testuser"}`))
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		}
	}))
}

// Global cleanup test data
func cleanupTestEnvironment() {
	if mockNetCTI != nil {
		mockNetCTI.Close()
	}
	os.RemoveAll(os.Getenv("NETHVOICE_MIDDLEWARE_SECRETS_DIR"))

	// Clear environment variables
	os.Unsetenv("NETHVOICE_MIDDLEWARE_LISTEN_ADDRESS")
	os.Unsetenv("NETHVOICE_MIDDLEWARE_V1_PROTOCOL")
	os.Unsetenv("NETHVOICE_MIDDLEWARE_V1_API_ENDPOINT")
	os.Unsetenv("NETHVOICE_MIDDLEWARE_V1_API_PATH")
	os.Unsetenv("NETHVOICE_MIDDLEWARE_V1_WS_PATH")
	os.Unsetenv("NETHVOICE_MIDDLEWARE_SECRET_JWT")
	os.Unsetenv("NETHVOICE_MIDDLEWARE_SECRETS_DIR")
	os.Unsetenv("NETHVOICE_MIDDLEWARE_ISSUER_2FA")
	os.Unsetenv("NETHVOICE_MIDDLEWARE_SENSITIVE_LIST")
}

// Helper function to reset test state between tests
func resetTestState() {
	// Clear user sessions and test files to ensure isolation between tests
	store.UserSessions = make(map[string]*models.UserSession)

	// Clean up any test files
	os.RemoveAll(os.Getenv("NETHVOICE_MIDDLEWARE_SECRETS_DIR"))
	os.MkdirAll(os.Getenv("NETHVOICE_MIDDLEWARE_SECRETS_DIR"), 0700)
}

// Test login endpoint
func TestLogin(t *testing.T) {
	resetTestState()

	loginData := map[string]string{
		"username": "testuser",
		"password": "testpass",
	}
	jsonData, _ := json.Marshal(loginData)

	resp, err := http.Post(testServerURL+"/login", "application/json", bytes.NewBuffer(jsonData))
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	assert.Equal(t, float64(200), response["code"])
	assert.NotEmpty(t, response["token"])
}

// Test logout endpoint
func TestLogout(t *testing.T) {
	resetTestState()

	token := utils.PerformLogin(testServerURL)

	client := &http.Client{}
	req, _ := http.NewRequest("POST", testServerURL+"/logout", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// Test 2FA QR code generation
func TestQRCode(t *testing.T) {
	resetTestState()

	token := utils.PerformLogin(testServerURL)

	client := &http.Client{}
	req, _ := http.NewRequest("GET", testServerURL+"/2fa/qr-code", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)

	data := response["data"].(map[string]interface{})
	assert.NotEmpty(t, data["url"])
	assert.NotEmpty(t, data["key"])
}

// Test 2FA status check
func Test2FAStatus(t *testing.T) {
	resetTestState()

	token := utils.PerformLogin(testServerURL)

	client := &http.Client{}
	req, _ := http.NewRequest("GET", testServerURL+"/2fa/status", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	assert.False(t, response["status"].(bool))
}

// Test OTP verification
func TestOTPVerify(t *testing.T) {
	resetTestState()

	token := utils.PerformLogin(testServerURL)
	otpSecret := utils.Setup2FA(testServerURL, token, t)
	otp := utils.GenerateOTP(otpSecret)

	otpData := map[string]string{
		"username": "testuser",
		"otp":      otp,
	}
	jsonData, _ := json.Marshal(otpData)

	client := &http.Client{}
	req, _ := http.NewRequest("POST", testServerURL+"/2fa/verify-otp", bytes.NewBuffer(jsonData))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// Test recovery codes generation
func TestRecoveryCodes(t *testing.T) {
	resetTestState()

	token := utils.PerformLogin(testServerURL)
	otpSecret := utils.Setup2FA(testServerURL, token, t)
	otp := utils.GenerateOTP(otpSecret)
	token = utils.Verify2FA(testServerURL, otp, token, t)

	recoveryCodes := map[string]string{
		"password": "testpass",
	}
	jsonData, _ := json.Marshal(recoveryCodes)

	client := &http.Client{}
	req, _ := http.NewRequest("POST", testServerURL+"/2fa/recovery-codes", bytes.NewBuffer(jsonData))
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)

	codes := response["codes"].([]interface{})
	assert.Greater(t, len(codes), 0)
}

// Test 2FA disable
func TestDisable2FA(t *testing.T) {
	resetTestState()

	token := utils.PerformLogin(testServerURL)
	otpSecret := utils.Setup2FA(testServerURL, token, t)
	otp := utils.GenerateOTP(otpSecret)
	token = utils.Verify2FA(testServerURL, otp, token, t)

	disableData := map[string]string{
		"password": "testpass",
	}
	jsonData, _ := json.Marshal(disableData)

	client := &http.Client{}
	req, _ := http.NewRequest("POST", testServerURL+"/2fa/disable", bytes.NewBuffer(jsonData))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

var (
	syncPubSub       chan struct{}
	syncReaderWriter chan struct{}
)

func publisherBehaviour(
	t *testing.T, 
	localAddr *string, 
	udpServerAddr string,
) {
	udpConn, err := net.Dial("udp", udpServerAddr)
	if err != nil {
		t.Fatalf("Failed to dial udp listener")
		t.Fail()
	}
	defer udpConn.Close()

	*localAddr = udpConn.LocalAddr().String()
	pubMsg := map[string]string{
		"nome_citofono": *localAddr,
	}
		
	data, marshalErr := json.Marshal(pubMsg)
	if marshalErr != nil {
		t.Fatalf("Failed to marshal json message")
		t.Fail()
	}
	_, writeErr := udpConn.Write(data)
	if writeErr != nil {
		t.Fatalf("Failed to send join message: %v", err)
		t.Fail()
	}
	t.Logf("Pub Message Sent")

	syncPubSub <- struct{}{}
	<- syncReaderWriter
	var (
		seqNum uint16    = 0
		timestamp int64  = 0
		payload          = make([]byte, 200)
	)

	for i := 0; i < 100; i++ {
		_, err := rand.Read(payload)
		if err != nil {
			t.Fatalf("Failed to create an RTP Packet")
			t.Fail()
		}

		packet := &rtp.Packet{
			Header: rtp.Header{
				Version:        2,
				PayloadType:    96,
				SequenceNumber: seqNum,
				Timestamp:      0,
				SSRC:           0xdeadbeef,
			},
			Payload: append([]byte(nil), payload...),
		}

		raw, err := packet.Marshal()
		if err != nil {
			t.Fatalf("Failed to marshal the packet")
			t.Fail()
		}
		_, errUdp := udpConn.Write(raw)
		if errUdp != nil {
			t.Fatalf("error: %v", errUdp)
			t.Fail()
		}

		seqNum += 1
		timestamp += 1800
		time.Sleep(20 * time.Millisecond)
	}
}

func subscriberBehaviour(
	t *testing.T, 
	localAddr *string,
) {

	<- syncPubSub
	c, _, err := websocket.DefaultDialer.Dial("ws://localhost:8899/rtp-stream", nil)
	if err != nil {
		t.Fatalf("dial error: %v", err)
		t.Fail()
	}
	defer c.Close()

	subMsg := map[string]string{
		"publisher": *localAddr,
	}

	if err := c.WriteJSON(subMsg); err != nil {
		t.Fatalf("subscribe error: %v", err)
		t.Fail()
	}

	t.Logf("Sub Message Sent")

	outFile, err := os.OpenFile("test_result.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("Cannot create temp file: %v", err)
		t.Fail()
	}

	var (
		expectedRTPPackets = 100
		packetCounter = 0
		header rtp.Header
	)

	syncReaderWriter <- struct{}{}
	for {
		if packetCounter >= expectedRTPPackets {
			break
		}

		s := time.Now()
		msgType, data, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("read error: %v", err)
			t.Fail()
		}
		e := time.Now()
		elapsed := e.Sub(s)

		if *jb {
			if elapsed < 20 {
				t.Errorf("The jitter buffer is not working")
				t.Fail()
			}
		}

		if msgType == websocket.BinaryMessage {
			header.Unmarshal(data)
			sn := strconv.Itoa(int(header.SequenceNumber))	
			if _, err := outFile.WriteString(sn + "\n"); err != nil {
				t.Fatalf("occured some errors when writing to file, %v", err)
				t.Fail()
			}
			t.Logf("Received RTP Packet")
			packetCounter++
		} else {
			var textData = string(data)
			if textData == "Unable to find the given publisher" {
				t.Fatalf("Publisher Not Found")
				t.Fail()
			}
		}
	}

	if packetCounter < expectedRTPPackets {
		t.Errorf("Some RTP packets are not arrived!")
		t.Fail()
	}
}

// for testing the jitter buffer write 
// go test -v -jb=true
func TestRTPProxy(t *testing.T) {
	resetTestState()
	var (
		udpServerAddr    = "127.0.0.1:5004"
		localAddr string 
		wg = &sync.WaitGroup{}
	)

	syncPubSub =       make(chan struct{}, 1)
	syncReaderWriter = make(chan struct{}, 1)

	wg.Add(1)
	go func(t *testing.T, wg *sync.WaitGroup) {
		defer wg.Done()
		publisherBehaviour(t, &localAddr, udpServerAddr)
	}(t, wg)

	wg.Add(1)
	go func(t *testing.T, wg *sync.WaitGroup) {
		defer wg.Done()
		subscriberBehaviour(t, &localAddr)
	}(t, wg)

	wg.Wait()
	close(syncPubSub)
	close(syncReaderWriter)
}