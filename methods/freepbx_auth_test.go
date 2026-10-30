/*
 * Copyright (C) 2026 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/nethesis/nethcti-middleware/configuration"
)

func TestSupportUsernameRegex(t *testing.T) {
	valid := []string{"support-neth-2239-7d37", "support-abcdefgh", "support-1"}
	invalid := []string{
		"support-", "admin", "Support-abc", "support-ABC", "support-a b",
		"support-a'--", "support-a\nb", "xsupport-abc", "support-a_b",
		"support-" + string(make([]byte, 65)),
	}
	for _, u := range valid {
		if !supportUsernameRe.MatchString(u) {
			t.Errorf("expected %q to be valid", u)
		}
	}
	for _, u := range invalid {
		if supportUsernameRe.MatchString(u) {
			t.Errorf("expected %q to be invalid", u)
		}
	}
}

func TestSecretKeyMatches(t *testing.T) {
	key := computeFreePBXSecretKey("support-a", "hash", "secret")
	if !secretKeyMatches(key, key) {
		t.Error("expected matching key to pass")
	}
	if secretKeyMatches(computeFreePBXSecretKey("support-a", "hash", "other"), key) {
		t.Error("expected different key to fail")
	}
	if secretKeyMatches("", "") {
		t.Error("expected empty expected key to fail")
	}
}

func newSupportContext(user, secretKey, ip string) *gin.Context {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/freepbx/extensions", nil)
	c.Request.RemoteAddr = ip + ":1234"
	c.Request.Header.Set("User", user)
	c.Request.Header.Set("Secretkey", secretKey)
	return c
}

func TestRewriteSupportToAdmin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	origSecret := configuration.Config.NethVoiceSecretKey
	origSupport, origAdmin := lookupSupportUserSHA1, lookupAdminSHA1
	defer func() {
		configuration.Config.NethVoiceSecretKey = origSecret
		lookupSupportUserSHA1, lookupAdminSHA1 = origSupport, origAdmin
	}()

	configuration.Config.NethVoiceSecretKey = "secret"
	lookups := 0
	lookupSupportUserSHA1 = func(u string) (string, error) {
		lookups++
		if u == "support-neth-1-2" {
			return "supporthash", nil
		}
		return "", errUserNotFound
	}
	lookupAdminSHA1 = func() (string, error) { return "adminhash", nil }

	good := computeFreePBXSecretKey("support-neth-1-2", "supporthash", "secret")

	c := newSupportContext("support-neth-1-2", good, "192.0.2.1")
	if !RewriteSupportToAdmin(c) {
		t.Fatal("expected valid support user to be rewritten")
	}
	if c.Request.Header.Get("User") != "admin" ||
		c.Request.Header.Get("Secretkey") != computeFreePBXSecretKey("admin", "adminhash", "secret") {
		t.Error("expected admin credentials after rewrite")
	}

	lookups = 0
	if RewriteSupportToAdmin(newSupportContext("support-x' OR 1=1 --", good, "192.0.2.2")) {
		t.Error("expected malformed username to fail")
	}
	if lookups != 0 {
		t.Error("expected no DB lookup for malformed username")
	}

	if RewriteSupportToAdmin(newSupportContext("support-neth-1-2", "bad", "192.0.2.3")) {
		t.Error("expected wrong Secretkey to fail")
	}

	configuration.Config.NethVoiceSecretKey = ""
	if RewriteSupportToAdmin(newSupportContext("support-neth-1-2", good, "192.0.2.4")) {
		t.Error("expected failure without NETHVOICESECRETKEY")
	}
}

func TestSupportAuthThrottled(t *testing.T) {
	ip := "198.51.100.7"
	defer clearSupportFailures(ip)

	for i := 0; i < supportMaxFailures; i++ {
		if SupportAuthThrottled(ip) {
			t.Fatalf("throttled too early after %d failures", i)
		}
		recordSupportFailure(ip)
	}
	if !SupportAuthThrottled(ip) {
		t.Error("expected ip to be throttled")
	}
	if SupportAuthThrottled("198.51.100.8") {
		t.Error("expected other ip not to be throttled")
	}

	supportFailuresMu.Lock()
	supportFailures[ip].first = supportFailures[ip].first.Add(-supportFailureWindow - 1)
	supportFailuresMu.Unlock()
	if SupportAuthThrottled(ip) {
		t.Error("expected throttling to expire after the window")
	}
}
