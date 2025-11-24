package middleware

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/store"
)

func TestMain(m *testing.M) {
	logs.Init("authz-tests")
	os.Exit(m.Run())
}

func TestRequireCapabilitiesMiddleware(t *testing.T) {
	dir := t.TempDir()
	profilesPath := filepath.Join(dir, "profiles.json")
	usersPath := filepath.Join(dir, "users.json")

	writeSampleProfiles(t, profilesPath)
	writeSampleUsers(t, usersPath)

	// Initialize profiles in store
	if err := store.InitProfiles(profilesPath, usersPath); err != nil {
		t.Fatalf("failed to initialize profiles: %v", err)
	}

	// Test case 1: User with capability should pass
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/phonebook/import", nil)
	c.Set("JWT_PAYLOAD", jwt.MapClaims{
		"id":                     "giacomo",
		"phonebook.ad_phonebook": true,
	})

	handler := RequireCapabilities("phonebook.ad_phonebook")
	handler(c)
	if c.IsAborted() {
		t.Fatalf("giacomo request should pass, but was aborted")
	}

	// Test case 2: User without capability should fail
	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	c2.Request, _ = http.NewRequest("GET", "/phonebook/import", nil)
	c2.Set("JWT_PAYLOAD", jwt.MapClaims{
		"id":                     "sample",
		"phonebook.ad_phonebook": false,
	})

	handler(c2)
	if !c2.IsAborted() {
		t.Fatalf("sample request should be aborted")
	}
	if w2.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden, got %d", w2.Code)
	}

	// Test case 3: User with missing capability should fail
	w3 := httptest.NewRecorder()
	c3, _ := gin.CreateTestContext(w3)
	c3.Request, _ = http.NewRequest("GET", "/phonebook/import", nil)
	c3.Set("JWT_PAYLOAD", jwt.MapClaims{
		"id": "unknown",
	})

	handler(c3)
	if !c3.IsAborted() {
		t.Fatalf("unknown user request should be aborted")
	}
	if w3.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden, got %d", w3.Code)
	}
}

func TestRequireCapabilitiesMultiple(t *testing.T) {
	// Test requiring multiple capabilities
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/api/endpoint", nil)
	c.Set("JWT_PAYLOAD", jwt.MapClaims{
		"id":                     "testuser",
		"phonebook.ad_phonebook": true,
		"phonebook.value":        true,
	})

	handler := RequireCapabilities("phonebook.ad_phonebook", "phonebook.value")
	handler(c)
	if c.IsAborted() {
		t.Fatalf("request with both capabilities should pass")
	}

	// Test failing when one capability is missing
	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	c2.Request, _ = http.NewRequest("GET", "/api/endpoint", nil)
	c2.Set("JWT_PAYLOAD", jwt.MapClaims{
		"id":                     "testuser",
		"phonebook.ad_phonebook": true,
		"phonebook.value":        false,
	})

	handler(c2)
	if !c2.IsAborted() {
		t.Fatalf("request with one false capability should be aborted")
	}
}

func writeSampleProfiles(t *testing.T, path string) {
	t.Helper()
	content := `{
        "1": {
            "id": "1",
            "name": "advanced",
            "macro_permissions": {
                "phonebook": {
                    "value": true,
                    "permissions": [
                        {"id": "12", "name": "ad_phonebook", "value": true}
                    ]
                }
            }
        },
        "2": {
            "id": "2",
            "name": "standard",
            "macro_permissions": {
                "phonebook": {
                    "value": true,
                    "permissions": [
                        {"id": "12", "name": "ad_phonebook", "value": false}
                    ]
                }
            }
        }
    }`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write profiles: %v", err)
	}
}

func writeSampleUsers(t *testing.T, path string) {
	t.Helper()
	content := `{
        "giacomo": {"profile_id": "1"},
        "sample": {"profile_id": "2"}
    }`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write users: %v", err)
	}
}
