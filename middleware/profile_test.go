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
)

func TestMain(m *testing.M) {
	logs.Init("authz-tests")
	os.Exit(m.Run())
}

func TestProfileManagerCheckCapabilities(t *testing.T) {
	dir := t.TempDir()
	profilesPath := filepath.Join(dir, "profiles.json")
	usersPath := filepath.Join(dir, "users.json")

	writeSampleProfiles(t, profilesPath)
	writeSampleUsers(t, usersPath)

	mgr, err := NewProfileManager(profilesPath, usersPath)
	if err != nil {
		t.Fatalf("failed to create ProfileManager: %v", err)
	}

	if ok, _ := mgr.CheckCapabilities("giacomo", []string{"phonebook.ad_phonebook"}); !ok {
		t.Fatalf("expected giacomo to have ad_phonebook")
	}

	if ok, missing := mgr.CheckCapabilities("sample", []string{"phonebook.ad_phonebook"}); ok || missing != "phonebook.ad_phonebook" {
		t.Fatalf("sample should be denied ad_phonebook, got ok=%v missing=%s", ok, missing)
	}

	if ok, missing := mgr.CheckCapabilities("unknown", []string{"phonebook.value"}); ok || missing != "user" {
		t.Fatalf("unknown should be denied with user missing, got ok=%v missing=%s", ok, missing)
	}
}

func TestRequireCapabilitiesMiddleware(t *testing.T) {
	dir := t.TempDir()
	profilesPath := filepath.Join(dir, "profiles.json")
	usersPath := filepath.Join(dir, "users.json")

	writeSampleProfiles(t, profilesPath)
	writeSampleUsers(t, usersPath)

	mgr, err := NewProfileManager(profilesPath, usersPath)
	if err != nil {
		t.Fatalf("failed to create ProfileManager: %v", err)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/phonebook/import", nil)
	c.Set("JWT_PAYLOAD", jwt.MapClaims{"id": "giacomo"})

	handler := mgr.RequireCapabilities("phonebook.ad_phonebook")
	handler(c)
	if c.IsAborted() {
		t.Fatalf("giacomo request should pass")
	}

	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	c2.Request, _ = http.NewRequest("GET", "/phonebook/import", nil)
	c2.Set("JWT_PAYLOAD", jwt.MapClaims{"id": "sample"})

	handler(c2)
	if !c2.IsAborted() {
		t.Fatalf("sample request should be aborted")
	}
	if w2.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden, got %d", w2.Code)
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
