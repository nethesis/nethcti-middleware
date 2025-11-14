package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"github.com/nethesis/nethcti-middleware/logs"
)

// ProfileManager handles profile/user permissions and exposes Gin middleware.
type ProfileManager struct {
	profilesPath string
	usersPath    string
	profiles     map[string]*Profile
	users        map[string]*User
}

// Profile represents a parsed profile with capability map.
type Profile struct {
	ID           string
	Name         string
	Capabilities map[string]bool
}

// User links a username to a profile ID.
type User struct {
	Username  string
	ProfileID string
}

// NewProfileManager creates and initializes a ProfileManager by loading profiles and users from files.
func NewProfileManager(profilesPath, usersPath string) (*ProfileManager, error) {
	profAbs, err := filepath.Abs(profilesPath)
	if err != nil {
		return nil, fmt.Errorf("profiles path: %w", err)
	}

	usersAbs, err := filepath.Abs(usersPath)
	if err != nil {
		return nil, fmt.Errorf("users path: %w", err)
	}

	m := &ProfileManager{
		profilesPath: profAbs,
		usersPath:    usersAbs,
		profiles:     make(map[string]*Profile),
		users:        make(map[string]*User),
	}

	if err := m.loadAll(); err != nil {
		return nil, err
	}

	return m, nil
}

// RequireCapabilities returns a middleware that enforces capability checks.
func (m *ProfileManager) RequireCapabilities(capabilities ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(capabilities) == 0 {
			c.Next()
			return
		}

		claims := jwt.ExtractClaims(c)
		username, _ := claims["id"].(string)
		if username == "" {
			logs.Log(fmt.Sprintf("[AUTHZ][WARN] missing identity on %s %s", c.Request.Method, c.Request.RequestURI))
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": http.StatusForbidden, "message": "authorization failed"})
			return
		}

		ok, missing := m.CheckCapabilities(username, capabilities)
		if !ok {
			logs.Log(fmt.Sprintf("[AUTHZ][DENIED] %s missing capability %s", username, missing))
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": http.StatusForbidden, "message": "missing capability"})
			return
		}

		c.Next()
	}
}

// CheckCapabilities verifies that the specified user has every capability.
func (m *ProfileManager) CheckCapabilities(username string, required []string) (bool, string) {
	user, ok := m.users[username]
	if !ok {
		return false, "user"
	}

	profile, ok := m.profiles[user.ProfileID]
	if !ok {
		return false, "profile"
	}

	for _, capability := range required {
		if !profile.Capabilities[capability] {
			return false, capability
		}
	}

	return true, ""
}

func (m *ProfileManager) loadAll() error {
	if err := m.reloadProfiles(); err != nil {
		return err
	}

	if err := m.reloadUsers(); err != nil {
		return err
	}

	return nil
}

func (m *ProfileManager) reloadProfiles() error {
	data, err := os.ReadFile(m.profilesPath)
	if err != nil {
		return fmt.Errorf("read profiles: %w", err)
	}

	raw := make(map[string]*rawProfile)
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parse profiles: %w", err)
	}

	profiles := make(map[string]*Profile)
	for key, rp := range raw {
		profID := rp.ID
		if profID == "" {
			profID = key
		}

		if profID == "" {
			continue
		}

		capMap := make(map[string]bool)
		for macroName, macro := range rp.MacroPermissions {
			capMap[macroName+".value"] = macro.Value
			for _, permission := range macro.Permissions {
				key := fmt.Sprintf("%s.%s", macroName, permission.Name)
				capMap[key] = permission.Value
			}
		}

		profiles[profID] = &Profile{
			ID:           profID,
			Name:         rp.Name,
			Capabilities: capMap,
		}
	}

	m.profiles = profiles
	logs.Log(fmt.Sprintf("[AUTHZ] loaded %d profiles", len(profiles)))
	return nil
}

func (m *ProfileManager) reloadUsers() error {
	data, err := os.ReadFile(m.usersPath)
	if err != nil {
		return fmt.Errorf("read users: %w", err)
	}

	raw := make(map[string]*rawUser)
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parse users: %w", err)
	}

	users := make(map[string]*User)
	for username, ru := range raw {
		if ru.ProfileID == "" {
			return fmt.Errorf("user %s missing profile reference", username)
		}

		if _, ok := m.profiles[ru.ProfileID]; !ok {
			return fmt.Errorf("user %s references unknown profile %s", username, ru.ProfileID)
		}

		users[username] = &User{
			Username:  username,
			ProfileID: ru.ProfileID,
		}
	}

	m.users = users
	logs.Log(fmt.Sprintf("[AUTHZ] loaded %d users", len(users)))
	return nil
}

type rawProfile struct {
	ID               string                         `json:"id"`
	Name             string                         `json:"name"`
	MacroPermissions map[string]*rawMacroPermission `json:"macro_permissions"`
}

type rawMacroPermission struct {
	Value       bool             `json:"value"`
	Permissions []*rawPermission `json:"permissions"`
}

type rawPermission struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Value bool   `json:"value"`
}

type rawUser struct {
	ProfileID string `json:"profile_id"`
}

// NewManager is a compatibility alias for NewProfileManager.
func NewManager(profilesPath, usersPath string) (*ProfileManager, error) {
	return NewProfileManager(profilesPath, usersPath)
}

// Manager is a compatibility alias for ProfileManager.
type Manager = ProfileManager
