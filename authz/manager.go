package authz

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/fsnotify/fsnotify"
	"github.com/gin-gonic/gin"
	"github.com/nethesis/nethcti-middleware/logs"
)

// Manager handles profile/user permissions and exposes Gin middleware.
type Manager struct {
	profilesPath string
	usersPath    string

	mu       sync.RWMutex
	profiles map[string]*Profile
	users    map[string]*User

	watcherProfiles *fsnotify.Watcher
	watcherUsers    *fsnotify.Watcher
	cancel          context.CancelFunc
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

// NewManager creates an authorization manager and starts file watchers.
func NewManager(ctx context.Context, profilesPath, usersPath string) (*Manager, error) {
	profAbs, err := filepath.Abs(profilesPath)
	if err != nil {
		return nil, fmt.Errorf("profiles path: %w", err)
	}

	usersAbs, err := filepath.Abs(usersPath)
	if err != nil {
		return nil, fmt.Errorf("users path: %w", err)
	}

	m := &Manager{
		profilesPath: profAbs,
		usersPath:    usersAbs,
		profiles:     make(map[string]*Profile),
		users:        make(map[string]*User),
	}

	if err := m.loadAll(); err != nil {
		return nil, err
	}

	if err := m.startWatchers(ctx); err != nil {
		m.Close()
		return nil, err
	}

	return m, nil
}

// Close stops file watchers and releases resources.
func (m *Manager) Close() {
	if m.cancel != nil {
		m.cancel()
	}

	if m.watcherProfiles != nil {
		m.watcherProfiles.Close()
	}

	if m.watcherUsers != nil {
		m.watcherUsers.Close()
	}
}

// IsLoaded returns true if profiles and users are already loaded.
func (m *Manager) IsLoaded() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.profiles) > 0 && len(m.users) > 0
}

// RequireCapabilities returns a middleware that enforces capability checks.
func (m *Manager) RequireCapabilities(capabilities ...string) gin.HandlerFunc {
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
func (m *Manager) CheckCapabilities(username string, required []string) (bool, string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

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

func (m *Manager) loadAll() error {
	if err := m.reloadProfiles(); err != nil {
		return err
	}

	if err := m.reloadUsers(); err != nil {
		return err
	}

	return nil
}

func (m *Manager) reloadProfiles() error {
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

	m.mu.Lock()
	m.profiles = profiles
	m.mu.Unlock()

	logs.Log(fmt.Sprintf("[AUTHZ] loaded %d profiles", len(profiles)))
	return nil
}

func (m *Manager) reloadUsers() error {
	data, err := os.ReadFile(m.usersPath)
	if err != nil {
		return fmt.Errorf("read users: %w", err)
	}

	raw := make(map[string]*rawUser)
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parse users: %w", err)
	}

	m.mu.RLock()
	profilesSnapshot := make(map[string]*Profile, len(m.profiles))
	for k, v := range m.profiles {
		profilesSnapshot[k] = v
	}
	m.mu.RUnlock()

	users := make(map[string]*User)
	for username, ru := range raw {
		if ru.ProfileID == "" {
			return fmt.Errorf("user %s missing profile reference", username)
		}

		if _, ok := profilesSnapshot[ru.ProfileID]; !ok {
			return fmt.Errorf("user %s references unknown profile %s", username, ru.ProfileID)
		}

		users[username] = &User{
			Username:  username,
			ProfileID: ru.ProfileID,
		}
	}

	m.mu.Lock()
	m.users = users
	m.mu.Unlock()

	logs.Log(fmt.Sprintf("[AUTHZ] loaded %d users", len(users)))
	return nil
}

func (m *Manager) startWatchers(parent context.Context) error {
	ctx, cancel := context.WithCancel(parent)
	m.cancel = cancel

	profWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	if err := profWatcher.Add(m.profilesPath); err != nil {
		profWatcher.Close()
		cancel()
		return fmt.Errorf("watch profiles: %w", err)
	}

	userWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		profWatcher.Close()
		cancel()
		return err
	}

	if err := userWatcher.Add(m.usersPath); err != nil {
		profWatcher.Close()
		userWatcher.Close()
		cancel()
		return fmt.Errorf("watch users: %w", err)
	}

	m.watcherProfiles = profWatcher
	m.watcherUsers = userWatcher

	go m.watchLoop(ctx, profWatcher, m.reloadProfiles, "profiles", m.profilesPath)
	go m.watchLoop(ctx, userWatcher, m.reloadUsers, "users", m.usersPath)

	return nil
}

func (m *Manager) watchLoop(ctx context.Context, watcher *fsnotify.Watcher, reload func() error, label, path string) {
	for {
		select {
		case <-ctx.Done():
			return
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			logs.Log(fmt.Sprintf("[AUTHZ][%s-watch] %v", label, err))
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}

			if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				if err := reload(); err != nil {
					logs.Log(fmt.Sprintf("[AUTHZ][%s] reload failed: %v", label, err))
				}
			}

			if event.Op&(fsnotify.Remove|fsnotify.Rename) != 0 {
				go m.readdWatcher(label, watcher, path)
			}
		}
	}
}

func (m *Manager) readdWatcher(label string, watcher *fsnotify.Watcher, path string) {
	for i := 0; i < 3; i++ {
		time.Sleep(500 * time.Millisecond)
		if err := watcher.Add(path); err == nil {
			logs.Log(fmt.Sprintf("[AUTHZ][%s] rewatch successful", label))
			return
		}
	}
	logs.Log(fmt.Sprintf("[AUTHZ][%s] failed to rewatch %s", label, path))
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
