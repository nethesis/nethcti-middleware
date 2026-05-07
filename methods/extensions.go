package methods

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/store"
)

// GetExtensionByMainExtensionAndType resolves an endpoint extension from
// the user main extension and the requested endpoint type.
func GetExtensionByMainExtensionAndType(c *gin.Context) {
	mainExtension := strings.TrimSpace(c.Param("mainextension"))
	extensionType := strings.TrimSpace(c.Param("type"))

	username, extension, err := store.GetExtensionByMainExtensionAndType(mainExtension, extensionType)
	if err != nil && mainExtension != "" && extensionType != "" {
		stats, reloadErr := store.ReloadProfiles()
		if reloadErr != nil {
			logs.Log("[WARNING][AUTH] failed to reload profiles before retrying extension lookup: " + reloadErr.Error())
		} else {
			logs.Log(fmt.Sprintf("[INFO][AUTH] reloaded profiles before retrying extension lookup: users=%d profiles=%d", stats.UsersLoaded, stats.ProfilesLoaded))
			username, extension, err = store.GetExtensionByMainExtensionAndType(mainExtension, extensionType)
		}
	}

	if err != nil {
		status := http.StatusNotFound
		if mainExtension == "" || extensionType == "" {
			status = http.StatusBadRequest
		}
		c.JSON(status, gin.H{
			"error":         err.Error(),
			"mainextension": mainExtension,
			"type":          extensionType,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"username":      username,
		"mainextension": mainExtension,
		"type":          extensionType,
		"extension":     extension,
	})
}
