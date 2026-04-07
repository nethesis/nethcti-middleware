package methods

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/nethesis/nethcti-middleware/store"
)

// GetExtensionByMainExtensionAndType resolves an endpoint extension from
// the user main extension and the requested endpoint type.
func GetExtensionByMainExtensionAndType(c *gin.Context) {
	mainExtension := strings.TrimSpace(c.Param("mainextension"))
	extensionType := strings.TrimSpace(c.Param("type"))

	username, extension, err := store.GetExtensionByMainExtensionAndType(mainExtension, extensionType)
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
