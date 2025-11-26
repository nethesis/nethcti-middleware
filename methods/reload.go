package methods

import (
	"net/http"

	"github.com/fatih/structs"
	"github.com/gin-gonic/gin"
	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/models"
	"github.com/nethesis/nethcti-middleware/store"
)

// AdminReloadProfiles reloads profiles and users globally via super admin API endpoint
func AdminReloadProfiles(c *gin.Context) {
	// Call store.ReloadProfiles() to reload profiles and users from configuration files
	if err := store.ReloadProfiles(); err != nil {
		logs.Log("[ERROR][AUTH] Failed to reload profiles via super admin: " + err.Error())
		c.JSON(http.StatusInternalServerError, structs.Map(models.StatusInternalServerError{
			Code:    http.StatusInternalServerError,
			Message: "failed to reload profiles",
			Data:    err.Error(),
		}))
		return
	}

	logs.Log("[INFO][AUTO] Global profile reload completed successfully via /admin/reload/profiles endpoint")

	// Return success response
	c.JSON(http.StatusOK, structs.Map(models.StatusOK{
		Code:    200,
		Message: "profiles reloaded successfully",
		Data:    gin.H{},
	}))
}
