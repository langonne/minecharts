package handlers

import (
	"net/http"

	"minecharts/cmd/config"
	"minecharts/cmd/database"
	"minecharts/cmd/logging"

	"github.com/gin-gonic/gin"
)

type MemoryQuotaResponse struct {
	Unlimited       bool    `json:"unlimited"`
	LimitGi         float64 `json:"limitGi,omitempty"`
	UsedGi          float64 `json:"usedGi,omitempty"`
	RemainingGi     float64 `json:"remainingGi,omitempty"`
	OverheadPercent float64 `json:"overheadPercent"`
}

// GetMemoryQuotaHandler returns the current memory quota usage including overhead.
func GetMemoryQuotaHandler(c *gin.Context) {
	overheadPercent := config.MemoryLimitOverheadPercent
	if overheadPercent < 0 {
		overheadPercent = 0
	}

	if !config.MemoryQuotaEnabled || config.MemoryQuotaLimit <= 0 {
		c.JSON(http.StatusOK, MemoryQuotaResponse{
			Unlimited:       true,
			OverheadPercent: overheadPercent,
		})
		return
	}

	db := database.GetDB()
	totalMemoryGB, err := db.SumServerMaxMemory(c.Request.Context())
	if err != nil {
		logging.Server.WithFields(
			"error", err.Error(),
		).Error("Failed to fetch memory quota usage")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch memory quota"})
		return
	}

	limitMi := int64(config.MemoryQuotaLimit) * 1024
	usedMi := config.MemoryLimitMi(totalMemoryGB)
	remainingMi := limitMi - usedMi
	if remainingMi < 0 {
		remainingMi = 0
	}

	toGi := func(mi int64) float64 {
		return float64(mi) / 1024.0
	}

	c.JSON(http.StatusOK, MemoryQuotaResponse{
		Unlimited:       false,
		LimitGi:         toGi(limitMi),
		UsedGi:          toGi(usedMi),
		RemainingGi:     toGi(remainingMi),
		OverheadPercent: overheadPercent,
	})
}
