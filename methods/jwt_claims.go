/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"fmt"

	jwtv4 "github.com/golang-jwt/jwt/v4"
	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/store"
)

// BuildUserJWTClaims builds the canonical JWT claims set for a user.
// All user tokens should use this helper to keep claims and capabilities aligned.
func BuildUserJWTClaims(username string, otpVerified bool) jwtv4.MapClaims {
	status, _ := GetUserStatus(username)

	claims := jwtv4.MapClaims{
		"id":           username,
		"2fa":          status == "1",
		"otp_verified": otpVerified,
	}

	profile, err := store.GetUserProfile(username)
	if err != nil {
		logs.Log(fmt.Sprintf("[WARNING][AUTH] Failed to load profile for user %s: %v", username, err))
		return claims
	}

	claims["profile_id"] = profile.ID
	claims["profile_name"] = profile.Name
	for capability, value := range profile.Capabilities {
		claims[capability] = value
	}

	logs.Log(fmt.Sprintf("[INFO][AUTH] Injected %d capabilities into JWT claims for user %s (profile: %s)",
		len(profile.Capabilities), username, profile.Name))

	return claims
}
