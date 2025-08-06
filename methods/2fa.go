/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"crypto/rand"
	"encoding/base32"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/dgryski/dgoogauth"
	"github.com/fatih/structs"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	jwtv4 "github.com/golang-jwt/jwt/v4"
	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/models"
	"github.com/nethesis/nethcti-middleware/store"
	"github.com/nethesis/nethcti-middleware/utils"
)

// -------------------------------- exported methods --------------------------------

// GetUserStatus retrieves the 2FA status for the user
func GetUserStatus(username string) (string, error) {
	status, err := os.ReadFile(configuration.Config.SecretsDir + "/" + username + "/status")
	statusS := strings.TrimSpace(string(status[:]))

	return statusS, err
}

// Test2FAStatus checks if 2FA is enabled for the user
func Get2FAStatus(c *gin.Context) {
	// get claims from token
	claims := jwt.ExtractClaims(c)

	// get status
	twoFaStatus, _ := GetUserStatus(claims["id"].(string))

	// return response
	c.JSON(http.StatusOK, gin.H{"status": twoFaStatus == "1"})
}

// VerifyOTP verifies the OTP provided by the user
func VerifyOTP(c *gin.Context) {
	// get payload
	var jsonOTP models.OTPJson

	if err := c.ShouldBindBodyWith(&jsonOTP, binding.JSON); err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(models.StatusBadRequest{
			Code:    400,
			Message: "request fields malformed",
			Data:    err.Error(),
		}))
		return
	}

	// get secret for the user
	username := jsonOTP.Username
	secret := getUserSecret(username)

	// check secret
	if len(secret) == 0 {
		c.JSON(http.StatusNotFound, structs.Map(models.StatusNotFound{
			Code:    404,
			Message: "user secret not found",
			Data:    "",
		}))
		return
	}

	// set OTP configuration
	otpc := &dgoogauth.OTPConfig{
		Secret:      secret,
		WindowSize:  3,
		HotpCounter: 0,
	}

	// verifiy OTP
	result, err := otpc.Authenticate(jsonOTP.OTP)
	if err != nil || !result {

		// check if OTP is a recovery code
		recoveryCodes := getRecoveryCodes(username)

		if !utils.Contains(jsonOTP.OTP, recoveryCodes) {
			c.JSON(http.StatusBadRequest, structs.Map(models.StatusBadRequest{
				Code:    400,
				Message: "invalid_otp",
				Data:    nil,
			}))
			return
		}

		// remove used recovery OTP
		recoveryCodes = utils.Remove(jsonOTP.OTP, recoveryCodes)

		// update recovery codes file
		if !updateRecoveryCodes(username, recoveryCodes) {
			c.JSON(http.StatusBadRequest, structs.Map(models.StatusBadRequest{
				Code:    400,
				Message: "OTP recovery codes not updated",
				Data:    "",
			}))
			return
		}
	}

	// enable 2FA for user
	if !enable2FA(username) {
		c.JSON(http.StatusBadRequest, structs.Map(models.StatusBadRequest{
			Code:    400,
			Message: "failed to enable 2FA",
			Data:    "",
		}))
		return
	}

	// update user session to mark OTP as verified
	store.UserSessions[username].OTP_Verified = true

	// Regenerate JWT token with updated 2FA status
	newUserSession, expire, err := regenerateUserToken(store.UserSessions[username])

	if err != nil {
		c.JSON(http.StatusInternalServerError, structs.Map(models.StatusBadRequest{
			Code:    500,
			Message: "failed to generate new token",
			Data:    err.Error(),
		}))
		return
	}

	// response with new token
	c.JSON(http.StatusOK, structs.Map(models.StatusOK{
		Code:    200,
		Message: "OTP verified",
		Data:    gin.H{"token": newUserSession.JWTToken, "expire": expire},
	}))
}

// QRCode generates a QR code for the user to set up 2FA
func QRCode(c *gin.Context) {
	// generate random secret
	secret := make([]byte, 20)
	_, err := rand.Read(secret)
	if err != nil {
		logs.Log("[ERR][2FA] Failed to generate random secret for QRCode: " + err.Error())
	}

	// convert to string
	secretBase32 := base32.StdEncoding.EncodeToString(secret)

	// get claims from token
	claims := jwt.ExtractClaims(c)

	// define issuer
	account := claims["id"].(string)
	issuer := configuration.Config.Issuer2FA

	// set secret for user
	result, setSecret := setUserSecret(account, secretBase32)
	if !result {
		c.JSON(http.StatusBadRequest, structs.Map(models.StatusBadRequest{
			Code:    400,
			Message: "user secret set error",
			Data:    "",
		}))
		return
	}

	// define URL
	URL, err := url.Parse("otpauth://totp")
	if err != nil {
		logs.Log("[ERR][2FA] Failed to parse URL for QRCode: " + err.Error())
	}

	// add params
	URL.Path += "/" + issuer + ":" + account
	params := url.Values{}
	params.Add("secret", setSecret)
	params.Add("algorithm", "SHA1")
	params.Add("digits", "6")
	params.Add("period", "30")

	// print url
	URL.RawQuery = params.Encode()

	// response
	c.JSON(http.StatusOK, structs.Map(models.StatusOK{
		Code:    200,
		Message: "QR code string",
		Data:    gin.H{"url": URL.String(), "key": setSecret},
	}))
}

// Disable2FA disables two-factor authentication for the user
func Disable2FA(c *gin.Context) {
	// get claims from token
	claims := jwt.ExtractClaims(c)
	username := claims["id"].(string)

	// revocate secret
	errRevocate := os.Remove(configuration.Config.SecretsDir + "/" + username + "/secret")
	if errRevocate != nil {
		c.JSON(http.StatusBadRequest, structs.Map(models.StatusBadRequest{
			Code:    403,
			Message: "error in revocate 2FA for user",
			Data:    nil,
		}))
		return
	}

	// revocate recovery codes
	errRevocateCodes := os.Remove(configuration.Config.SecretsDir + "/" + username + "/codes")
	if errRevocateCodes != nil {
		// if the file does not exist, it is ok, skip the error
		if !os.IsNotExist(errRevocateCodes) {
			c.JSON(http.StatusBadRequest, structs.Map(models.StatusBadRequest{
				Code:    403,
				Message: "error in delete 2FA recovery codes",
				Data:    nil,
			}))
			return
		}
	}

	// set 2FA to disabled
	f, _ := os.OpenFile(configuration.Config.SecretsDir+"/"+username+"/status", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	defer f.Close()

	// write file with tokens
	_, err := f.WriteString("0")

	// check error
	if err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(models.StatusBadRequest{
			Code:    400,
			Message: "2FA not revocated",
			Data:    "",
		}))
		return
	}

	// Regenerate JWT token with updated 2FA status (disabled)
	userSession := store.UserSessions[username]

	if userSession != nil {
		// Reset OTP verification status
		userSession.OTP_Verified = false

		newUserSession, expire, err := regenerateUserToken(userSession)
		if err != nil {
			c.JSON(http.StatusInternalServerError, structs.Map(models.StatusBadRequest{
				Code:    500,
				Message: "failed to generate new token after disabling 2FA",
				Data:    err.Error(),
			}))
			return
		}

		// response with new token
		c.JSON(http.StatusOK, structs.Map(models.StatusOK{
			Code:    200,
			Message: "2FA revocate successfully",
			Data:    gin.H{"token": newUserSession.JWTToken, "expire": expire},
		}))
		return
	}

	// response without new token if user session not found
	c.JSON(http.StatusOK, structs.Map(models.StatusOK{
		Code:    200,
		Message: "2FA revocate successfully",
		Data:    "",
	}))
}

// Get2FARecoveryCodes retrieves the recovery codes for the user
func Get2FARecoveryCodes(c *gin.Context) {
	claims := jwt.ExtractClaims(c)

	codes := getRecoveryCodes(claims["id"].(string))

	c.JSON(http.StatusOK, gin.H{"codes": codes})
}

// -------------------------------- private methods --------------------------------

// enable2FA enables two-factor authentication for the user
func enable2FA(username string) bool {
	// check if dir exists, otherwise create it
	if _, errD := os.Stat(configuration.Config.SecretsDir + "/" + username); os.IsNotExist(errD) {
		_ = os.MkdirAll(configuration.Config.SecretsDir+"/"+username, 0700)
	}

	// set 2FA to enabled
	f, _ := os.OpenFile(configuration.Config.SecretsDir+"/"+username+"/status", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	defer f.Close()

	// write file with 2fa status
	_, err := f.WriteString("1")

	return err == nil
}

// regenerateUserToken creates a new JWT token for an existing user session
func regenerateUserToken(userSession *models.UserSession) (*models.UserSession, time.Time, error) {
	// Create new JWT payload with updated 2FA status
	status, _ := GetUserStatus(userSession.Username)

	now := time.Now()
	expire := now.Add(time.Hour * 24 * 14) // 2 weeks

	claims := jwtv4.MapClaims{
		"id":  userSession.Username,
		"2fa": status == "1",
		"exp": expire.Unix(),
		"iat": now.Unix(),
	}

	// Create and sign token using github.com/golang-jwt/jwt/v4
	token := jwtv4.NewWithClaims(jwtv4.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(configuration.Config.Secret_jwt))

	if err != nil {
		return nil, time.Time{}, err
	}

	// Update user session with new token
	userSession.JWTToken = tokenString

	return userSession, expire, nil
}

// getUserSecret retrieves the secret for the user
func getUserSecret(username string) string {
	// get secret
	secret, err := os.ReadFile(configuration.Config.SecretsDir + "/" + username + "/secret")

	// handle error
	if err != nil {
		return ""
	}

	// return string
	return string(secret[:])
}

// setUserSecret sets the secret for the user
func setUserSecret(username string, secret string) (bool, string) {
	// get secret
	secretB, _ := os.ReadFile(configuration.Config.SecretsDir + "/" + username + "/secret")

	// check error
	if len(string(secretB[:])) == 0 {
		// check if dir exists, otherwise create it
		if _, errD := os.Stat(configuration.Config.SecretsDir + "/" + username); os.IsNotExist(errD) {
			_ = os.MkdirAll(configuration.Config.SecretsDir+"/"+username, 0700)
		}

		// open file
		f, _ := os.OpenFile(configuration.Config.SecretsDir+"/"+username+"/secret", os.O_WRONLY|os.O_CREATE, 0600)
		defer f.Close()

		// write file with secret
		_, err := f.WriteString(secret)

		// check error
		if err != nil {
			return false, ""
		}

		return true, secret
	}

	return true, string(secretB[:])
}

// getRecoveryCodes retrieves the recovery codes for the user
func getRecoveryCodes(username string) []string {
	// create empty array
	var recoveryCodes []string

	// check if recovery codes exists
	savedCodes, _ := os.ReadFile(configuration.Config.SecretsDir + "/" + username + "/codes")

	// check length
	if len(string(savedCodes[:])) == 0 {

		// get secret
		secret := getUserSecret(username)

		// get recovery codes
		if len(string(secret)) > 0 {
			// generate new random recovery codes
			newCodes := generateRandomRecoveryCodes()

			// create codes string
			codesString := strings.Join(newCodes, "\n") + "\n"

			// open file
			f, _ := os.OpenFile(configuration.Config.SecretsDir+"/"+username+"/codes", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
			defer f.Close()

			// write file with codes
			_, _ = f.WriteString(codesString)

			// assign codes
			return newCodes
		}
	}

	// parse output
	recoveryCodes = strings.Split(string(savedCodes[:]), "\n")

	// remove empty element, the last one
	if len(recoveryCodes) > 0 && recoveryCodes[len(recoveryCodes)-1] == "" {
		recoveryCodes = recoveryCodes[:len(recoveryCodes)-1]
	}

	// return codes
	return recoveryCodes
}

// updateRecoveryCodes updates the recovery codes for the user
func updateRecoveryCodes(username string, codes []string) bool {
	// open file
	f, _ := os.OpenFile(configuration.Config.SecretsDir+"/"+username+"/codes", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	defer f.Close()

	// write file with secret
	codes = append(codes, "")
	_, err := f.WriteString(strings.Join(codes[:], "\n"))

	// check error
	return err == nil
}

// generateRandomRecoveryCodes generates random recovery codes
func generateRandomRecoveryCodes() []string {
	var codes []string

	// Generate 5 random recovery codes
	for i := 0; i < 5; i++ {
		// Generate 6-digit numeric recovery code
		code := ""
		for j := 0; j < 6; j++ {
			digit := make([]byte, 1)
			rand.Read(digit)
			code += string('0' + (digit[0] % 10))
		}
		codes = append(codes, code)
	}

	return codes
}
