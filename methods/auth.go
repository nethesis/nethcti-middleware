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
	"os/exec"
	"strings"
	"time"

	"github.com/Jeffail/gabs/v2"
	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/dgryski/dgoogauth"
	"github.com/fatih/structs"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	jwtv4 "github.com/golang-jwt/jwt/v4"

	"github.com/nethesis/nethcti-middleware/configuration"
	"github.com/nethesis/nethcti-middleware/logs"
	"github.com/nethesis/nethcti-middleware/models"
	"github.com/nethesis/nethcti-middleware/response"
	"github.com/nethesis/nethcti-middleware/store"
	"github.com/nethesis/nethcti-middleware/utils"
)

// regenerateUserToken creates a new JWT token for an existing user session
func regenerateUserToken(userSession *models.UserSession) (string, time.Time, error) {
	// Create new JWT payload with updated 2FA status
	status, _ := GetUserStatus(userSession.Username)

	now := time.Now()
	expire := now.Add(time.Hour * 24 * 14) // 2 weeks

	claims := jwtv4.MapClaims{
		"id":      userSession.Username,
		"role":    "",
		"actions": []string{},
		"2fa":     status == "1",
		"exp":     expire.Unix(),
		"iat":     now.Unix(),
	}

	// Create and sign token using github.com/golang-jwt/jwt/v4
	token := jwtv4.NewWithClaims(jwtv4.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(configuration.Config.Secret_jwt))
	if err != nil {
		return "", time.Time{}, err
	}

	// Update user session with new token
	userSession.JWTToken = tokenString

	return tokenString, expire, nil
}

func OTPVerify(c *gin.Context) {
	// get payload
	var jsonOTP models.OTPJson

	if err := c.ShouldBindBodyWith(&jsonOTP, binding.JSON); err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "request fields malformed",
			Data:    err.Error(),
		}))
		return
	}

	// get secret for the user
	secret := GetUserSecret(jsonOTP.Username)

	// check secret
	if len(secret) == 0 {
		c.JSON(http.StatusNotFound, structs.Map(response.StatusNotFound{
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
		recoveryCodes := GetRecoveryCodes(jsonOTP.Username)

		if !utils.Contains(jsonOTP.OTP, recoveryCodes) {
			// compose validation error
			jsonParsed, _ := gabs.ParseJSON([]byte(`{
				"validation": {
				  "errors": [
					{
					  "message": "invalid_otp",
					  "parameter": "otp",
					  "value": ""
					}
				  ]
				}
			}`))

			// return validation error
			c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
				Code:    400,
				Message: "validation_failed",
				Data:    jsonParsed,
			}))
			return
		}

		// remove used recovery OTP
		recoveryCodes = utils.Remove(jsonOTP.OTP, recoveryCodes)

		// update recovery codes file
		if !UpdateRecoveryCodes(jsonOTP.Username, recoveryCodes) {
			c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
				Code:    400,
				Message: "OTP recovery codes not updated",
				Data:    "",
			}))
			return
		}
	}

	// enable 2FA for user
	if !Enable2FA(jsonOTP.Username) {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "failed to enable 2FA",
			Data:    "",
		}))
		return
	}

	// update user session to mark OTP as verified
	store.UserSessions[jsonOTP.Username].OTP_Verified = true

	// Regenerate JWT token with updated 2FA status
	userSession := store.UserSessions[jsonOTP.Username]
	newToken, expire, err := regenerateUserToken(userSession)
	if err != nil {
		c.JSON(http.StatusInternalServerError, structs.Map(response.StatusBadRequest{
			Code:    500,
			Message: "failed to generate new token",
			Data:    err.Error(),
		}))
		return
	}

	// response with new token
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "OTP verified",
		Data:    gin.H{"token": newToken, "expire": expire},
	}))
}

func QRCode(c *gin.Context) {
	// generate random secret
	secret := make([]byte, 20)
	_, err := rand.Read(secret)
	if err != nil {
		logs.Logs.Println("[ERR][2FA] Failed to generate random secret for QRCode: " + err.Error())
	}

	// convert to string
	secretBase32 := base32.StdEncoding.EncodeToString(secret)

	// get claims from token
	claims := jwt.ExtractClaims(c)

	// define issuer
	account := claims["id"].(string)
	issuer := configuration.Config.Issuer2FA

	// set secret for user
	result, setSecret := SetUserSecret(account, secretBase32)
	if !result {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "user secret set error",
			Data:    "",
		}))
		return
	}

	// define URL
	URL, err := url.Parse("otpauth://totp")
	if err != nil {
		logs.Logs.Println("[ERR][2FA] Failed to parse URL for QRCode: " + err.Error())
	}

	// add params
	URL.Path += "/" + issuer + ":" + account
	params := url.Values{}
	params.Add("secret", setSecret)
	params.Add("issuer", issuer)
	params.Add("algorithm", "SHA1")
	params.Add("digits", "6")
	params.Add("period", "30")

	// print url
	URL.RawQuery = params.Encode()

	// response
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "QR code string",
		Data:    gin.H{"url": URL.String(), "key": setSecret},
	}))
}

func Get2FAStatus(c *gin.Context) {
	// get claims from token
	claims := jwt.ExtractClaims(c)

	// get status
	twoFaStatus, _ := GetUserStatus(claims["id"].(string))

	// return response
	c.JSON(http.StatusOK, gin.H{"status": twoFaStatus == "1"})
}

func Get2FARecoveryCodes(c *gin.Context) {
	claims := jwt.ExtractClaims(c)

	codes := GetRecoveryCodes(claims["id"].(string))

	c.JSON(http.StatusOK, gin.H{"codes": codes})
}

func GetUserStatus(username string) (string, error) {
	status, err := os.ReadFile(configuration.Config.SecretsDir + "/" + username + "/status")
	statusS := strings.TrimSpace(string(status[:]))

	return statusS, err
}

func GetUserSecret(username string) string {
	// get secret
	secret, err := os.ReadFile(configuration.Config.SecretsDir + "/" + username + "/secret")

	// handle error
	if err != nil {
		return ""
	}

	// return string
	return string(secret[:])
}

func SetUserSecret(username string, secret string) (bool, string) {
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

func Verify2FA(username, otp string) bool {
	// get secret for the user
	secret := GetUserSecret(username)
	if len(secret) == 0 {
		return false
	}

	// set OTP configuration
	otpc := &dgoogauth.OTPConfig{
		Secret:      secret,
		WindowSize:  3,
		HotpCounter: 0,
	}

	// verify OTP
	result, err := otpc.Authenticate(otp)
	if err != nil || !result {
		// check if OTP is a recovery code
		recoveryCodes := GetRecoveryCodes(username)
		if utils.Contains(otp, recoveryCodes) {
			// remove used recovery OTP
			recoveryCodes = utils.Remove(otp, recoveryCodes)
			// update recovery codes file
			return UpdateRecoveryCodes(username, recoveryCodes)
		}
		return false
	}

	return true
}

func GetRecoveryCodes(username string) []string {
	// create empty array
	var recoveryCodes []string

	// check if recovery codes exists
	codesB, _ := os.ReadFile(configuration.Config.SecretsDir + "/" + username + "/codes")

	// check length
	if len(string(codesB[:])) == 0 {

		// get secret
		secret := GetUserSecret(username)

		// get recovery codes
		if len(string(secret)) > 0 {
			// execute oathtool to get recovery codes
			out, err := exec.Command("/usr/bin/oathtool", "-w", "4", "-b", secret).Output()

			// check errors
			if err != nil {
				return recoveryCodes
			}

			// open file
			f, _ := os.OpenFile(configuration.Config.SecretsDir+"/"+username+"/codes", os.O_WRONLY|os.O_CREATE, 0600)
			defer f.Close()

			// write file with secret
			_, _ = f.WriteString(string(out[:]))

			// assign binary output
			codesB = out
		}

	}

	// parse output
	recoveryCodes = strings.Split(string(codesB[:]), "\n")

	// remove empty element, the last one
	if recoveryCodes[len(recoveryCodes)-1] == "" {
		recoveryCodes = recoveryCodes[:len(recoveryCodes)-1]
	}

	// return codes
	return recoveryCodes
}

func UpdateRecoveryCodes(username string, codes []string) bool {
	// open file
	f, _ := os.OpenFile(configuration.Config.SecretsDir+"/"+username+"/codes", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	defer f.Close()

	// write file with secret
	codes = append(codes, "")
	_, err := f.WriteString(strings.Join(codes[:], "\n"))

	// check error
	return err == nil
}

func Enable2FA(username string) bool {
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

func Disable2FA(c *gin.Context) {
	// get claims from token
	claims := jwt.ExtractClaims(c)

	// revocate secret
	errRevocate := os.Remove(configuration.Config.SecretsDir + "/" + claims["id"].(string) + "/secret")
	if errRevocate != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    403,
			Message: "error in revocate 2FA for user",
			Data:    nil,
		}))
		return
	}

	// revocate recovery codes
	errRevocateCodes := os.Remove(configuration.Config.SecretsDir + "/" + claims["id"].(string) + "/codes")
	if errRevocateCodes != nil {
		// if the file does not exist, it is ok, skip the error
		if !os.IsNotExist(errRevocateCodes) {
			c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
				Code:    403,
				Message: "error in delete 2FA recovery codes",
				Data:    nil,
			}))
			return
		}
	}

	// set 2FA to disabled
	f, _ := os.OpenFile(configuration.Config.SecretsDir+"/"+claims["id"].(string)+"/status", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	defer f.Close()

	// write file with tokens
	_, err := f.WriteString("0")

	// check error
	if err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "2FA not revocated",
			Data:    "",
		}))
		return
	}

	// Regenerate JWT token with updated 2FA status (disabled)
	username := claims["id"].(string)
	userSession := store.UserSessions[username]
	if userSession != nil {
		// Reset OTP verification status
		userSession.OTP_Verified = false

		newToken, expire, err := regenerateUserToken(userSession)
		if err != nil {
			c.JSON(http.StatusInternalServerError, structs.Map(response.StatusBadRequest{
				Code:    500,
				Message: "failed to generate new token after disabling 2FA",
				Data:    err.Error(),
			}))
			return
		}

		// response with new token
		c.JSON(http.StatusOK, structs.Map(response.StatusOK{
			Code:    200,
			Message: "2FA revocate successfully",
			Data:    gin.H{"token": newToken, "expire": expire},
		}))
		return
	}

	// response without new token if user session not found
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "2FA revocate successfully",
		Data:    "",
	}))
}
