/*
 * Copyright (C) 2025 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package methods

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"os/exec"
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

func OTPVerify(c *gin.Context) {
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
	secret := GetUserSecret(username)

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
		recoveryCodes := GetRecoveryCodes(username)

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
		if !UpdateRecoveryCodes(username, recoveryCodes) {
			c.JSON(http.StatusBadRequest, structs.Map(models.StatusBadRequest{
				Code:    400,
				Message: "OTP recovery codes not updated",
				Data:    "",
			}))
			return
		}
	}

	// enable 2FA for user
	if !Enable2FA(username) {
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
	result, setSecret := SetUserSecret(account, secretBase32)
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

func DeleteExpiredTokens() {
	// iterate through all user sessions
	for username, userSession := range store.UserSessions {
		// parse JWT token to check expiration
		token, err := jwtv4.Parse(userSession.JWTToken, func(token *jwtv4.Token) (interface{}, error) {
			return []byte(configuration.Config.Secret_jwt), nil
		})

		// check if token is valid and not expired
		isValid := false
		if err == nil && token.Valid {
			if claims, ok := token.Claims.(jwtv4.MapClaims); ok {
				if exp, ok := claims["exp"].(float64); ok {
					// check if token is not expired
					if time.Now().Unix() < int64(exp) {
						isValid = true
					}
				}
			}
		}

		// remove session if token is expired or invalid
		if !isValid {
			delete(store.UserSessions, username)
			logs.Log("[INFO][JWT] Removed expired session for user: " + username)
		}
	}

	logs.Log("[INFO][JWT] Completed cleanup of expired user sessions")
}

func PhoneIslandTokenLogin(c *gin.Context) {
	claims := jwt.ExtractClaims(c)
	username, ok := claims["id"].(string)
	if !ok || username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid user"})
		return
	}

	// Get token from CTI Server
	userSession := store.UserSessions[username]
	nethctiToken := userSession.NethCTIToken

	req, err := http.NewRequest("POST", configuration.Config.V1Protocol+"://"+configuration.Config.V1ApiEndpoint+configuration.Config.V1ApiPath+"/authentication/phone_island_token_login", nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to create request"})
		return
	}
	req.Header.Set("Authorization", nethctiToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to contact server v1"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.JSON(http.StatusBadGateway, gin.H{"message": "server v1 returned error", "status": resp.StatusCode})
		return
	}

	var v1Resp struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&v1Resp); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to parse server v1 response"})
		return
	}

	phoneIslandToken := v1Resp.Token

	apiKey, err := generateAPIKey(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to generate api key"})
		return
	}
	if err := saveAPIKey(username, apiKey, phoneIslandToken); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to save api key"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":    apiKey,
		"username": username,
	})
}

func PhoneIslandTokenRemove(c *gin.Context) {
	claims := jwt.ExtractClaims(c)
	username, ok := claims["id"].(string)
	if !ok || username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid user"})
		return
	}

	err := os.Remove(configuration.Config.SecretsDir + "/" + username + "/phone_island_api_key.json")
	if err != nil {
		if os.IsNotExist(err) {
			c.JSON(http.StatusOK, gin.H{"removed": false, "message": "api key not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"removed": false, "message": "failed to remove api key"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"removed": true})
}

func PhoneIslandTokenCheck(c *gin.Context) {
	claims := jwt.ExtractClaims(c)
	username, ok := claims["id"].(string)
	if !ok || username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid user"})
		return
	}

	exists := false
	if _, err := os.Stat(configuration.Config.SecretsDir + "/" + username + "/phone_island_api_key.json"); err == nil {
		exists = true
	} else if !os.IsNotExist(err) {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to check api key"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"exists": exists})
}

func VerifyPassword(c *gin.Context) {
	// get payload
	var loginData models.LoginJson

	if err := c.ShouldBindBodyWith(&loginData, binding.JSON); err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(models.StatusBadRequest{
			Code:    400,
			Message: "request fields malformed",
			Data:    err.Error(),
		}))
		return
	}

	// validate required fields
	if loginData.Username == "" || loginData.Password == "" {
		c.JSON(http.StatusBadRequest, structs.Map(models.StatusBadRequest{
			Code:    400,
			Message: "username and password are required",
			Data:    "",
		}))
		return
	}

	// verify password against NetCTI server
	netCtiLoginURL := configuration.Config.V1Protocol + "://" + configuration.Config.V1ApiEndpoint + configuration.Config.V1ApiPath + "/authentication/login"
	payload := map[string]string{"username": loginData.Username, "password": loginData.Password}
	payloadBytes, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", netCtiLoginURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		logs.Log("[AUTH] Failed to create HTTP request for password verification")
		c.JSON(http.StatusInternalServerError, structs.Map(models.StatusInternalServerError{
			Code:    500,
			Message: "failed to create verification request",
			Data:    "",
		}))
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logs.Log("[AUTH] Failed to send password verification request to NetCTI")
		c.JSON(http.StatusInternalServerError, structs.Map(models.StatusInternalServerError{
			Code:    500,
			Message: "failed to contact authentication server",
			Data:    "",
		}))
		return
	}
	defer resp.Body.Close()

	var NethCTIToken string
	isValidPassword := false

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		wwwAuth := resp.Header.Get("Www-Authenticate")
		if wwwAuth != "" {
			// Generate NethCTIToken using the www-authenticate header
			NethCTIToken = utils.GenerateLegacyToken(resp, loginData.Username, loginData.Password)
			if NethCTIToken != "" {
				// Verify the generated token by making a request to /user/me
				netCtiMeURL := configuration.Config.V1Protocol + "://" + configuration.Config.V1ApiEndpoint + configuration.Config.V1ApiPath + "/user/me"
				req, _ := http.NewRequest("GET", netCtiMeURL, nil)
				req.Header.Set("Authorization", NethCTIToken)

				resp, err = client.Do(req)
				if err == nil && resp.StatusCode == http.StatusOK {
					isValidPassword = true
				}
				if resp != nil {
					resp.Body.Close()
				}
			}
		}
	case http.StatusOK:
		isValidPassword = true
	}

	if isValidPassword {
		c.JSON(http.StatusOK, structs.Map(models.StatusOK{
			Code:    200,
			Message: "password verified successfully",
			Data:    gin.H{"valid": true},
		}))
	} else {
		c.JSON(http.StatusUnauthorized, structs.Map(models.StatusUnauthorized{
			Code:    401,
			Message: "invalid credentials",
			Data:    gin.H{"valid": false},
		}))
	}
}

// Generate a random API key string
func generateAPIKey(username string) (string, error) {
	claims := jwtv4.MapClaims{
		"id":  username,
		"2fa": false,
		"exp": time.Now().Add(100 * 365 * 24 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}

	token := jwtv4.NewWithClaims(jwtv4.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(configuration.Config.Secret_jwt))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// Save API key for a user
func saveAPIKey(username string, apiKey string, phoneIslandToken string) error {
	dir := configuration.Config.SecretsDir + "/" + username
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}

	data := models.ApiKeyData{
		Username:         username,
		APIKey:           apiKey,
		PhoneIslandToken: phoneIslandToken,
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(dir+"/phone_island_api_key.json", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(jsonBytes)
	if err != nil {
		return err
	}

	return nil
}

// AuthenticateAPIKey returns true if the API key matches the stored key for the user, false otherwise
func AuthenticateAPIKey(username, apiKey string) bool {
	dir := configuration.Config.SecretsDir + "/" + username
	filePath := dir + "/phone_island_api_key.json"

	// Check if directory exists
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return false
	}

	// Check if file exists
	data, err := os.ReadFile(filePath)
	if err != nil {
		return false
	}

	// Unmarshal the JSON data
	var keyData models.ApiKeyData
	if err := json.Unmarshal(data, &keyData); err != nil {
		return false
	}

	return keyData.APIKey == apiKey
}

// Return the PhoneIslandToken from ApiKeyData given a JWT token string
func GetPhoneIslandToken(jwtToken string, onlyToken bool) (string, error) {
	// Parse the JWT token to extract the username (id)
	token, err := jwtv4.Parse(jwtToken, func(token *jwtv4.Token) (interface{}, error) {
		return []byte(configuration.Config.Secret_jwt), nil
	})
	if err != nil || !token.Valid {
		return "", err
	}

	claims, ok := token.Claims.(jwtv4.MapClaims)
	if !ok {
		return "", err
	}

	username, ok := claims["id"].(string)
	if !ok || username == "" {
		return "", err
	}

	dir := configuration.Config.SecretsDir + "/" + username
	filePath := dir + "/phone_island_api_key.json"

	// Check if file exists
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}

	var keyData models.ApiKeyData
	if err := json.Unmarshal(data, &keyData); err != nil {
		return "", err
	}

	if onlyToken {
		return keyData.PhoneIslandToken, nil
	} else {
		completedToken := keyData.Username + ":" + keyData.PhoneIslandToken
		return completedToken, nil
	}
}
