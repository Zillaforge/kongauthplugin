package utility

import (
	"fmt"
	"strings"
)

const (
	_defaultTokenCookieKey = "token"

	OnHdrType    = "OnHdr"
	OnCookieType = "OnCookie"
	OnEmpty      = "OnEmpty"
)

type ParserJWTTokenConfig struct {
	Token string
}

type GetHeaderFunc func() (string, error)

func ParserJWTToken(onAuthHdr, onApiKeyHdr, onCookie GetHeaderFunc, cfg *ParserJWTTokenConfig) (mode string, auth string, err error) {
	authHdr, errAuthHdr := onAuthHdr()
	apiKeyHdr, errApiKeyHdr := onApiKeyHdr()
	authCookie, errCookie := onCookie()

	if errAuthHdr != nil && errApiKeyHdr != nil && errCookie != nil {
		return OnEmpty, "", fmt.Errorf("get token fail from header and cookie")
	}

	if authHdr != "" {
		return OnHdrType, authHdr, nil
	}

	if apiKeyHdr != "" {
		// 補上 Bearer 在開頭
		return OnHdrType, formatToken(apiKeyHdr), nil
	}

	if errCookie != nil {
		return OnEmpty, "", fmt.Errorf("get token fail from cookie")
	}

	if authCookie == "" {
		return OnEmpty, "", fmt.Errorf("get empty auth in cookie")
	}

	if cfg.Token == "" {
		cfg.Token = _defaultTokenCookieKey
	}

	cookieArr := readCookies(authCookie, cfg.Token)

	if len(cookieArr) != 1 {
		return "", "", fmt.Errorf("cannot find token or find great then 1 in cookie")
	}

	return OnCookieType, formatToken(cookieArr[0].Value), nil
}

func formatToken(token string) string {
	if !strings.HasPrefix(token, "Bearer") {
		return "Bearer " + token
	}
	return token
}
