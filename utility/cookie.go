package utility

import (
	"fmt"
	"net/textproto"
	"strings"

	"golang.org/x/net/http/httpguts"
)

type Cookie struct {
	Name  string
	Value string
}

func readCookies(cookieStr string, filter string) []*Cookie {
	line := cookieStr
	cookies := make([]*Cookie, 0, strings.Count(cookieStr, ";"))
	// for _, line := range lines {
	line = textproto.TrimString(line)

	var part string
	for len(line) > 0 { // continue since we have rest
		if splitIndex := strings.Index(line, ";"); splitIndex > 0 {
			part, line = line[:splitIndex], line[splitIndex+1:]
		} else {
			part, line = line, ""
		}
		fmt.Println("=>", part, line)
		part = textproto.TrimString(part)
		if len(part) == 0 {
			fmt.Println("if len(part) == 0")
			continue
		}
		name, val := part, ""
		if j := strings.Index(part, "="); j >= 0 {
			name, val = name[:j], name[j+1:]
		}
		if !isCookieNameValid(name) {
			fmt.Println("if !isCookieNameValid(name)", name)
			continue
		}
		if filter != "" && filter != name {
			fmt.Println(`if filter != "" && filter != name`)
			continue
		}
		val, ok := parseCookieValue(val, true)
		if !ok {
			fmt.Println("if !ok")
			continue
		}
		cookies = append(cookies, &Cookie{Name: name, Value: val})
	}
	// }
	return cookies
}

func isCookieNameValid(raw string) bool {
	if raw == "" {
		return false
	}
	return strings.IndexFunc(raw, func(r rune) bool {
		return !httpguts.IsTokenRune(r)
	}) < 0
}

func parseCookieValue(raw string, allowDoubleQuote bool) (string, bool) {
	// Strip the quotes, if present.
	if allowDoubleQuote && len(raw) > 1 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		raw = raw[1 : len(raw)-1]
	}
	for i := 0; i < len(raw); i++ {
		if !validCookieValueByte(raw[i]) {
			return "", false
		}
	}
	return raw, true
}
func validCookieValueByte(b byte) bool {
	return 0x20 <= b && b < 0x7f && b != '"' && b != ';' && b != '\\'
}
