package common

import (
	"fmt"
	"strings"

	"github.com/Kong/go-pdk"
	"pegasus-cloud.com/aes/pegasusiamclient/pb"
)

type Headers struct {
	systemAdmin    bool
	userInfo       *pb.UserInfo
	projectInfo    *pb.ProjectInfo
	membershipInfo *pb.MembershipInfo
	hdrs           map[string]string
	saatUserID     string
}

func (h *Headers) SetSystemAdmin(b bool) {
	h.systemAdmin = b
}

func (h *Headers) GetSystemAdmin() bool {
	return h.systemAdmin
}

func (h *Headers) SetUserInfo(u *pb.UserInfo) {
	h.userInfo = u
}

func (h *Headers) GetUserInfo() *pb.UserInfo {
	return h.userInfo
}

func (h *Headers) SetProjectInfo(p *pb.ProjectInfo) {
	h.projectInfo = p
}

func (h *Headers) GetProjectInfo() *pb.ProjectInfo {
	return h.projectInfo
}

func (h *Headers) SetMembershipInfo(m *pb.MembershipInfo) {
	h.membershipInfo = m
}

func (h *Headers) GetMembershipInfo() *pb.MembershipInfo {
	return h.membershipInfo
}

func (h *Headers) SetHeader(kong *pdk.PDK, name string, value string) (err error) {
	if h.hdrs == nil {
		h.hdrs = make(map[string]string)
	}
	if err = kong.ServiceRequest.SetHeader(name, value); err != nil {
		kong.Log.Err("set header failed: err=", err.Error(), ", name=", name, ", value=", value)
		return
	}
	h.hdrs[name] = value
	return
}

func (h *Headers) SetHeaders(kong *pdk.PDK, headers map[string][]string) (err error) {
	if h.hdrs == nil {
		h.hdrs = make(map[string]string)
	}
	var elements = []string{}
	for k, v := range headers {
		elements = append(elements, fmt.Sprintf("%s=%s", k, strings.Join(v, ",")))
	}

	if err = kong.ServiceRequest.SetHeaders(headers); err != nil {
		kong.Log.Err("set header failed: err=", err.Error(), ", pairs=", strings.Join(elements, ";"))
		return
	}
	for k, v := range headers {
		h.hdrs[k] = strings.Join(v, ",")
	}
	return
}

func (h *Headers) PrintHeaders(kong *pdk.PDK) {
	if h.hdrs == nil {
		h.hdrs = make(map[string]string)
	}
	var elements = []string{}
	for k, v := range h.hdrs {
		elements = append(elements, fmt.Sprintf("%s=%s", k, v))
	}
	kong.Log.Debug("Set Headers : paris=", strings.Join(elements, ";"))
}

// 模擬分身 模擬者的UserID
func (h *Headers) SetSAATUserID(s string) {
	h.saatUserID = s
}

func (h *Headers) GetSAATUserID() string {
	return h.saatUserID
}
