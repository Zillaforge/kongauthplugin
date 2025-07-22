package main

import (
	"kong_auth_plugin/common"
	"kong_auth_plugin/utility"

	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/Kong/go-pdk"
	"github.com/Kong/go-pdk/server"
	cCon "github.com/Zillaforge/pegasusiamclient/constants"
	"github.com/Zillaforge/pegasusiamclient/iam"
	"github.com/Zillaforge/pegasusiamclient/pb"
	"github.com/Zillaforge/toolkits/errors"
)

const (
	headerKey      = "asus-auth-plugin-data"
	pathRegexpRule = `.+/\b(project|projects)\b\/(?P<UUID>\b[0-9a-f]{8}\b-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-\b[0-9a-f]{12}\b)`

	xIAMProjectIDKey = "X-IAM-PROJECT-ID"

	userIDKey         = "User-ID"
	userNameKey       = "User-Name"
	userAccountKey    = "User-Account"
	userEmailKey      = "User-Email"
	userRoleKey       = "User-Role"
	userRoleNumberKey = "User-Role-Number"

	projectIDKey        = "Project-ID"
	projectNameKey      = "Project-Name"
	projectNamespaceKey = "Project-Namespace"
	projectActiveKey    = "Project-Active"

	systemAdminKey = "System-admin"

	jsonOutputKey = "asus-auth-plugin-data"

	// 模擬分身 模擬者的UserID
	saatUserIDKey = "SAAT-User-ID"

	_skipResource = "Resource"
)

var (
	version    = "2.0.3"
	priority   = 999
	pathRegexp *regexp.Regexp
)

type (
	// Config ...
	Config struct {
		Hosts            []string `json:"hosts"`
		EnableURLEncode  bool     `json:"enable_url_encode"`
		EnableRawHeader  bool     `json:"enable_raw_header"`
		EnableJSONHeader bool     `json:"enable_json_header"`
		TokenKeyInCookie string   `json:"token_key_in_cookie"`
		RedirectURL      string   `json:"redirect_url"`
		//支援的Type有 OnHdr, OnCookie, and OnEmpty
		RedirectTypes            []string `json:"redirect_types"`
		EnablePermissionValidate bool     `json:"enable_permission_validate"`
		VerifiedService          string   `json:"verified_service"`
	}
	// User ...
	User struct {
		ID         string `json:"id,omitempty"`
		Name       string `json:"name,omitempty"`
		Email      string `json:"email,omitempty"`
		Role       string `json:"role,omitempty"`
		RoleNumber int    `json:"role_number,omitempty"`
	}
	// Project ...
	Project struct {
		ID        string `json:"id,omitempty"`
		Name      string `json:"name,omitempty"`
		Namespace string `json:"namespace,omitempty"`
		Active    bool   `json:"active,omitempty"`
	}
	// Header ...
	Header struct {
		User    *User    `json:"user,omitempty"`
		Project *Project `json:"project,omitempty"`
	}
)

// New ...
func New() interface{} {
	return &Config{}
}

func main() {
	server.StartServer(New, version, priority)
}

// Access ...
func (conf Config) Access(kong *pdk.PDK) {

	// Create connection pool between plugin and IAM server
	if err := newPool(conf.Hosts); err != nil {
		errMsg := fmt.Sprintf("Create PoolHandler is failed: %s", err.Error())
		kong.Log.Err(errMsg)
		kong.Response.Exit(http.StatusInternalServerError, common.NewErrorStruct(errMsg).ToBytes(), nil)
		return
	}
	handler := poolMap[convertPoolKey(conf.Hosts)]
	if handler == nil {
		errMsg := "PoolHandler is nil"
		kong.Log.Err(errMsg)
		kong.Response.Exit(http.StatusInternalServerError, common.NewErrorStruct(errMsg).ToBytes(), nil)
		return
	}

	// Complie regular express
	hs := common.Headers{}
	if pathRegexp == nil {
		pathRegexp = regexp.MustCompile(pathRegexpRule)
	}

	// Get authorization in header from request
	authType, auth, err := utility.ParserJWTToken(
		func() (string, error) {
			return kong.Request.GetHeader("Authorization")
		}, func() (string, error) {
			return kong.Request.GetHeader("X-API-KEY")
		}, func() (string, error) {
			return kong.Request.GetHeader("Cookie")
		}, &utility.ParserJWTTokenConfig{
			Token: conf.TokenKeyInCookie,
		})
	if err != nil {
		if conf.RedirectURL != "" {
			for _, t := range conf.RedirectTypes {
				if t == authType {
					kong.Response.SetHeader("Location", conf.RedirectURL)
					kong.Response.ExitStatus(http.StatusFound)
					return
				}
			}
		}
		errMsg := fmt.Sprintf("Get authorization from request error occurred: %s", err.Error())
		kong.Log.Err(errMsg)
		kong.Response.Exit(http.StatusBadRequest, common.NewErrorStruct(errMsg).ToBytes(), nil)
		return
	}
	// Decode authorization and gain uid
	verification, err := handler.VerifyToken(&pb.VerifyTokenInput{
		Token: auth,
	})
	if err != nil {
		if conf.RedirectURL != "" {
			for _, t := range conf.RedirectTypes {
				if t == authType {
					kong.Response.SetHeader("Location", conf.RedirectURL)
					kong.Response.ExitStatus(http.StatusFound)
					return
				}
			}
		}
		errMsg := fmt.Sprintf("Verify Token error occurred: %s(%s)", err.Error(), authType)
		kong.Log.Err(errMsg)
		kong.Response.Exit(http.StatusBadRequest, common.NewErrorStruct(errMsg).ToBytes(), nil)
		return
	}
	hs.SetSAATUserID(verification.SAATUserID)

	// Get user information from iam server via iam client
	userInfo, err := handler.GetUser(&pb.UserID{
		ID: verification.User.ID,
	})
	if err != nil {
		errMsg := fmt.Sprintf("Get user from iam server error occurred: %s", err.Error())
		kong.Log.Err(errMsg)
		kong.Response.Exit(http.StatusInternalServerError, common.NewErrorStruct(errMsg).ToBytes(), nil)
		return
	}
	// Check user is NOT frozen (Frozen user can't not be admin or system)
	if userInfo.Frozen {
		errMsg := "The user has been Frozen. Please contact administrator"
		kong.Log.Err(errMsg)
		kong.Response.Exit(http.StatusBadRequest, common.NewErrorStruct(errMsg).ToBytes(), nil)
		return
	}
	// If EnableURLEncode is enabled
	// User's DisplayName will be encoded
	if conf.EnableURLEncode {
		userInfo.DisplayName = strings.Replace(url.QueryEscape(userInfo.DisplayName), "+", "%20", -1)
	}
	hs.SetUserInfo(userInfo)
	isSystemAdmin, err := isSystemAdmin(handler, userInfo.ID)
	hs.SetSystemAdmin(isSystemAdmin)
	if err != nil {
		errMsg := fmt.Sprintf("Identify system administrator error occurred: %s", err.Error())
		kong.Log.Err(errMsg)
		kong.Response.Exit(http.StatusInternalServerError, common.NewErrorStruct(errMsg).ToBytes(), nil)
		return
	}

	var pid string
	if val, err := kong.Request.GetHeader(xIAMProjectIDKey); err == nil {
		pid = val
	}

	// Get path in URL
	path, err := kong.Request.GetPathWithQuery()
	if err != nil {
		errMsg := fmt.Sprintf("Get path from request error occurred: %s", err.Error())
		kong.Log.Err(errMsg)
		kong.Response.Exit(http.StatusInternalServerError, common.NewErrorStruct(errMsg).ToBytes(), nil)
		return
	}
	matches := pathRegexp.FindStringSubmatch(path)
	if len(matches) != 0 {
		for i, name := range pathRegexp.SubexpNames() {
			if i > 0 && i <= len(matches) {
				switch name {
				case "UUID":
					pid = matches[i]
				}
			}
		}
	}

	if pid != "" {
		projectInfo, err := handler.GetProject(&pb.ProjectID{
			ID: pid,
		})
		if err != nil {
			errMsg := fmt.Sprintf("Get path from request error occurred: %s", err.Error())
			kong.Log.Err(errMsg)
			kong.Response.Exit(http.StatusInternalServerError, common.NewErrorStruct(errMsg).ToBytes(), nil)
			return
		}
		if projectInfo.ID == "" {
			errMsg := fmt.Sprintf("The project does not exist with pid %s", pid)
			kong.Log.Err(errMsg)
			kong.Response.Exit(http.StatusInternalServerError, common.NewErrorStruct(errMsg).ToBytes(), nil)
			return
		}
		hs.SetProjectInfo(projectInfo)
		membershipInfo, err := handler.GetMembership(&pb.MemUserProjectInput{
			UserID:    userInfo.ID,
			ProjectID: pid,
		})
		if err != nil {
			cErr, ok := errors.IsError(err)
			switch {
			case ok && cErr.Code() == cCon.GRPCMembershipDoesNotExistErrCode:
				break
			default:
				errMsg := fmt.Sprintf("Get membership from iam server error occurred: %s", err.Error())
				kong.Log.Err(errMsg)
				kong.Response.Exit(http.StatusInternalServerError, common.NewErrorStruct(errMsg).ToBytes(), nil)
				return
			}
		}
		if membershipInfo != nil {
			hs.SetMembershipInfo(membershipInfo)
		} else {
			hs.SetMembershipInfo(&pb.MembershipInfo{})
		}

		if hs.GetSystemAdmin() {
			// tenantRole is assigned to "SYSTEM_ADMIN" if admin operates project without membership
			if hs.GetMembershipInfo().ID == "" {
				hs.GetMembershipInfo().TenantRole = systemAdmin
			}
		} else {
			if hs.GetMembershipInfo().ID == "" {
				errMsg := fmt.Sprintf("The membership does not exist with uid %s and pid %s", userInfo.ID, pid)
				kong.Log.Err(errMsg)
				kong.Response.Exit(http.StatusForbidden, common.NewErrorStruct(errMsg).ToBytes(), nil)
				return
			}
			if hs.GetMembershipInfo().Frozen {
				errMsg := "The membership has been Frozen. Please contact administrator"
				kong.Log.Err(errMsg)
				kong.Response.Exit(http.StatusBadRequest, common.NewErrorStruct(errMsg).ToBytes(), nil)
				return
			}
			if hs.GetProjectInfo().Frozen {
				errMsg := "The project has been Frozen. Please contact administrator"
				kong.Log.Err(errMsg)
				kong.Response.Exit(http.StatusBadRequest, common.NewErrorStruct(errMsg).ToBytes(), nil)
				return
			}
		}

		// If EnableURLEncode is enabled
		// DisplayName of project will be encoded
		if conf.EnableURLEncode {
			hs.GetProjectInfo().DisplayName = strings.Replace(url.QueryEscape(hs.GetProjectInfo().DisplayName), "+", "%20", -1)
		}
	}

	// if plugin enable permission validate
	if conf.EnablePermissionValidate {
		// call permission validate function
		if pass, validateErr := validatePermission(hs, kong, handler, conf.VerifiedService); validateErr != nil {
			errMsg := validateErr.Message
			kong.Log.Err(errMsg)
			kong.Response.Exit(http.StatusInternalServerError, validateErr.ToBytes(), nil)
			return
		} else if !pass {
			errMsg := "permission denied"
			kong.Log.Err(errMsg)
			kong.Response.Exit(http.StatusForbidden, common.NewErrorStruct(errMsg).ToBytes(), nil)
			return
		}
	}

	if err := response(hs, kong, conf.EnableRawHeader, conf.EnableJSONHeader); err != nil {
		kong.Response.Exit(http.StatusInternalServerError, common.NewErrorStruct(err.Error()).ToBytes(), nil)
		return
	}
}

func response(input common.Headers, kong *pdk.PDK, enableRawHeader, enableJSONHeader bool) (err error) {
	input.SetHeader(kong, systemAdminKey, fmt.Sprintf("%t", input.GetSystemAdmin()))
	if enableRawHeader {
		err = addRawHeaders(input, kong)
	}
	if enableJSONHeader {
		err = addJSONHeaders(input, kong)
	}
	input.PrintHeaders(kong)
	return
}

func addRawHeaders(input common.Headers, kong *pdk.PDK) (err error) {
	if input.GetUserInfo() != nil {
		for key, value := range map[string]string{
			userIDKey:      input.GetUserInfo().ID,
			userNameKey:    input.GetUserInfo().DisplayName,
			userAccountKey: input.GetUserInfo().Account,
			userEmailKey:   input.GetUserInfo().Email,
		} {
			input.SetHeader(kong, key, value)
		}
		extra := map[string]interface{}{}
		json.Unmarshal(input.GetUserInfo().Extra, &extra)
		input.SetHeaders(kong, utility.FlattenMapToHttpHeader(extra, "User-Extra"))
	}
	if input.GetMembershipInfo() != nil {
		roleNumber, err := convertRole(input.GetMembershipInfo().TenantRole)
		if err != nil {
			return err
		}
		for key, value := range map[string]string{
			userRoleKey:       input.GetMembershipInfo().TenantRole,
			userRoleNumberKey: strconv.Itoa(roleNumber),
		} {
			input.SetHeader(kong, key, value)
		}
		extra := map[string]interface{}{}
		json.Unmarshal(input.GetMembershipInfo().Extra, &extra)
		input.SetHeaders(kong, utility.FlattenMapToHttpHeader(extra, "Member-Extra"))
	}
	if input.GetProjectInfo() != nil {
		projectActive := "false"
		if !input.GetProjectInfo().Frozen {
			projectActive = "true"
		}
		for key, value := range map[string]string{
			projectIDKey:        input.GetProjectInfo().ID,
			projectNameKey:      input.GetProjectInfo().DisplayName,
			projectNamespaceKey: input.GetProjectInfo().Namespace,
			projectActiveKey:    projectActive,
		} {
			input.SetHeader(kong, key, value)
		}
		extra := map[string]interface{}{}
		json.Unmarshal(input.GetProjectInfo().Extra, &extra)
		input.SetHeaders(kong, utility.FlattenMapToHttpHeader(extra, "Project-Extra"))
	}
	input.SetHeader(kong, saatUserIDKey, input.GetSAATUserID())
	return nil
}

func addJSONHeaders(input common.Headers, kong *pdk.PDK) (err error) {
	jsonHs := Header{}
	if input.GetUserInfo() != nil {
		jsonHs.User = &User{
			ID:    input.GetUserInfo().ID,
			Name:  input.GetUserInfo().DisplayName,
			Email: input.GetUserInfo().Account,
		}
	}
	if input.GetMembershipInfo() != nil {
		roleNumber, err := convertRole(input.GetMembershipInfo().TenantRole)
		if err != nil {
			return err
		}
		jsonHs.User.Role = input.GetMembershipInfo().TenantRole
		jsonHs.User.RoleNumber = roleNumber
	}
	if input.GetProjectInfo() != nil {
		jsonHs.Project = &Project{
			ID:        input.GetProjectInfo().ID,
			Name:      input.GetProjectInfo().DisplayName,
			Namespace: input.GetProjectInfo().Namespace,
			Active:    !input.GetProjectInfo().Frozen,
		}
	}
	bheaders, err := json.Marshal(jsonHs)
	if err != nil {
		return err
	}
	input.SetHeader(kong, jsonOutputKey, string(bheaders))
	return nil
}

func isSystemAdmin(handler *iam.PoolHandler, userID string) (yes bool, err error) {
	// Get membership information by UserID and admin project ID
	// If membership ID is't empty, it should be a administrator
	// otherwise, it's a general user
	adminProjectInfo, err := handler.GetAdminProject()
	if err != nil {
		return false, err
	}
	_, err = handler.GetMembership(&pb.MemUserProjectInput{
		UserID:    userID,
		ProjectID: adminProjectInfo.ID,
	})
	if err != nil {
		cErr, ok := errors.IsError(err)
		switch {
		case ok && cErr.Code() == cCon.GRPCMembershipDoesNotExistErrCode:
			return false, nil
		case ok:
			return false, cErr
		default:
			return false, err
		}
	}
	return true, nil
}

func validatePermission(input common.Headers, kong *pdk.PDK, handler *iam.PoolHandler, service string) (result bool, err *common.ErrorStruct) {
	projectID := ""
	if input.GetProjectInfo() != nil {
		projectID = input.GetProjectInfo().ID
	}
	// get the request method
	method, getMethodErr := kong.Request.GetMethod()
	if getMethodErr != nil {
		err = &common.ErrorStruct{
			Message: fmt.Sprintf("Get kong request method error occurred: %s", getMethodErr.Error()),
		}

		return
	}
	// get request path
	path, getPathErr := kong.Request.GetPathWithQuery()
	if getPathErr != nil {
		err = &common.ErrorStruct{
			Message: fmt.Sprintf("Get path from request error occurred: %s", getPathErr.Error()),
		}
		return
	}
	// init the permissionValidate request input
	// Action pattern ex: iam-service:GET:/iam/api/v1/projects
	permissionValidateInput := &pb.PermissionValidateInput{
		ProjectID: projectID,
		UserID:    input.GetUserInfo().ID,
		Service:   service,
		Action:    fmt.Sprintf("%s:%s:%s", service, method, path),
		Skip:      _skipResource,
	}
	// add debug log
	kong.Log.Debug(fmt.Printf("permissionValidateInput %v", permissionValidateInput))
	// call iam grpc PermissionValidate
	pass, PermissionValidateErr := handler.PermissionValidate(permissionValidateInput)
	if PermissionValidateErr != nil {
		err = &common.ErrorStruct{
			Message: fmt.Sprintf("PermissionValidate error occurred: %s", PermissionValidateErr.Error()),
		}

		return
	}
	// if the permission validate not pass
	if !*pass.Val {
		return
	}

	result = true
	return
}
