package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Zillaforge/pegasusiamclient/iam"
)

const (
	systemAdmin  = "SYSTEM_ADMIN"
	tenantOwner  = "TENANT_OWNER"
	tenantAdmin  = "TENANT_ADMIN"
	tenantMember = "TENANT_MEMBER"

	connPerHost = 20
)

var poolMap = make(map[string]*iam.PoolHandler)

func newPool(hosts []string) (err error) {
	poolKey := convertPoolKey(hosts)
	if _, ok := poolMap[poolKey]; !ok {
		poolHandler, err := iam.New(iam.PoolProvider{
			TCPProvider: iam.TCPProvider{
				Hosts:       hosts,
				ConnPerHost: connPerHost,
			},
		})
		if err != nil {
			return err
		}
		poolMap[poolKey] = poolHandler
		fmt.Println("===============")
		fmt.Println("Createing a new PoolProvider: ")
		fmt.Printf("Pool Key: %s\n", poolKey)
		fmt.Printf("Pool Value: %+v\n", poolHandler)
		fmt.Printf("Connections Per Host: %d\n", connPerHost)
		fmt.Println("===============")
	} else {
		fmt.Printf("PoolProvider(%s) is exist\n", poolKey)
	}
	fmt.Printf("PoolMap: %+v\n", poolMap)
	fmt.Printf("To access IAM Server by using %s\n", poolKey)
	return nil
}

func convertPoolKey(hosts []string) (name string) {
	return strings.Join(hosts, ",")
}

func convertRole(role string) (roleNumber int, err error) {
	switch role {
	case systemAdmin:
		roleNumber, err = 16, nil
	case tenantOwner:
		roleNumber, err = 8, nil
	case tenantAdmin:
		roleNumber, err = 4, nil
	case tenantMember:
		roleNumber, err = 2, nil
	default:
		roleNumber, err = 0, errors.New("role should not be converted to role number, please check your role again")
	}
	return roleNumber, err
}
