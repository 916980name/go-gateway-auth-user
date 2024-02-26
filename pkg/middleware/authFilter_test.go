package middleware

import (
	"encoding/json"
	"testing"
)

func TestCheckPrivileges(t *testing.T) {
	for _, tt := range [...]struct {
		Name            string
		RoutePrivileges string
		VerifiedPayload map[string]interface{}
		Result          bool
	}{
		{
			Name:            "should pass when check privilege given user have one route privilege",
			RoutePrivileges: "user, admin, pri1, pri2",
			VerifiedPayload: map[string]interface{}{"privileges": "pri1, other"},
			Result:          true,
		},
		{
			Name:            "should pass when check privilege given user have many route privilege",
			RoutePrivileges: "user, admin, pri1, pri2",
			VerifiedPayload: map[string]interface{}{"privileges": "pri1, user, admin"},
			Result:          true,
		},
		{
			Name:            "should not pass when check privilege given user do not have any privilege",
			RoutePrivileges: "user, admin, pri1, pri2",
			VerifiedPayload: map[string]interface{}{"no-p-here": ""},
			Result:          false,
		},
		{
			Name:            "should not pass when check privilege given user do not have any route privilege",
			RoutePrivileges: "user, admin, pri1, pri2",
			VerifiedPayload: map[string]interface{}{"privileges": "other1, other2, other3"},
			Result:          false,
		},
	} {
		t.Run(tt.Name, func(t *testing.T) {
			b, _ := json.Marshal(tt.VerifiedPayload)
			userInfo := GeneralUserInfo{}
			json.Unmarshal(b, &userInfo)
			pass, _ := checkPrivileges(tt.RoutePrivileges, userInfo)
			if pass != tt.Result {
				t.Errorf("expect: %v, got: %v", tt.Result, pass)
			}
		})
	}

}
