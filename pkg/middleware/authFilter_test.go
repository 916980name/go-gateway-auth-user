package middleware

import "testing"

func TestCheckPrivileges(t *testing.T) {
	for _, tt := range [...]struct {
		name            string
		routePrivileges string
		verifiedPayload map[string]interface{}
		result          bool
	}{
		{
			name:            "should pass when check privilege given user have one route privilege",
			routePrivileges: "user, admin, pri1, pri2",
			verifiedPayload: map[string]interface{}{"privileges": "pri1, other"},
			result:          true,
		},
		{
			name:            "should pass when check privilege given user have many route privilege",
			routePrivileges: "user, admin, pri1, pri2",
			verifiedPayload: map[string]interface{}{"privileges": "pri1, user, admin"},
			result:          true,
		},
		{
			name:            "should not pass when check privilege given user do not have any privilege",
			routePrivileges: "user, admin, pri1, pri2",
			verifiedPayload: map[string]interface{}{"no-p-here": ""},
			result:          false,
		},
		{
			name:            "should not pass when check privilege given user do not have any route privilege",
			routePrivileges: "user, admin, pri1, pri2",
			verifiedPayload: map[string]interface{}{"privileges": "other1, other2, other3"},
			result:          false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pass, _ := checkPrivileges(tt.routePrivileges, tt.verifiedPayload)
			if pass != tt.result {
				t.Errorf("expect: %v, got: %v", tt.result, pass)
			}
		})
	}

}
