package rbac

import "testing"

func TestFirstSchemaFromPostgresDSN(t *testing.T) {
	tests := []struct {
		dsn  string
		want string
	}{
		{"postgres://u:p@h:5432/db?search_path=gateway-test1", "gateway-test1"},
		{"postgres://u:p@h:5432/db?search_path=gateway-test1%2Cpublic", "gateway-test1"},
		{"postgresql://u:p@h/db?sslmode=disable&search_path=a,b", "a"},
		{"host=h user=u dbname=d search_path=myschema", "myschema"},
		{"host=h user=u dbname=d search_path=\"s1,s2\"", "s1"},
		{"postgres://u:p@h/db", ""},
		{"", ""},
	}
	for _, tt := range tests {
		if got := firstSchemaFromPostgresDSN(tt.dsn); got != tt.want {
			t.Errorf("firstSchemaFromPostgresDSN(%q) = %q, want %q", tt.dsn, got, tt.want)
		}
	}
}

func TestConfigApplyDefaultsSchema(t *testing.T) {
	c := Config{
		DB: DBConfig{
			DSN: "postgres://x:y@localhost/db?search_path=app",
		},
	}
	c.ApplyDefaults()
	if c.DB.Schema != "app" {
		t.Fatalf("schema = %q, want app", c.DB.Schema)
	}

	c2 := Config{DB: DBConfig{DSN: "postgres://x:y@localhost/db"}}
	c2.ApplyDefaults()
	if c2.DB.Schema != "public" {
		t.Fatalf("schema = %q, want public", c2.DB.Schema)
	}

	c3 := Config{DB: DBConfig{DSN: "postgres://x:y@localhost/db?search_path=x", Schema: "explicit"}}
	c3.ApplyDefaults()
	if c3.DB.Schema != "explicit" {
		t.Fatalf("schema = %q, want explicit", c3.DB.Schema)
	}
}
