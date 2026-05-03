package rbac

import (
	"net/url"
	"strings"
)

func SchemaFromDSN(dsn string) string {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return "public"
	}
	if u, err := url.Parse(dsn); err == nil && u.Scheme != "" &&
		(u.Scheme == "postgres" || u.Scheme == "postgresql") {
		if q := strings.TrimSpace(u.Query().Get("search_path")); q != "" {
			return strings.TrimSpace(strings.Split(q, ",")[0])
		}
	}
	for _, tok := range strings.Fields(dsn) {
		const p = "search_path="
		if strings.HasPrefix(tok, p) {
			v := strings.Trim(strings.TrimPrefix(tok, p), `"'`)
			if v != "" {
				return strings.TrimSpace(strings.Split(v, ",")[0])
			}
		}
	}
	return "public"
}
