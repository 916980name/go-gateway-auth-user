package util

import (
	"net/http"
	"time"
)

func ResponseSetRootCookie(resp *http.Response, name string, value string, timeout *time.Time) {
	cookie := &http.Cookie{
		Name:  name,
		Value: value,
		Path:  "/",
	}
	if timeout != nil {
		cookie.Expires = *timeout
	}
	if v := cookie.String(); v != "" {
		// http.SetCookie also hardcode this
		resp.Header.Add("Set-Cookie", v)
	}
}
