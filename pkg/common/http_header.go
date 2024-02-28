package common

import "fmt"

type Trace_request_id struct{}
type Trace_request_user struct{}
type Trace_request_uid struct{}
type Trace_request_uri struct{}
type Trace_request_method struct{}
type Trace_request_timezone struct{}
type Trace_request_ip struct{}
type Trace_request_domain struct{}

const (
	REQUEST_ID       = "R-ID"
	REQUEST_USER     = "R-USER"
	REQUEST_UID      = "R-UID"
	REQUEST_URI      = "R-URI"
	REQUEST_DOMAIN   = "R-DM"
	REQUEST_METHOD   = "R-METHOD"
	REQUEST_TIMEZONE = "R-TZ"
	RESOURCE_IP      = "R-IP"
)

type HTTPError struct {
	Msg    string
	Status int
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("%d %s", e.Status, e.Msg)
}

func NewHTTPError(msg string, status int) *HTTPError {
	return &HTTPError{
		Msg:    msg,
		Status: status,
	}
}
