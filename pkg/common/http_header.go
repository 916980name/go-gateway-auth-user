package common

type Trace_request_id struct{}
type Trace_request_user struct{}
type Trace_request_uri struct{}
type Trace_request_method struct{}
type Trace_request_timezone struct{}
type Trace_request_ip struct{}

const (
	REQUEST_ID       = "R-ID"
	REQUEST_USER     = "R-USER"
	REQUEST_URI      = "R-URI"
	REQUEST_METHOD   = "R-METHOD"
	REQUEST_TIMEZONE = "R-TZ"
	RESOURCE_IP      = "R-IP"
)
