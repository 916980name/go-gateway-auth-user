package proxy

import (
	"api-gateway/pkg/common"
	"api-gateway/pkg/log"
	"context"
	"io"
	"net/http"
)

var defaultHTTPClient = &http.Client{}

type Proxy func(ctx context.Context, request *http.Request) (*http.Response, error)
type Middleware func(next Proxy) Proxy

// https://stackoverflow.com/questions/53272536/how-do-i-get-response-statuscode-in-golang-middleware
// https://github.com/urfave/negroni/blob/master/response_writer.go
type CustomResponseWriter struct {
	http.ResponseWriter
	StatusCode int
	DataCopy   []byte
}

func NewCustomResponseWriter(w http.ResponseWriter) *CustomResponseWriter {
	return &CustomResponseWriter{w, http.StatusBadGateway, nil}
}

func (crw *CustomResponseWriter) WriteHeader(code int) {
	crw.StatusCode = code
	crw.ResponseWriter.WriteHeader(code)
}

func NewHTTPProxyDetailed(backend string) Proxy {
	return func(ctx context.Context, r *http.Request) (*http.Response, error) {
		r.URL.Host = backend
		r.RequestURI = ""
		r.URL.Scheme = "http"
		addTraceHeader(ctx, r)
		resp, err := defaultHTTPClient.Do(r.WithContext(ctx))

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		if err != nil {
			return nil, err
		}
		log.C(ctx).Infow("remote response", "code", resp.StatusCode)

		return resp, err
	}
	// https://stackoverflow.com/questions/34724160/go-http-send-incoming-http-request-to-an-other-server-using-client-do
}

func addTraceHeader(ctx context.Context, r *http.Request) {
	if requestID := ctx.Value(common.Trace_request_id{}); requestID != nil {
		if str, ok := requestID.(string); ok {
			r.Header.Add(common.REQUEST_ID, str)
		}
	}
	if resourceIP := ctx.Value(common.Trace_request_ip{}); resourceIP != nil {
		if str, ok := resourceIP.(string); ok {
			r.Header.Add(common.RESOURCE_IP, str)
		}
	}
	if requestUri := ctx.Value(common.Trace_request_uri{}); requestUri != nil {
		if str, ok := requestUri.(string); ok {
			r.Header.Add(common.REQUEST_URI, str)
		}
	}
	if method := ctx.Value(common.Trace_request_method{}); method != nil {
		if str, ok := method.(string); ok {
			r.Header.Add(common.REQUEST_METHOD, str)
		}
	}
	if user := ctx.Value(common.Trace_request_user{}); user != nil {
		if str, ok := user.(string); ok {
			r.Header.Add(common.REQUEST_USER, str)
		}
	}
	if userid := ctx.Value(common.Trace_request_uid{}); userid != nil {
		if str, ok := userid.(string); ok {
			r.Header.Add(common.REQUEST_UID, str)
		}
	}
	// TODO timezone
}

func HandleProxyResponse(ctx context.Context, resp *http.Response, w *CustomResponseWriter) {
	for k := range w.Header() {
		delete(w.Header(), k)
	}

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	// Copy the response body to the http.ResponseWriter
	_, err := io.Copy(w, resp.Body)
	if err != nil {
		http.Error(w.ResponseWriter, err.Error(), http.StatusInternalServerError)
		return
	}
}
