package proxy

import (
	"api-gateway/pkg/common"
	"api-gateway/pkg/log"
	"context"
	"io"
	"net/http"
)

var defaultHTTPClient = &http.Client{}

type Proxy func(ctx context.Context, request *http.Request) (context.Context, *http.Response, error)
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
	return func(ctx context.Context, r *http.Request) (context.Context, *http.Response, error) {
		r.URL.Host = backend
		r.RequestURI = ""
		r.URL.Scheme = "http"
		ctx = addTraceHeader(ctx, r)
		// https://stackoverflow.com/a/19006050/8936864
		r.Close = true
		resp, err := defaultHTTPClient.Do(r.WithContext(ctx))

		select {
		case <-ctx.Done():
			return ctx, nil, ctx.Err()
		default:
		}
		if err != nil {
			return ctx, nil, err
		}
		log.C(ctx).Infow("proxy response", "code", resp.StatusCode)

		return ctx, resp, err
	}
	// https://stackoverflow.com/questions/34724160/go-http-send-incoming-http-request-to-an-other-server-using-client-do
}

func addTraceHeader(ctx context.Context, r *http.Request) context.Context {
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
	if timezone := ctx.Value(common.Trace_request_timezone{}); timezone != nil {
		if str, ok := timezone.(string); ok {
			r.Header.Add(common.REQUEST_TIMEZONE, str)
		}
	}
	return ctx
}

func HandleProxyResponse(ctx context.Context, w *CustomResponseWriter, r *http.Request, p Proxy) context.Context {
	ctx, resp, err := p(ctx, r)
	if err != nil {
		if herr, ok := err.(*common.HTTPError); ok {
			http.Error(w, herr.Msg, herr.Status)
			return ctx
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return ctx
		}
	}
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
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		http.Error(w.ResponseWriter, err.Error(), http.StatusInternalServerError)
		return ctx
	}
	return ctx
}
