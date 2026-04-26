package proxy

import (
	"api-gateway/pkg/common"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type trackCloser struct {
	io.Reader
	closed bool
}

func (tc *trackCloser) Close() error {
	tc.closed = true
	return nil
}

func TestHandleProxyResponse_Success(t *testing.T) {
	body := "response body content"
	w := httptest.NewRecorder()
	crw := NewCustomResponseWriter(w)
	r := httptest.NewRequest("GET", "/test", nil)

	mockProxy := func(ctx context.Context, req *http.Request) (context.Context, *http.Response, error) {
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"X-Custom": {"value1"}},
			Body:       io.NopCloser(bytes.NewBufferString(body)),
		}
		return ctx, resp, nil
	}

	HandleProxyResponse(context.Background(), crw, r, mockProxy)

	if crw.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", crw.StatusCode, http.StatusOK)
	}
	if w.Header().Get("X-Custom") != "value1" {
		t.Errorf("header X-Custom = %q, want %q", w.Header().Get("X-Custom"), "value1")
	}
	if w.Body.String() != body {
		t.Errorf("body = %q, want %q", w.Body.String(), body)
	}
}

func TestHandleProxyResponse_HTTPError(t *testing.T) {
	w := httptest.NewRecorder()
	crw := NewCustomResponseWriter(w)
	r := httptest.NewRequest("GET", "/test", nil)

	mockProxy := func(ctx context.Context, req *http.Request) (context.Context, *http.Response, error) {
		return ctx, nil, common.NewHTTPError("Forbidden", http.StatusForbidden)
	}

	HandleProxyResponse(context.Background(), crw, r, mockProxy)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestHandleProxyResponse_GenericError(t *testing.T) {
	w := httptest.NewRecorder()
	crw := NewCustomResponseWriter(w)
	r := httptest.NewRequest("GET", "/test", nil)

	mockProxy := func(ctx context.Context, req *http.Request) (context.Context, *http.Response, error) {
		return ctx, nil, errors.New("something failed")
	}

	HandleProxyResponse(context.Background(), crw, r, mockProxy)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

func TestHandleProxyResponse_BodyClosed(t *testing.T) {
	tc := &trackCloser{Reader: bytes.NewBufferString("data")}
	w := httptest.NewRecorder()
	crw := NewCustomResponseWriter(w)
	r := httptest.NewRequest("GET", "/test", nil)

	mockProxy := func(ctx context.Context, req *http.Request) (context.Context, *http.Response, error) {
		return ctx, &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{},
			Body:       tc,
		}, nil
	}

	HandleProxyResponse(context.Background(), crw, r, mockProxy)

	if !tc.closed {
		t.Error("response body was not closed")
	}
}

func TestCustomResponseWriter_WriteHeader(t *testing.T) {
	w := httptest.NewRecorder()
	crw := NewCustomResponseWriter(w)

	if crw.StatusCode != http.StatusBadGateway {
		t.Errorf("initial status = %d, want %d", crw.StatusCode, http.StatusBadGateway)
	}

	crw.WriteHeader(http.StatusNotFound)
	if crw.StatusCode != http.StatusNotFound {
		t.Errorf("status after WriteHeader = %d, want %d", crw.StatusCode, http.StatusNotFound)
	}
}
