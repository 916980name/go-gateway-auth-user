package recovery

import (
	"api-gateway/pkg/common"
	"api-gateway/pkg/proxy"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRecovery_PanicReturns500(t *testing.T) {
	panicProxy := func(ctx context.Context, r *http.Request) (context.Context, *http.Response, error) {
		panic("test panic")
	}
	m := Recovery()
	chain := m(panicProxy)

	r := httptest.NewRequest("GET", "/test", nil)
	_, _, err := chain(context.Background(), r)
	if err == nil {
		t.Fatal("expected error after panic, got nil")
	}
	herr, ok := err.(*common.HTTPError)
	if !ok {
		t.Fatalf("expected *common.HTTPError, got %T: %v", err, err)
	}
	if herr.Status != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", herr.Status, http.StatusInternalServerError)
	}
}

func TestRecovery_NoPanicPassesThrough(t *testing.T) {
	normalProxy := func(ctx context.Context, r *http.Request) (context.Context, *http.Response, error) {
		return ctx, &http.Response{StatusCode: 200}, nil
	}
	m := Recovery()
	chain := m(normalProxy)

	r := httptest.NewRequest("GET", "/test", nil)
	_, resp, err := chain(context.Background(), r)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if resp == nil || resp.StatusCode != 200 {
		t.Errorf("expected 200 response, got %v", resp)
	}
}

func TestRecovery_HandlerCalled(t *testing.T) {
	var handlerCalled bool
	var capturedErr interface{}

	panicProxy := func(ctx context.Context, r *http.Request) (context.Context, *http.Response, error) {
		panic("handler test")
	}
	m := Recovery(WithHandler(func(ctx context.Context, req *http.Request, err interface{}) {
		handlerCalled = true
		capturedErr = err
	}))
	chain := m(panicProxy)

	r := httptest.NewRequest("GET", "/test", nil)
	chain(context.Background(), r)

	if !handlerCalled {
		t.Error("expected handler to be called on panic")
	}
	if capturedErr != "handler test" {
		t.Errorf("handler received err = %v, want %q", capturedErr, "handler test")
	}
}

func TestRecovery_ErrorPassesThrough(t *testing.T) {
	errProxy := func(ctx context.Context, r *http.Request) (context.Context, *http.Response, error) {
		return ctx, nil, common.NewHTTPError("bad request", http.StatusBadRequest)
	}
	m := Recovery()
	chain := m(errProxy)

	r := httptest.NewRequest("GET", "/test", nil)
	_, _, err := chain(context.Background(), r)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	herr, ok := err.(*common.HTTPError)
	if !ok {
		t.Fatalf("expected *common.HTTPError, got %T", err)
	}
	if herr.Status != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", herr.Status, http.StatusBadRequest)
	}
}

var _ proxy.Proxy // ensure proxy import is used
