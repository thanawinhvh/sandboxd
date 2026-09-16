package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// terminalTestMiddleware builds auth with one service token.
func terminalTestMiddleware() *Middleware {
	return NewMiddleware(&Config{
		APITokens: []NamedToken{{Name: "appgu", Token: "s3cr3t"}},
	}, nil, nil)
}

func TestTerminalQueryToken(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a := ActorFrom(r.Context())
		if a.Kind != "service" || a.Name != "appgu" {
			t.Errorf("actor = %+v, want service/appgu", a)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	h := terminalTestMiddleware().Wrap(next)

	cases := []struct {
		name string
		url  string
		hdr  string // Authorization header, "" = none
		want int
	}{
		{"query token ok", "/v1/sandboxes/abc/terminal?token=s3cr3t", "", http.StatusNoContent},
		{"query token wrong", "/v1/sandboxes/abc/terminal?token=nope", "", http.StatusUnauthorized},
		{"query token missing", "/v1/sandboxes/abc/terminal", "", http.StatusUnauthorized},
		{"query token ignored off-path", "/v1/sandboxes?token=s3cr3t", "", http.StatusUnauthorized},
		{"bearer still works", "/v1/sandboxes/abc/terminal", "Bearer s3cr3t", http.StatusNoContent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// httptest.NewRequest is non-loopback (192.0.2.1),
			// so the external/token path is exercised.
			r := httptest.NewRequest(http.MethodGet, tc.url, nil)
			if tc.hdr != "" {
				r.Header.Set("Authorization", tc.hdr)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			if rec.Code != tc.want {
				t.Fatalf("code = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}
