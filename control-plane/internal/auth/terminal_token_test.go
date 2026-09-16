package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const terminalTestSecret = "0123456789abcdef0123456789abcdef"

func terminalClaims(sandboxID, sub string, exp time.Time) map[string]any {
	return map[string]any{
		"iss":        "appgu",
		"iat":        time.Now().Add(-time.Minute).Unix(),
		"exp":        exp.Unix(),
		"aud":        TerminalAudience,
		"sub":        sub,
		"sandbox_id": sandboxID,
	}
}

func TestVerifyTerminalToken(t *testing.T) {
	secrets := map[string]string{"v1": terminalTestSecret}
	good := signHS256(t, "v1", terminalTestSecret,
		terminalClaims("sb1", "user-alice", time.Now().Add(15*time.Minute)))

	c, err := VerifyTerminalToken(good, secrets, time.Now())
	if err != nil {
		t.Fatalf("want valid, got err %v", err)
	}
	if c.SandboxID != "sb1" || c.Sub != "user-alice" || c.Kid != "v1" {
		t.Fatalf("unexpected claims: %+v", c)
	}

	// A preview token must never verify as a terminal token (aud
	// separation), and vice versa.
	preview := signHS256(t, "v1", terminalTestSecret,
		claims("sb1", "user-alice", time.Now().Add(time.Hour)))
	if _, err := VerifyTerminalToken(preview, secrets, time.Now()); err != ErrTokenBadAud {
		t.Errorf("preview aud on terminal path: want ErrTokenBadAud, got %v", err)
	}
	if _, err := VerifyPreviewToken(good, secrets, time.Now()); err != ErrTokenBadAud {
		t.Errorf("terminal aud on preview path: want ErrTokenBadAud, got %v", err)
	}

	expired := signHS256(t, "v1", terminalTestSecret,
		terminalClaims("sb1", "user-alice", time.Now().Add(-time.Minute)))
	if _, err := VerifyTerminalToken(expired, secrets, time.Now()); err != ErrTokenExpired {
		t.Errorf("expired: want ErrTokenExpired, got %v", err)
	}

	wrongSecret := signHS256(t, "v1", "wrong-secret",
		terminalClaims("sb1", "user-alice", time.Now().Add(15*time.Minute)))
	if _, err := VerifyTerminalToken(wrongSecret, secrets, time.Now()); err != ErrTokenBadSig {
		t.Errorf("wrong secret: want ErrTokenBadSig, got %v", err)
	}
}

func TestTerminalAccess_BindsSandboxID(t *testing.T) {
	secrets := map[string]string{"v1": terminalTestSecret}
	tok := signHS256(t, "v1", terminalTestSecret,
		terminalClaims("sb1", "user-alice", time.Now().Add(15*time.Minute)))

	if _, ok := TerminalAccess(tok, "/v1/sandboxes/sb1/terminal", secrets, time.Now()); !ok {
		t.Errorf("matching sandbox id must allow access")
	}
	if _, ok := TerminalAccess(tok, "/v1/sandboxes/sb2/terminal", secrets, time.Now()); ok {
		t.Errorf("token for sb1 must not open sb2's terminal")
	}
	if _, ok := TerminalAccess(tok, "/v1/sandboxes/sb1/terminal/extra", secrets, time.Now()); ok {
		t.Errorf("non-terminal path shape must not allow access")
	}
	if _, ok := TerminalAccess("", "/v1/sandboxes/sb1/terminal", secrets, time.Now()); ok {
		t.Errorf("empty token must not allow access")
	}
}

func TestTerminalQueryTokenJWT(t *testing.T) {
	mw := NewMiddleware(&Config{
		APITokens:      []NamedToken{{Name: "appgu", Token: "s3cr3t"}},
		PreviewSecrets: map[string]string{"v1": terminalTestSecret},
	}, nil, nil)

	var got Actor
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = ActorFrom(r.Context())
		w.WriteHeader(http.StatusNoContent)
	})
	h := mw.Wrap(next)

	mint := func(sandboxID, sub string, exp time.Time) string {
		return signHS256(t, "v1", terminalTestSecret, terminalClaims(sandboxID, sub, exp))
	}
	future := time.Now().Add(15 * time.Minute)
	previewTok := signHS256(t, "v1", terminalTestSecret,
		claims("sb1", "user-alice", time.Now().Add(time.Hour)))

	cases := []struct {
		name string
		url  string
		want int
	}{
		{"jwt ok", "/v1/sandboxes/sb1/terminal?token=" + mint("sb1", "user-alice", future), http.StatusNoContent},
		{"jwt wrong sandbox", "/v1/sandboxes/sb2/terminal?token=" + mint("sb1", "user-alice", future), http.StatusUnauthorized},
		{"jwt expired", "/v1/sandboxes/sb1/terminal?token=" + mint("sb1", "user-alice", time.Now().Add(-time.Minute)), http.StatusUnauthorized},
		{"jwt garbage", "/v1/sandboxes/sb1/terminal?token=not.a.jwt", http.StatusUnauthorized},
		{"preview token rejected", "/v1/sandboxes/sb1/terminal?token=" + previewTok, http.StatusUnauthorized},
		{"jwt ignored off-path", "/v1/sandboxes?token=" + mint("sb1", "user-alice", future), http.StatusUnauthorized},
		{"service token still works", "/v1/sandboxes/sb1/terminal?token=s3cr3t", http.StatusNoContent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got = Actor{}
			r := httptest.NewRequest(http.MethodGet, tc.url, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			if rec.Code != tc.want {
				t.Fatalf("code = %d, want %d", rec.Code, tc.want)
			}
			if tc.name == "jwt ok" && (got.Kind != "terminal" || got.Name != "user-alice") {
				t.Errorf("actor = %+v, want terminal/user-alice", got)
			}
		})
	}
}
