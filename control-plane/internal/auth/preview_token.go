package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// PreviewAudience is the required `aud` claim on a preview token.
const PreviewAudience = "sandbox-preview"

// TerminalAudience is the required `aud` claim on a terminal token —
// the short-lived upstream-signed JWT a browser presents as
// `?token=` on GET /v1/sandboxes/{id}/terminal. Same kid/secret
// registry as preview tokens (SANDBOXD_PREVIEW_TOKEN_SECRETS); the
// `aud` separates the two capabilities, so a preview token can never
// open a terminal and vice versa.
const TerminalAudience = "sandbox-terminal"

// Verification errors. CheckPreviewAccess buckets these into the
// machine-readable forward-auth denial reasons.
var (
	ErrTokenMalformed  = errors.New("token malformed")
	ErrTokenBadAlg     = errors.New("token alg is not HS256")
	ErrTokenUnknownKid = errors.New("token kid not configured")
	ErrTokenBadSig     = errors.New("token signature invalid")
	ErrTokenExpired    = errors.New("token expired")
	ErrTokenBadAud     = errors.New("token aud mismatch")
)

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// PreviewClaims is the validated payload of an upstream-signed preview
// token (roadmap §7). sandboxd verifies the signature, exp and aud; it
// does not check `sub` beyond presence — the upstream has already
// decided this viewer may see this sandbox.
type PreviewClaims struct {
	Iss       string `json:"iss"`
	Iat       int64  `json:"iat"`
	Exp       int64  `json:"exp"`
	Aud       string `json:"aud"`
	Sub       string `json:"sub"`
	SandboxID string `json:"sandbox_id"`
	Kid       string `json:"-"` // copied from the JWS header
}

// TerminalClaims is the validated payload of an upstream-signed
// terminal token. Same wire shape as PreviewClaims; only the `aud`
// differs (TerminalAudience), enforced by VerifyTerminalToken.
type TerminalClaims = PreviewClaims

// VerifyPreviewToken parses and verifies an HS256 JWS. `secrets` maps
// the `kid` header to the shared HMAC secret; `now` is the reference
// time for the `exp` check. The token format is the standard compact
// JWS (`header.payload.signature`, each base64url, no padding).
func VerifyPreviewToken(token string, secrets map[string]string, now time.Time) (*PreviewClaims, error) {
	return verifyToken(token, secrets, now, PreviewAudience)
}

// VerifyTerminalToken parses and verifies an upstream-signed terminal
// token: same compact JWS and kid/secret registry as preview tokens,
// but requiring TerminalAudience. It does NOT check that the token's
// sandbox_id matches the request path — the caller (TerminalAccess)
// does that, since only it knows the path.
func VerifyTerminalToken(token string, secrets map[string]string, now time.Time) (*TerminalClaims, error) {
	return verifyToken(token, secrets, now, TerminalAudience)
}

// verifyToken is the shared HS256 JWS core behind both audiences.
func verifyToken(token string, secrets map[string]string, now time.Time, audience string) (*PreviewClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrTokenMalformed
	}
	hdrRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrTokenMalformed
	}
	var hdr jwtHeader
	if err := json.Unmarshal(hdrRaw, &hdr); err != nil {
		return nil, ErrTokenMalformed
	}
	if !strings.EqualFold(hdr.Alg, "HS256") {
		return nil, ErrTokenBadAlg
	}
	secret, ok := secrets[hdr.Kid]
	if !ok || secret == "" {
		return nil, ErrTokenUnknownKid
	}

	// Recompute HMAC-SHA256 over the signing input and constant-time
	// compare against the presented signature.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	want := mac.Sum(nil)
	got, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrTokenMalformed
	}
	if subtle.ConstantTimeCompare(want, got) != 1 {
		return nil, ErrTokenBadSig
	}

	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrTokenMalformed
	}
	var c PreviewClaims
	if err := json.Unmarshal(payloadRaw, &c); err != nil {
		return nil, ErrTokenMalformed
	}
	c.Kid = hdr.Kid
	if c.Aud != audience {
		return nil, ErrTokenBadAud
	}
	if c.Exp <= now.Unix() {
		return nil, ErrTokenExpired
	}
	return &c, nil
}

// CheckPreviewAccess is the shared access decision used by both
// GET /forward-auth and the private-sandbox wake path. It returns the
// validated claims and "" when access is allowed, or nil and a
// machine-readable denial reason (one of: no_cookie, bad_signature,
// expired, wrong_sandbox, wrong_user — roadmap §8).
//
// ownerExternalUserID is workspace_owner.external_user_id for the
// sandbox; an empty string skips the owner check (used when the owner
// row is absent, e.g. an un-backfilled legacy private sandbox — the
// signature + sandbox-id checks still apply).
func CheckPreviewAccess(cookieVal, sandboxID, ownerExternalUserID string, secrets map[string]string, now time.Time) (*PreviewClaims, string) {
	if cookieVal == "" {
		return nil, "no_cookie"
	}
	claims, err := VerifyPreviewToken(cookieVal, secrets, now)
	if err != nil {
		if errors.Is(err, ErrTokenExpired) {
			return nil, "expired"
		}
		// malformed / bad alg / unknown kid / bad sig / bad aud all
		// collapse to the single "bad_signature" bucket.
		return nil, "bad_signature"
	}
	if claims.SandboxID != sandboxID {
		return nil, "wrong_sandbox"
	}
	if ownerExternalUserID != "" && claims.Sub != ownerExternalUserID {
		return nil, "wrong_user"
	}
	return claims, ""
}

// TerminalAccess verifies a `?token=` JWT presented on the terminal
// path: signature + expiry + TerminalAudience, and the token's
// sandbox_id must equal the id in the path — a token minted for one
// sandbox never opens another's shell. Returns the validated claims
// and true, or nil and false on any failure (callers map every
// failure to the same 401; the reason never leaves the process).
func TerminalAccess(token, path string, secrets map[string]string, now time.Time) (*TerminalClaims, bool) {
	id := terminalSandboxID(path)
	if id == "" || token == "" {
		return nil, false
	}
	claims, err := VerifyTerminalToken(token, secrets, now)
	if err != nil || claims.SandboxID != id {
		return nil, false
	}
	return claims, true
}

// terminalSandboxID extracts the sandbox id from a terminal path
// `/v1/sandboxes/<id>/terminal`, or "" when the path does not have
// exactly that shape. Stricter than a prefix/suffix match: any extra
// segment (or an empty id) is rejected.
func terminalSandboxID(p string) string {
	const prefix = "/v1/sandboxes/"
	const suffix = "/terminal"
	if !strings.HasPrefix(p, prefix) || !strings.HasSuffix(p, suffix) {
		return ""
	}
	id := p[len(prefix) : len(p)-len(suffix)]
	if id == "" || strings.Contains(id, "/") {
		return ""
	}
	return id
}
