package capability

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// Encode serializes a token as base64url(JSON), suitable for inclusion
// in an HTTP Authorization: Bearer header.
//
// base64url ("URL-safe", unpadded per RFC 4648 §5) avoids characters
// that need percent-encoding in headers and URLs.
func (t *Token) Encode() (string, error) {
	raw, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// Decode parses an Encode'd capability token. Decode does NOT verify
// the signature — call Token.Verify after Decode in any code path that
// trusts the token to authorize an action.
func Decode(s string) (*Token, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.New("token is not valid base64url")
	}
	var t Token
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, errors.New("token JSON is malformed")
	}
	return &t, nil
}

// FromAuthorizationHeader extracts the token portion of a Bearer-scheme
// HTTP Authorization header.
//
// Returns ("", nil) when the header is empty — the caller decides
// whether absence is a 401 condition. Returns an error for malformed
// headers (wrong scheme, etc).
func FromAuthorizationHeader(header string) (string, error) {
	if header == "" {
		return "", nil
	}
	const scheme = "Bearer "
	if !strings.HasPrefix(header, scheme) {
		return "", errors.New(`expected "Bearer <token>" Authorization header`)
	}
	return strings.TrimSpace(header[len(scheme):]), nil
}

// MasterKeyFromBase64 decodes a base64url-encoded master key into raw
// bytes. The gateway reads the key from the INTENTGATE_MASTER_KEY env
// var; that string must round-trip through this function.
//
// Both standard base64 (with possible padding) and unpadded base64url
// are accepted, since human operators occasionally paste the wrong
// flavor; the byte content is what matters for HMAC.
func MasterKeyFromBase64(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("master key is empty")
	}
	// Try the canonical encoding first, fall back to permissive ones.
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.StdEncoding,
		base64.RawStdEncoding,
	} {
		if raw, err := enc.DecodeString(s); err == nil {
			if len(raw) < 16 {
				return nil, errors.New("master key must decode to at least 16 bytes")
			}
			return raw, nil
		}
	}
	return nil, errors.New("master key is not valid base64")
}
