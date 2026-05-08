package capability

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// SignatureSize is the byte length of an HMAC-SHA256 signature.
const SignatureSize = sha256.Size

// hmacOnce returns HMAC-SHA256(key, data). Used by both the chain
// computation and by Attenuate (which only does the last hop).
func hmacOnce(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// computeSignature derives the chained HMAC for a token under
// masterKey. The chain construction is:
//
//	sig_0      = HMAC(masterKey, canonicalPayload)
//	sig_{i+1}  = HMAC(sig_i,    canonicalBytes(caveat_i))
//
// The token's stored Signature must equal sig_n (after all caveats).
func computeSignature(t *Token, masterKey []byte) ([]byte, error) {
	if len(masterKey) == 0 {
		return nil, errors.New("master key is empty")
	}
	payload, err := t.canonicalPayload()
	if err != nil {
		return nil, err
	}
	prev := hmacOnce(masterKey, payload)
	for i := range t.Caveats {
		cb, err := t.Caveats[i].canonicalBytes()
		if err != nil {
			return nil, err
		}
		prev = hmacOnce(prev, cb)
	}
	return prev, nil
}

// Sign computes and stores the HMAC chain signature on the token.
//
// Sign is used internally by Mint. Application code that calls Mint
// or Attenuate gets a signed token without ever touching Sign directly.
func (t *Token) Sign(masterKey []byte) error {
	sig, err := computeSignature(t, masterKey)
	if err != nil {
		return err
	}
	t.Signature = base64.RawURLEncoding.EncodeToString(sig)
	return nil
}

// Verify checks the token's signature chain against masterKey.
//
// Verify uses hmac.Equal for the comparison, which is constant-time
// with respect to the signature contents. A non-nil error from Verify
// MUST cause the gateway to reject the request.
//
// Verify does not check expiry or other caveats — call Token.Check for
// that. The split exists because signature verification is purely about
// integrity ("did our authority issue this?"), while caveat evaluation
// depends on per-request context ("does this token authorize THIS call?").
func (t *Token) Verify(masterKey []byte) error {
	if err := t.Validate(); err != nil {
		return err
	}
	expected, err := computeSignature(t, masterKey)
	if err != nil {
		return err
	}
	provided, err := base64.RawURLEncoding.DecodeString(t.Signature)
	if err != nil {
		return errors.New("signature is not valid base64url")
	}
	if !hmac.Equal(provided, expected) {
		return errors.New("signature mismatch")
	}
	return nil
}
