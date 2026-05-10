package approvals

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"time"
)

// NewPendingID returns a 16-byte ID encoded as 22-char base64url.
// 4 bytes of unix seconds give rough mint-time sortability for log
// debugging; 12 bytes of crypto/rand provide the uniqueness
// guarantee. Format chosen to match the capability package's JTI
// shape so operators see a single visual style across the audit log.
func NewPendingID() (string, error) {
	var b [16]byte
	binary.BigEndian.PutUint32(b[:4], uint32(time.Now().UTC().Unix()))
	if _, err := rand.Read(b[4:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
