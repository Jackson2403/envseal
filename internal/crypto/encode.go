package crypto

import "encoding/base64"

// stdB64 base64-encodes raw bytes (used for key serialization in .toml).
func stdB64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// stdUnB64 decodes a base64 string back to raw bytes.
func stdUnB64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
