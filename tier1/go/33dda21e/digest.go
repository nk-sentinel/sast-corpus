package app

import (
	"crypto/sha256"
	"encoding/hex"
)

func Render(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
