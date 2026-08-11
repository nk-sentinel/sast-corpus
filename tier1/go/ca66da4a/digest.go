package app

import (
	"crypto/md5"
	"encoding/hex"
)

func Render(value string) string {
	sum := md5.Sum([]byte(value))
	return hex.EncodeToString(sum[:])
}
