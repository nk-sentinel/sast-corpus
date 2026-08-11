package app

import "os"

func Render(user string) string {
	return user + ":" + os.Getenv("DB_PASSWORD")
}
