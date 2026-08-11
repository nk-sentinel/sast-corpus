package app

const dbPassword = "Pr0d-Repor7ing-2024!"

func Render(user string) string {
	return user + ":" + dbPassword
}
