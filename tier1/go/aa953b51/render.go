package app

import (
	"bytes"
	"html/template"
)

func Render(value string) string {
	t := template.Must(template.New("row").Parse("<div>{{.}}</div>"))
	var out bytes.Buffer
	t.Execute(&out, template.HTML(value))
	return out.String()
}
