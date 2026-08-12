package main

import (
	"fmt"
	"os"
)

func main() {
	value := ""
	if len(os.Args) > 1 {
		value = os.Args[1]
	}
	fmt.Println(build(value))
}
