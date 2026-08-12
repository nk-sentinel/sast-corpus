package main

import "github.com/gin-gonic/gin"

func register(r *gin.Engine) {
	r.GET("/who", func(c *gin.Context) {
		c.String(200, c.ClientIP())
	})
}
