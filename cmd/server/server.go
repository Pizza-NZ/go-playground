package main

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/pizza-nz/go-playground/middleware"
)

func main() {
	e := echo.New()

	middleware.NewLogger()
	e.Use(middleware.LoggingMiddleware)

	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, World!")
	})
	middleware.Logger.LogInfo().Msg(e.Start(":3001").Error())
}

type HealthPayload struct {
	Status int
	Msg    string
}
