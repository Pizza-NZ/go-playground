package main

import (
	"fmt"

	"github.com/labstack/echo/v4"
	"github.com/pizza-nz/go-playground/middleware"
)

func Authorize(c echo.Context) error {
	username := c.FormValue("username")
	user, ok := users[username]
	if !ok {
		middleware.Logger.LogInfo().Msg(fmt.Sprintf("User: %s\t\tUser was invalid", username))
		return echo.ErrUnauthorized
	}

	// Get session token from the cookie
	st, err := c.Cookie("session_token")
	if err != nil || st.Value == "" || st.Value != user.SessionToken {
		middleware.Logger.LogInfo().Msg(fmt.Sprintf("User: %s SessionToken: %s\t\tSessionToken was invalid", username, st))
		return echo.ErrUnauthorized
	}

	// csrf := c.Request().Header.Value(echo.HeaderXCSRFToken)
	csrf := c.Request().Header.Get(echo.HeaderXCSRFToken)
	if csrf != user.CSRFToken || csrf == "" {
		middleware.Logger.LogInfo().Msg(fmt.Sprintf("User: %s CSRFToken: %s\t\tCSRFToken was invalid", username, csrf))
		return echo.ErrUnauthorized
	}

	return nil
}
