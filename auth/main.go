package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/pizza-nz/go-playground/middleware"
)

// JWT Auth

type Login struct {
	HashedPassword string
	SessionToken   string
	CSRFToken      string
}

// In-memory Database
// Key is the username
var users = map[string]Login{}

func main() {
	e := echo.New()

	middleware.NewLogger()
	e.Use(middleware.LoggingMiddleware)

	e.POST("/register", register)
	e.POST("/login", login)
	e.POST("/logout", logout)
	e.POST("/protected", protected)

	middleware.Logger.LogInfo().Msg(e.Start(":1234").Error())
}

func register(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")
	if len(username) < 8 || len(password) < 8 {
		return echo.ErrBadRequest
	}

	if _, ok := users[username]; ok {
		return echo.ErrConflict
	}

	hashedPassword, _ := hashPassword(password)
	users[username] = Login{
		HashedPassword: hashedPassword,
	}

	return c.String(http.StatusOK, "User Registered OK")
}

func login(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")

	user, ok := users[username]
	if !ok || !checkPasswordHash(password, user.HashedPassword) {
		return echo.ErrUnauthorized
	}

	sessionToken := generateToken(32)
	csrfToken := generateToken(32)

	c.SetCookie(createCookie("session_token", sessionToken, time.Now().Add(24*time.Hour), true))
	c.SetCookie(createCookie("csrf_token", csrfToken, time.Now().Add(24*time.Hour), false))

	// Store token
	user.SessionToken = sessionToken
	user.CSRFToken = csrfToken
	users[username] = user

	return c.String(http.StatusOK, "Login successful")
}

func logout(c echo.Context) error {
	if err := Authorize(c); err != nil {
		return echo.ErrUnauthorized
	}
	c.SetCookie(clearCookie("session_token", true))
	c.SetCookie(clearCookie("csrf_token", false))

	username := c.FormValue("username")
	user, _ := users[username]
	user.SessionToken = ""
	user.CSRFToken = ""
	users[username] = user

	c.String(http.StatusOK, "Logged Out Succcessful")
	return nil
}

func protected(c echo.Context) error {
	if err := Authorize(c); err != nil {
		return echo.ErrUnauthorized
	}

	username := c.FormValue("username")
	c.String(http.StatusOK, fmt.Sprintf("CSRF validated successfully! Welcome, %s", username))
	return nil
}
