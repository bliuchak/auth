package server

import (
	"github.com/go-chi/chi"
	"github.com/ibliuchak/auth/cmd/httpd/server/handler"
)

type Router struct {
	home *handler.Home
	user *handler.Users
	auth *handler.Auth
	m    *handler.Middleware
}

func NewRouter(home *handler.Home, user *handler.Users, auth *handler.Auth, m *handler.Middleware) *Router {
	return &Router{home: home, user: user, auth: auth, m: m}
}

func (rt *Router) Init() *chi.Mux {
	r := chi.NewRouter()

	r.Get("/", rt.home.GetHome)
	r.Put("/user", rt.user.CreateUser)
	r.Post("/login", rt.auth.Login)
	r.With(rt.m.JWTValidation).Post("/refresh", rt.auth.Refresh)
	r.With(rt.m.JWTValidation).Get("/user/{userID}", rt.user.GetUserByID)

	return r
}
