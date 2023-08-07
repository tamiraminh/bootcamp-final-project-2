package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/evermos/boilerplate-go/internal/domain/user"
	"github.com/evermos/boilerplate-go/shared/failure"
	"github.com/evermos/boilerplate-go/shared/jwtmodel"
	"github.com/evermos/boilerplate-go/transport/http/middleware"
	"github.com/evermos/boilerplate-go/transport/http/response"
	"github.com/go-chi/chi"
)

type UserHandler struct {
	UserService user.UserService
	JWTAuthMiddleware *middleware.JWTAuthentication

}


func ProvideUserHandler(userService user.UserService, jwtAuthMiddleware *middleware.JWTAuthentication) UserHandler  {
	return UserHandler{
		UserService: userService,
		JWTAuthMiddleware: jwtAuthMiddleware,
	}
}

func (h *UserHandler) Router(r chi.Router)  {
	r.Route("/users", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Post("/", h.CreateUser)
			r.Post("/login", h.Login)
		})

		r.Group(func(r chi.Router) {
			r.Use(h.JWTAuthMiddleware.JWTMiddlewareValidate)
			r.Get("/validate", h.Validate)
			r.Get("/profile", h.Profile)
			r.Put("/profile", h.UpdateUser)
			// r.Delete("/foo/{id}", h.SoftDeleteFoo)
		})

	})
	
}

func (h *UserHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var requestFormat user.UserRequestFormat
	err := decoder.Decode(&requestFormat)
	if err != nil {
		response.WithError(w, failure.BadRequest(err))
		return
	}


	user, err := h.UserService.Create(requestFormat)
	if err != nil {
		response.WithError(w, err)
		return
	}

	response.WithJSON(w, http.StatusCreated, user)
}



func (h *UserHandler) Login(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var requestFormat user.LoginRequestFormat
	err := decoder.Decode(&requestFormat)
	if err != nil {
		response.WithError(w, failure.BadRequest(err))
		return
	}


	login, err := h.UserService.Login(requestFormat)
	if err != nil {
		response.WithError(w, err)
		return
	}

	response.WithJSON(w, http.StatusOK, login)
}


func (h *UserHandler) Profile(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(middleware.ClaimsKey("claims")).(*jwtmodel.Claims)
	if !ok {
		http.Error(w, "Error Claims", http.StatusUnauthorized)
		return
	}

	user, err := h.UserService.ResolveByUsername(claims.Username)
	if err != nil {
		response.WithError(w, err)
		return
	}

	response.WithJSON(w, http.StatusCreated, user)
}


func (h *UserHandler) Validate(w http.ResponseWriter, r *http.Request) {
	
	claims, ok := r.Context().Value(middleware.ClaimsKey("claims")).(*jwtmodel.Claims)
	if !ok {
		http.Error(w, "Error Claims", http.StatusUnauthorized)
		return
	}


	response.WithJSON(w, http.StatusOK, claims)
}


func (h *UserHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {

	claims, ok := r.Context().Value(middleware.ClaimsKey("claims")).(*jwtmodel.Claims)
	if !ok {
		http.Error(w, "Error Claims", http.StatusUnauthorized)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var requestFormat user.UserRequestFormat
	err := decoder.Decode(&requestFormat)
	if err != nil {
		response.WithError(w, failure.BadRequest(err))
		return
	}

	user, err := h.UserService.Update(claims.Username, requestFormat)
	if err != nil {
		response.WithError(w, err)
		return
	}


	response.WithJSON(w, http.StatusOK, user)
}