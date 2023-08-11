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


// CreateFoo creates a new User.
// @Summary Create a new User.
// @Description This endpoint creates a new User.
// @Tags v1/users
// @Param user body user.UserRequestFormat true "The user to be created."
// @Produce json
// @Success 201 {object} response.Base{data=user.UserResponseFormat}
// @Failure 400 {object} response.Base
// @Failure 409 {object} response.Base
// @Failure 500 {object} response.Base
// @Router /v1/users [post]
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


// @Summary Login User
// @Description This endpoint is to user login and get access token.
// @Tags v1/users
// @Param user body user.LoginRequestFormat true "The user to be created."
// @Produce json
// @Success 200 {object} response.Base{data=user.LoginResponseFormat}
// @Failure 400 {object} response.Base
// @Failure 404 {object} response.Base
// @Failure 500 {object} response.Base
// @Router /v1/users/login [post]
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


// @Summary Resolve Profile User by ID
// @Description This endpoint resolves a detail user by its ID.
// @Tags v1/users
// @Security JWTToken
// @Produce json
// @Success 200 {object} response.Base{data=user.UserResponseFormat}
// @Failure 400 {object} response.Base
// @Failure 404 {object} response.Base
// @Failure 500 {object} response.Base
// @Router /v1/users/profile [get]
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

// @Summary validate jwt token
// @Description This endpoint is to validate user. This is done by
// @Tags v1/users
// @Security JWTToken
// @Produce json
// @Success 200 {object} response.Base{data=jwtmodel.Claims}
// @Failure 400 {object} response.Base
// @Failure 409 {object} response.Base
// @Failure 500 {object} response.Base
// @Router /v1/users/validate [get]
func (h *UserHandler) Validate(w http.ResponseWriter, r *http.Request) {
	
	claims, ok := r.Context().Value(middleware.ClaimsKey("claims")).(*jwtmodel.Claims)
	if !ok {
		http.Error(w, "Error Claims", http.StatusUnauthorized)
		return
	}


	response.WithJSON(w, http.StatusOK, claims)
}

// @Summary Update a User.
// @Description This endpoint updates an existing User.
// @Tags v1/users
// @Security JWTToken
// @Param foo body user.UserRequestFormat true "The user to be updated."
// @Produce json
// @Success 200 {object} response.Base{data=foobarbaz.FooResponseFormat}
// @Failure 400 {object} response.Base
// @Failure 409 {object} response.Base
// @Failure 500 {object} response.Base
// @Router /v1/users/profile [put]
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