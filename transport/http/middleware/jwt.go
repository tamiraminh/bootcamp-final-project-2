package middleware

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/evermos/boilerplate-go/configs"
	"github.com/evermos/boilerplate-go/shared/jwtmodel"
	"github.com/evermos/boilerplate-go/transport/http/response"
	"github.com/golang-jwt/jwt"
)



type JWTAuthentication struct {
	Config *configs.Config
}

type ClaimsKey string

const (
	HeaderJWTAuthorization = "Authorization"
)

func ProvideJWTAuthentication(config *configs.Config) *JWTAuthentication {
	return &JWTAuthentication{config}
}


func (a *JWTAuthentication) ValidateJWT(tokenString string) (*jwtmodel.Claims, error)  {
	secret := a.Config.App.JWTSecret

	token, err := jwt.ParseWithClaims(tokenString, &jwtmodel.Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("JWT validation failed: %v", err)
	}

	if claims, ok := token.Claims.(*jwtmodel.Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("JWT is not valid")
}


func (a *JWTAuthentication) JWTMiddlewareValidate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")[(len("Bearer ")):]
		if tokenString == "" {
			log.Println("no header")
			response.WithJSON(w, http.StatusUnauthorized, "Unauthorized")
			return

		}

		claims, err := a.ValidateJWT(tokenString)
		if err != nil {
			log.Println(err)
			response.WithJSON(w, http.StatusUnauthorized, "Unauthorized")
			return
		}


		ctx := context.WithValue(r.Context(), ClaimsKey("claims"), claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}