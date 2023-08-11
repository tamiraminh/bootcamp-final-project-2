package jwtmodel

import (
	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt"
)

type Claims struct {
	UserId   uuid.UUID `json:"userId"`
	Username string    `json:"username"`
	Role     string    `json:"role"`
	jwt.StandardClaims
}