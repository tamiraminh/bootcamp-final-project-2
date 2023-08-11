package user

import (
	"time"

	"github.com/evermos/boilerplate-go/configs"
	"github.com/evermos/boilerplate-go/shared/failure"
	"github.com/evermos/boilerplate-go/shared/jwtmodel"
	"github.com/golang-jwt/jwt"
)

type UserService interface {
	Create(requestFormat UserRequestFormat) (user User, err error)
	Login(requestFormat LoginRequestFormat) (login Login, err error)
	ResolveByUsername(username string) (user User, err error)
	Update(username string,requestFormat UserRequestFormat) (user User, err error)
}

type UserServiceImpl struct {
	UserRepository UserRepository
	Config *configs.Config
}

func ProvideUserServiceImpl(userRepository UserRepository, config *configs.Config)  *UserServiceImpl {
	s := new(UserServiceImpl)
	s.UserRepository = userRepository
	s.Config = config

	return s
}

func (s *UserServiceImpl) Create(requestFormat UserRequestFormat) (user User, err error)  {
	user, err = user.NewFromRequestFormat(requestFormat)
	if err != nil {
		return user, failure.BadRequest(err)
	}

	err = s.UserRepository.Create(user)
	if err != nil {
		return
	}

	user.AccessToken, err = s.GenerateJWT(user)
	if err != nil {
		return user, failure.InternalError(err)
	} 

	return
}


func (s *UserServiceImpl) Login(requestFormat LoginRequestFormat) (login Login, err error)  {
	login, err = login.NewFromRequestFormat(requestFormat)
	if err != nil {
		return login, failure.BadRequest(err)
	}
	var user User
	user, err = s.UserRepository.ResolveByUsername(login.Username)
	if err != nil {
		return
	}

	
	
	login.User = user
	
	if match := CheckPasswordHash(login.Password, login.User.Password); !match {
		return Login{}, failure.BadRequestFromString("Password False!")
	}

	login.AccessToken, err = s.GenerateJWT(user)
	if err != nil {
		return login, failure.InternalError(err)
	} 

	return

}



func (s *UserServiceImpl) ResolveByUsername(username string) (user User, err error)  {
	user, err = s.UserRepository.ResolveByUsername(username)

	if user.IsDeleted() {
		return user, failure.NotFound("User")
	}


	return
}

func (s *UserServiceImpl) Update(username string,requestFormat UserRequestFormat) (user User, err error)  {
	user, err = s.UserRepository.ResolveByUsername(username)
	if err != nil {
		return
	}

	err = user.Update(requestFormat, user)
	if err != nil {
		return
	}

	err = s.UserRepository.Update(user)


	return
}




func (s *UserServiceImpl) GenerateJWT(user User) (string, error)  {
	secret := configs.Get().App.JWTSecret

	claims := jwtmodel.Claims{
		UserId: user.Id,
		Username: user.Username,
		Role: user.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 1).Unix(),
			Issuer: "evermos",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err 
	}

	return tokenString, nil
}