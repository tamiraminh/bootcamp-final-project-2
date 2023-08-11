package user

import (
	"encoding/json"
	"log"
	"time"

	"github.com/evermos/boilerplate-go/shared"
	"github.com/evermos/boilerplate-go/shared/nuuid"

	"github.com/gofrs/uuid"
	"github.com/guregu/null"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Id 			uuid.UUID 	`db:"id" validate:"required"`
	Username 	string		`db:"username" validate:"required"`
	Email	 	string		`db:"email" validate:"required"`
	Name 	 	string 		`db:"name" validate:"required"`
	Password 	string 		`db:"password" validate:"required"`
	Role 	 	string 		`db:"role" validate:"required"`
	AccessToken string 		`db:"-"`
	CreatedAt   time.Time   `db:"created_at"`
	CreatedBy   uuid.UUID   `db:"created_by"`
	UpdatedAt   null.Time   `db:"updated_at"`
	UpdatedBy   nuuid.NUUID `db:"updated_by"`
	DeletedAt   null.Time   `db:"deleted_at"`
	DeletedBy   nuuid.NUUID `db:"deleted_by"`
}

func (u *User) IsDeleted() (deleted bool) {
	return u.DeletedAt.Valid && u.DeletedBy.Valid
}

func (u User) MarshalJSON() ([]byte, error) {
	return json.Marshal(u.ToResponseFormat())
}

func HashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
    return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}

func (u *User) Update(req UserRequestFormat, user User) (err error) {
	
	u.Username = req.Username
	u.Email = req.Email
	u.Name = req.Name
	u.Password = req.Password
	u.Role = req.Role
	u.UpdatedAt = null.TimeFrom(time.Now())
	u.UpdatedBy = nuuid.From(user.Id)
	
	err = u.Validate()
	if err != nil {
		log.Println(err.Error())
		return
	} 
	
	hashPassword, err := HashPassword(req.Password)
	if err != nil {
		log.Println(err.Error())
		return 
	}
	u.Password = hashPassword
	
	return
}

func (u *User) Validate() (err error) {
	validator := shared.GetValidator()
	return validator.Struct(u)
}

func (u User) NewFromRequestFormat(req UserRequestFormat) (newUser User, err error) {
	userID, _ := uuid.NewV4()
	newUser = User{
		Id: userID,
		Username: req.Username,
		Email: req.Email,
		Name: req.Name,
		Password: req.Password,
		Role: req.Role,
		CreatedAt:   time.Now(),
		CreatedBy:   userID,
	}
	err = newUser.Validate()
	if err != nil {
		log.Println(err.Error())
		return
	} 
	
	passwordHashed, err := HashPassword(req.Password)
	if err != nil {
		log.Println(err.Error())
		return
	} 
	newUser.Password = passwordHashed
	

	return
}




func (u User) ToResponseFormat() UserResponseFormat {
	resp := UserResponseFormat{
		Id: u.Id,
		Username: u.Username,
		Email: u.Email,
		Name: u.Name,
		Role: u.Role,
		AccessToken: u.AccessToken,
		CreatedAt: u.CreatedAt,
		CreatedBy: u.CreatedBy,
		UpdatedAt: u.UpdatedAt,
		UpdatedBy: u.UpdatedBy.Ptr(),
		DeletedAt: u.DeletedAt,
		DeletedBy: u.DeletedBy.Ptr(),

	}
	return resp
}



type UserRequestFormat struct {
	Username 	string  `json:"username" validate:"required"`
	Email	 	string  `json:"email" validate:"required"`
	Name 	    string  `json:"name" validate:"required"`
	Password 	string  `json:"password" validate:"required"`
	Role 	    string  `json:"role" validate:"required"`
}


type UserResponseFormat struct {
	Id uuid.UUID 			`json:"id"`
	Username 	string 		`json:"username"`
	Email 		string	 	`json:"email"`
	Name 	 	string 		`json:"name"`
	Role 	 	string 		`json:"role"`
	AccessToken string 		`json:"accessToken"`
	CreatedAt   time.Time   `json:"created_at"`
	CreatedBy   uuid.UUID   `json:"created_by"`
	UpdatedAt   null.Time   `json:"updated_at,omitempty"`
	UpdatedBy   *uuid.UUID 	`json:"updated_by,omitempty"`
	DeletedAt   null.Time   `json:"deleted_at,omitempty"`
	DeletedBy   *uuid.UUID 	`json:"deleted_by,omitempty"`	
}


type Login struct {
	Username 	string 		
	Password 	string  	
	User		User
	AccessToken string
	
}

func (l Login) MarshalJSON() ([]byte, error) {
	return json.Marshal(l.ToResponseFormat())
}

func (l Login) NewFromRequestFormat(req LoginRequestFormat) (newLogin Login, err error) {
	if err != nil {
		log.Println(err.Error())
		return
	} 
	newLogin = Login{
		Username: req.Username,
		Password: req.Password,
	}

	return
}

func (l Login) ToResponseFormat() LoginResponseFormat {
	
	resp := LoginResponseFormat{
		AccessToken: l.AccessToken,

	}
	return resp
}

type LoginRequestFormat struct {
	Username 	string 		`json:"username" validate:"required"`
	Password 	string  	`json:"password" validate:"required"`
	
}

type LoginResponseFormat struct {
	AccessToken string 		`json:"accessToken"`
}


