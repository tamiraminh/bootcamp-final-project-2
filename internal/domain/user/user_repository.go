package user

import (
	"database/sql"

	"github.com/evermos/boilerplate-go/infras"
	"github.com/evermos/boilerplate-go/shared/failure"
	"github.com/evermos/boilerplate-go/shared/logger"
	"github.com/gofrs/uuid"
	"github.com/jmoiron/sqlx"
)


var userQueries = struct {
	selectUser		string
	insertUser 		string 
	updateUser		string
} {
	selectUser: `SELECT * FROM user`,
	insertUser: `
	  INSERT INTO user (
		id,
		username, 
		email,
		name, 
		password, 
		role, 
		created_at,
		created_by,
		updated_at,
		updated_by,
		deleted_at,
		deleted_by
	  ) VALUES (
		:id,
		:username, 
		:email,
		:name, 
		:password, 
		:role, 
		:created_at,
		:created_by,
		:updated_at,
		:updated_by,
		:deleted_at,
		:deleted_by
	  )
	`,
	updateUser: `
	UPDATE user
	SET
	  	username = :username,
		email = :email,
		name = :name,
		password = :password,
		role = :role,
		created_at = :created_at ,
		created_by = :created_by ,
		updated_at = :updated_at ,
		updated_by = :updated_by ,
		deleted_at = :deleted_at ,
		deleted_by = :deleted_by
	WHERE id = :id`,
}

type UserRepository interface {
	Create(user User) (err error)
	ExistsByID(id uuid.UUID) (exists bool, err error)
	ResolveByUsername(username string) (user User, err error)
	Update(user User) (err error)

	
}

type UserRepositoryMySQL struct {
	DB *infras.MySQLConn
}

func ProvideUserRepositoryMySQL(db *infras.MySQLConn) *UserRepositoryMySQL  {
	s := new(UserRepositoryMySQL)
	s.DB = db
	return s 
}

func (r *UserRepositoryMySQL) Create(user User) (err error)  {
	exists, err := r.ExistsByID(user.Id)
	if err != nil {
		logger.ErrorWithStack(err)
		return
	}

	if exists {
		err = failure.Conflict("create", "User", "already exists")
		logger.ErrorWithStack(err)
		return
	}

	return r.DB.WithTransaction(func(tx *sqlx.Tx, e chan error) {
		if err := r.txCreate(tx, user); err != nil {
			e <- err
			return
		}

		e <- nil
	})
}

func (r *UserRepositoryMySQL) Update(user User) (err error) {
	exists, err := r.ExistsByID(user.Id)
	if err != nil {
		logger.ErrorWithStack(err)
		return
	}

	if !exists {
		err = failure.NotFound("user")
		logger.ErrorWithStack(err)
		return
	}

	return r.DB.WithTransaction(func(tx *sqlx.Tx, e chan error) {
		if err := r.txUpdate(tx, user); err != nil {
			e <- err
			return
		}

		e <- nil
	})
}


func (r *UserRepositoryMySQL) ExistsByID(id uuid.UUID) (exists bool, err error) {
	err = r.DB.Read.Get(
		&exists,
		"SELECT COUNT(id) FROM user WHERE id = ?", id.String())
	if err != nil {
		logger.ErrorWithStack(err)
	}

	return
}


func (r *UserRepositoryMySQL) ResolveByUsername(username string) (user User, err error) {
	err = r.DB.Read.Get(
		&user,
		userQueries.selectUser+" WHERE  username = ?",
		username)
	if err != nil && err == sql.ErrNoRows {
		err = failure.NotFound("User")
		logger.ErrorWithStack(err)
		return
	}
	return
}


func (r *UserRepositoryMySQL) txCreate(tx *sqlx.Tx, user User) (err error) {
	stmt, err := tx.PrepareNamed(userQueries.insertUser)
	if err != nil {
		logger.ErrorWithStack(err)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(user)
	if err != nil {
		logger.ErrorWithStack(err)
	}

	return
}


func (r *UserRepositoryMySQL) txUpdate(tx *sqlx.Tx, user User) (err error) {
	stmt, err := tx.PrepareNamed(userQueries.updateUser)
	if err != nil {
		logger.ErrorWithStack(err)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(user)
	if err != nil {
		logger.ErrorWithStack(err)
	}

	return
}
