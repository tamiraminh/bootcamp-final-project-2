# Bootcamp Auth Service
This service is have feature to 
1. Login
2. Register
3. Validate JWT Token
4. Update (only can access with Header Authorization JWT Token)
5. Get Profile (only can access with Header Authorization JWT Token)



## Setup and Installation

1. clone this repository 
2. create new database to store bootcamp.sql
3. import database to mysql 
```
mysql -u username -p database_name < path/to/bootcamp.sql
```
4. copy .env.example file and rename to .env 
5. fill the env with your credentials, database credentials and jwt secret specially
```
APP.JWT_SECRET=secret
```
6. run go generate command in root project to setup project
```
go generate ./...
```

## Run and Test
To run this program, run this command in root terminal 
```
go run . 
```

## Improvement After Huddle
1. Add validator to User Struct 
2. Repair flow generate Token from model to service 
3. Secret using Config, not directly using viper 
4. repair table to course not related to user table 
5. Add Bearer in JWT Token