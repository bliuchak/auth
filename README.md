# auth

Basic service for user authorization. It can `register`, `authorize` and `refresh` issues JWT token.

It's still `work-in-progress` project so the code may look shitty.

## Endpoints

- `GET /` - just home
- `PUT /user` - create user `{"email":"user@example.com","password":"secret"}`, returns nothing
- `POST /login` - authorize user `{"email":"user@example.com","password":"secret"}`, returns JWT token `{"token":"jwt..."}`
- `POST /refresh` - refresh JWT token `{"token":"old_jwt"}`, returns new token with higher expiration time `{"token":"new_jwt"}`
- `GET /user/:id` - returns user info by ID (in progress)

## Installation

- docker network create lab
- docker-compose up

## Usage

- Home
```
curl --request GET --url http://localhost:3000/
```

-  Create user
```
curl --request PUT \
  --url http://localhost:3000/user \
  --header 'content-type: application/json' \
  --data '{
	"email": "user@example.com",
	"password": "secret"
}'
```

- Login
```
curl --request POST \
  --url http://localhost:3000/login \
  --header 'content-type: application/json' \
  --data '{
	"email": "user@example.com",
	"password": "secret"
}'
```

- refresh
```
curl --request POST \
  --url http://localhost:3000/refresh \
  --header 'content-type: application/json' \
  --data '{
	"token": "jwt-token"
}'
```
