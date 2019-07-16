# auth

Basic service for user authorization. It can `register` and `authorize` user, also it can `refresh` issued JWT token.

It's still `work-in-progress` project so the code may look shitty.

## Endpoints

- `GET /` - just home
- `PUT /user` - create user `{"email":"user@example.com","password":"secret"}`, returns nothing
- `POST /login` - authorize user `{"email":"user@example.com","password":"secret"}`, returns JWT token `{"token":"jwt..."}`
- `POST /refresh` - refresh (prolong expiration) JWT token, returns new token with higher expiration time `{"token":"new_jwt"}`. To access this endpoint data you should pass JWT token received from `/login` endpoint.
- `GET /user/:id` - returns user info by ID `{"email":"user@example.com"}`. To access this endpoint data you should pass JWT token received from `/login` endpoint.

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

- Get user
```
curl --request GET \
  --url http://localhost:3000/user/64ac6833-aaa2-4071-acdf-3104b88847e2 \
  --header 'authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY0YWM2ODMzLWFhYTItNDA3MS1hY2RmLTMxMDRiODg4NDdlMiIsImVtYWlsIjoidXNlckBleGFtcGxlLmNvbSIsImV4cCI6MTU2MzMxMDMwOH0.wLhzASqjoMAVRC5vWjfyTg_JD7I83e6If1D9LTHojMc'
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

- Refresh token
```
curl --request POST \
  --url http://localhost:3000/refresh \
  --header 'authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY0YWM2ODMzLWFhYTItNDA3MS1hY2RmLTMxMDRiODg4NDdlMiIsImVtYWlsIjoidXNlckBleGFtcGxlLmNvbSIsImV4cCI6MTU2MzMxMzg2NH0.Oc1TxVQoxmLcT5TFwxdE2GEKjKpM22hlu3jpAuBNoUQ'
```
