package storage

import (
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"gopkg.in/couchbase/gocb.v1"
)

const (
	usersBucketName  = "users"
	tokensBucketName = "tokens"
)

type Storage struct {
	cluster *gocb.Cluster
}

func NewCouchbaseStorage(address, username, password string) (*Storage, error) {
	var (
		bucketPassword     string
		usersBucketExists  bool
		tokensBucketExists bool
	)
	defaultBucketQuota := 100

	cluster, err := gocb.Connect(address)
	if err != nil {
		return nil, errors.Wrap(err, "cluster connection error")
	}

	if err = cluster.Authenticate(gocb.PasswordAuthenticator{
		Username: username,
		Password: password,
	}); err != nil {
		return nil, errors.Wrap(err, "cluster auth error")
	}

	buckets, _ := cluster.Manager(username, password).GetBuckets()
	for _, bucket := range buckets {
		if bucket.Name == usersBucketName {
			usersBucketExists = true
		}
		if bucket.Name == tokensBucketName {
			tokensBucketExists = true
		}
	}

	if !usersBucketExists {
		err = cluster.Manager(username, password).InsertBucket(&gocb.BucketSettings{
			Name:  usersBucketName,
			Quota: defaultBucketQuota,
		})
		if err != nil {
			return nil, errors.Wrap(err, "can't create 'users' bucket")
		}

		// TODO figure out better way how to wait until bucket will be ready
		// see also https://forums.couchbase.com/t/bucket-creation-callback/17220
		time.Sleep(2 * time.Second)

		users, err := cluster.OpenBucket(usersBucketName, bucketPassword)
		if err != nil {
			return nil, errors.Wrap(err, "can't open 'users' bucket")
		}

		if err := users.Manager(username, password).CreatePrimaryIndex("", true, false); err != nil {
			return nil, errors.Wrap(err, "can't create primary index in 'users' bucket")
		}
	}

	if !tokensBucketExists {
		err = cluster.Manager(username, password).InsertBucket(&gocb.BucketSettings{
			Name:  tokensBucketName,
			Quota: defaultBucketQuota,
		})
		if err != nil {
			return nil, errors.Wrap(err, "can't create 'tokens' bucket")
		}

		// TODO figure out better way how to wait until bucket will be ready
		// see also https://forums.couchbase.com/t/bucket-creation-callback/17220
		time.Sleep(2 * time.Second)

		tokens, err := cluster.OpenBucket(tokensBucketName, bucketPassword)
		if err != nil {
			return nil, errors.Wrap(err, "can't open 'tokens' bucket")
		}

		if err := tokens.Manager(username, password).CreatePrimaryIndex("", true, false); err != nil {
			return nil, errors.Wrap(err, "can't create primary index in 'tokens' bucket")
		}
	}

	return &Storage{cluster: cluster}, nil
}

func (s *Storage) CreateUser(id uuid.UUID, email, hashedPassword string) error {
	user := User{
		ID:       id,
		Email:    email,
		Password: string(hashedPassword),
	}

	users, err := s.cluster.OpenBucket("users", "")
	if err != nil {
		return errors.Wrap(err, "failed to open bucket")
	}

	defer users.Close()

	_, err = users.Upsert(id.String(), user, 0)
	if err != nil {
		return errors.Wrap(err, "failed to upsert user")
	}

	return nil
}

func (s *Storage) GetUserByID(id string) (User, error) {
	query := gocb.NewN1qlQuery("select Email from users where ID=$userID")

	params := make(map[string]interface{})
	params["userID"] = id

	users, err := s.cluster.OpenBucket("users", "")
	if err != nil {
		return User{}, errors.Wrap(err, "failed to open bucket")
	}

	defer users.Close()

	rows, err := users.ExecuteN1qlQuery(query, params)
	if err != nil {
		return User{}, errors.Wrap(err, "can't get user")
	}

	rows.Close()

	if rows.Metrics().ResultCount == 0 {
		return User{}, ErrUserNotFound
	}

	var user User
	for rows.Next(&user) {
		break
	}

	return user, nil
}

func (s *Storage) GetUserByEmail(email string) (User, error) {
	var user User

	query := gocb.NewN1qlQuery("select `ID`,`Email`,`Password` from `users` where `Email`=$email")

	params := make(map[string]interface{})
	params["email"] = email

	users, err := s.cluster.OpenBucket(usersBucketName, "")
	if err != nil {
		return user, errors.Wrap(err, "can't open 'users' bucket")
	}

	defer users.Close()

	rows, err := users.ExecuteN1qlQuery(query, params)
	if err != nil {
		return user, errors.Wrap(err, "can't get user")
	}

	for rows.Next(&user) {
		break
	}

	return user, nil
}

func (s *Storage) CreateToken(token string, claims Claims) error {
	tokenData := Token{
		Token:  token,
		Claims: claims,
	}

	tokens, err := s.cluster.OpenBucket(tokensBucketName, "")
	if err != nil {
		return errors.Wrap(err, "can't open 'tokens' bucket")
	}

	defer tokens.Close()

	_, err = tokens.Upsert(token, tokenData, 0)
	if err != nil {
		return errors.Wrap(err, "can't upset token")
	}

	return nil
}

func (s *Storage) DeprecateToken(token Token) error {
	// set token expiration time if far far past
	token.Claims.ExpiresAt = 1

	tokens, err := s.cluster.OpenBucket(tokensBucketName, "")
	if err != nil {
		return errors.Wrap(err, "can't open 'tokens' bucket")
	}

	defer tokens.Close()

	_, err = tokens.Upsert(token.Token, token, 0)
	if err != nil {
		return errors.Wrap(err, "can't upsert token")
	}

	return nil
}

func (s *Storage) GetNotExpiredTokenByToken(token string) (Token, error) {
	query := gocb.NewN1qlQuery("select claims, token from tokens where claims.exp > $now and token = $token")

	params := make(map[string]interface{})
	params["token"] = token
	params["now"] = time.Now().Unix()

	tokens, err := s.cluster.OpenBucket(tokensBucketName, "")
	if err != nil {
		return Token{}, errors.Wrap(err, "can't open 'tokens' bucket")
	}

	defer tokens.Close()

	rows, err := tokens.ExecuteN1qlQuery(query, params)
	if err != nil {
		return Token{}, errors.Wrap(err, "can't get token")
	}

	rows.Close()

	if rows.Metrics().ResultCount == 0 {
		return Token{}, ErrTokenNotFound
	}

	var tokenReponse Token
	for rows.Next(&tokenReponse) {
		break
	}

	return tokenReponse, nil
}
