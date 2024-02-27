package jwt

import (
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

type JWTRefreshToken struct {
	Md5 string
	Exp int64
}

func NewJWTRefreshToken(md5 string, exp int64) JWTRefreshToken {
	return JWTRefreshToken{
		Md5: md5,
		Exp: exp,
	}
}

func (t JWTRefreshToken) GetAccessTokenMD5() string {
	return t.Md5
}

func (t JWTRefreshToken) GetExpirationTime() (*jwtv5.NumericDate, error) {
	return &jwtv5.NumericDate{Time: time.Unix(t.Exp, 0)}, nil
}

func (t JWTRefreshToken) GetIssuedAt() (*jwtv5.NumericDate, error) {
	return nil, nil
}

func (t JWTRefreshToken) GetNotBefore() (*jwtv5.NumericDate, error) {
	return nil, nil
}

func (t JWTRefreshToken) GetIssuer() (string, error) {
	return "", nil
}

func (t JWTRefreshToken) GetSubject() (string, error) {
	return "", nil
}

func (t JWTRefreshToken) GetAudience() (jwtv5.ClaimStrings, error) {
	return nil, nil
}
