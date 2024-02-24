package jwt

import (
	"crypto/rsa"
	"fmt"
	"testing"
	"time"
)

var (
	rsaPrivateKeyString = `-----BEGIN PRIVATE KEY-----
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
Kmmqawin8IbqlEfUSJ9Ewpp6hS+pSw==
-----END PRIVATE KEY-----
`
	rsaPublicKeyString = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAozyHHaYahT+/ML8rdi63
4hy0+O5mkMYhSqD4dxsToOhLc1B0CPqWgDjDzES+E5yvx+A1vc5HxhvDzZXW+3Jr
419B+nHp4/AXCSm4C7su4kvVYX+TZdBkolXA3yojxdsi0dOFt26Y/rvvWfuXAAGz
Lua6bKjyVhyM/fKwuwbwhx87z/QHpiCWtv9ZnpZQveVGdPffkBBtspmJ0ieWTjBA
Ux6i7SzSvYzJUEXfJFJAlnenTV2ur9l7YN0uTJ+nOHl0Yw6F2jywKDjqfMxGLnK8
1SuoICI8xt7tsdpe4yi1zT5e2dhnuVjDuZrAgtLdt3bhLvGsBy5qof6k/w7sCy3H
8aWebtdlNIQLYE429BazTvC50Sj0ZsDYQyCj73EhCbBZB824SoxpP3rjpPWU6BsF
N8uTsuB22wYcniSJ1zuIgtbNsoq15jdgQp6IPzDI597jriXLXlyoWSP0Y0wvW4op
T4KAX9oki2XN2XH+nzgUduH5Ns/zuIgLMJJM/0GR+xKVFiEUU2TPEjm2XgzMDDmB
lRegmxgbGxT2A/lpor21eTu0D5MMeqb3A7UnRZGOslmdWRmP1npBN2XQHbzBU3r3
KuirK7/qS3mGZdzxDtjgXA8sE8DDnZyi2wbEzzNcmSUczU6KM1/K1mJrt3qbC5Un
Ap6d7oOXuLL6d1G9GHLXRmcCAwEAAQ==
-----END PUBLIC KEY-----
`
	rsaPrivateKey *rsa.PrivateKey
	rsaPublicKey  *rsa.PublicKey
)

func init() {
	pri, pub, _ := InitRSAKeyPair(rsaPrivateKeyString, rsaPublicKeyString)
	rsaPrivateKey = pri
	rsaPublicKey = pub
}

func TestRsa(t *testing.T) {
	info := map[string]interface{}{
		"age":        10,
		"privileges": "admin, p1, p2",
		"username":   "user1",
	}
	token, err := GenerateJWTRSA(info, 5*time.Second, rsaPrivateKey)
	if err != nil {
		t.Errorf("generate fail: %v", err)
	}
	fmt.Printf("token: %v\n", token)

	data, err := VerifyJWTRSA(token, rsaPublicKey)
	if err != nil {
		t.Errorf("verify fail: %v", err)
	}
	gotInfo, ok := data.(map[string]interface{})
	if !ok {
		t.Errorf("read data fail")
	}
	fmt.Printf("gotInfo: %v\n", gotInfo)
}
