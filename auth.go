package main

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/hashicorp/go-hclog"
)

var jwtKey = []byte("my_secret_key")

type Auth struct {
	l hclog.Logger
}

type tokenOps interface {
	generateToken(user *user) (string, error)
	tokenValidity()
}

type token struct {
	Value    string
	Expired  bool
	Validity time.Duration
}

type user struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type response struct {
	AuthToken    string `json:"authToken"`
	RefreshToken string `json:"refreshToken"`
}

type claim struct {
	Username string
	jwt.StandardClaims
}

func NewAuth() *Auth {
	log := hclog.New(&hclog.LoggerOptions{Name: "Auth-Handler"})
	return &Auth{l: log}
}

func (a *Auth) Ping(w http.ResponseWriter, r *http.Request) {
	a.l.Info("Pong")
	w.Write([]byte("Pong!!"))
}

func (a *Auth) Login(w http.ResponseWriter, r *http.Request) {
	a.l.Debug("Logion handler")
	reqBody := &user{}
	err := reqBody.fromJson(r.Body)
	if err != nil {
		a.l.Info("Unable to unmarshal json", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if !reqBody.checkCreds() {
		a.l.Info("Wrong creds", "creds", reqBody)
		http.Error(w, "Wrong credentials ", http.StatusUnauthorized)
		return
	}

	var authToken, refreshtoken tokenOps
	authToken = &token{Validity: 5 * time.Minute}
	refreshtoken = &token{Validity: 5 * 24 * time.Hour}
	authTokenString, err := authToken.generateToken(reqBody)
	refreshtokenString, err := refreshtoken.generateToken(reqBody)
	if err != nil {
		a.l.Error("Error in generating tokens", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	resp := &response{AuthToken: authTokenString, RefreshToken: refreshtokenString}
	resp.toJson(w)

}

func (a *Auth) AuthMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.l.Info("Auth middleware")
		authToken := r.Header.Get("Authorization")

		if authToken == "" {
			a.l.Info("Tokens not found", "tokens", authToken)
			http.Error(w, "Token not Provided", http.StatusForbidden)
			return
		}

		claims := &claim{}

		decodedAuthToken, err := jwt.ParseWithClaims(authToken, claims, func(t *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				a.l.Info("Invalid signature", "error", err)
				http.Error(w, "Invalid signature", http.StatusForbidden)
				return
			}

			a.l.Info("can not parse token", "error", err)
			http.Error(w, "Invalid tokens", http.StatusBadRequest)
			return
		}

		if !decodedAuthToken.Valid {
			http.Error(w, "Invalid tokens", http.StatusBadRequest)
			return
		}

		h.ServeHTTP(w, r)
	})
}

func (a *Auth) RefreshToken(w http.ResponseWriter, r *http.Request) {
	a.l.Info("Refresh Token")
	refreshToken := r.Header.Get("Authorization")
	refreshClaims := &claim{}

	decodedRefreshToken, err := jwt.ParseWithClaims(refreshToken, refreshClaims, func(t *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			a.l.Info("Invalid signature", "error", err)
			http.Error(w, "Invalid signature", http.StatusForbidden)
			return
		}

		a.l.Info("can not parse token", "error", err)
		http.Error(w, "Invalid tokens", http.StatusBadRequest)
		return
	}

	if decodedRefreshToken.Valid && !checkExpiry(refreshClaims) {
		newAuthToken := &token{Validity: 5 * time.Minute}
		newAuthTokenString, err := newAuthToken.generateToken(&user{Username: refreshClaims.Username})
		if err != nil {
			a.l.Error("Error in generating tokens", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		tkn := &response{AuthToken: newAuthTokenString, RefreshToken: refreshToken}
		tkn.toJson(w)
		return

	} else {
		a.l.Info("Invalid token", "err", err)
		http.Error(w, "Invalid tokens", http.StatusBadRequest)
		return
	}

}

func (t *token) generateToken(user *user) (string, error) {
	expiration := time.Now().Add(t.Validity)
	claims := &claim{
		Username: user.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expiration.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

func (t *token) tokenValidity() {

}

func (r *response) toJson(w io.Writer) error {
	e := json.NewEncoder(w)
	return e.Encode(r)
}

func (u *user) fromJson(r io.Reader) error {
	d := json.NewDecoder(r)
	return d.Decode(u)
}

func (rp *response) fromJson(r io.Reader) error {
	d := json.NewDecoder(r)
	return d.Decode(rp)
}

func (u *user) checkCreds() bool {
	if u.Username == "admin" && u.Password == "password" {
		return true
	}
	return false
}

func checkExpiry(c *claim) bool {
	return time.Unix(c.ExpiresAt, 0).Sub(time.Now()) < 30*time.Second
}
