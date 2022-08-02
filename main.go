package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

var (
	hmacSampleSecret = []byte("mysupersecretkey")
)

type CustomClaims struct {
	jwt.StandardClaims
	Sum   string
	Roles []string
}

func secureHandler(rw http.ResponseWriter, req *http.Request) {
	fmt.Fprintln(rw, "Secure route")
}

func validateToken(tokenString string) (CustomClaims, error) {
	var claims CustomClaims
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return hmacSampleSecret, nil
	})

	if err != nil {
		return claims, err
	}

	if token.Valid {
		return claims, nil
	} else {
		return claims, err
	}
}

func generateToken(sum string) (string, error) {
	// Create a new token object, specifying signing method and the claims
	// you would like it to contain.
	claims := CustomClaims{
		Sum:   sum,
		Roles: []string{"ADMIN"},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(hmacSampleSecret)

	return tokenString, err
}

func authMiddleware(handler http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {

		authz := req.Header.Get("Authorization")
		if len(authz) == 0 {
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}

		tokenString := strings.Split(authz, " ")[1]

		claims, err := validateToken(tokenString)
		if err != nil {
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}

		fmt.Println(claims)

		handler(rw, req)
		fmt.Println("Pós-mid")
	}
}

func homeHandler(rw http.ResponseWriter, req *http.Request) {
	token, err := generateToken("robson")
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	fmt.Fprintln(rw, token)
}

func main() {

	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/secure", authMiddleware(secureHandler))

	http.ListenAndServe(":8000", nil)
}
