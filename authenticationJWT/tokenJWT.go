package authenticationJWT

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

const (
	tokenKeySecret = "TESTECHAVE"
)

// CreateToken retorna um token assinado com as permissões do usuario
func CreateToken(userID uint64) (string, error) {

	permissions := jwt.MapClaims{}
	permissions["authorized"] = true
	permissions["exp"] = time.Now().Add(time.Hour * 6).Unix()
	permissions["usuarioId"] = userID

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, permissions)

	return token.SignedString([]byte(tokenKeySecret)) //Secret

}

// ValidateToken verifica se token passado pela requisição é válido
func ValidateToken(r *http.Request) error {

	tokenString := extractToken(r)

	token, erro := jwt.Parse(tokenString, returnVerificationKey)
	if erro != nil {
		//fmt.Print("Entrou no jwt.Parse do ValidateToken")
		return erro
	}

	if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return nil
	}

	return errors.New("Invalid Token")
}

func ExtractUserID(r *http.Request) (uint64, error) {

	tokenString := extractToken(r)

	token, erro := jwt.Parse(tokenString, returnVerificationKey)
	if erro != nil {
		return 0, erro
	}

	if permissions, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		usuarioID, erro := strconv.ParseUint(fmt.Sprintf("%.0f", permissions["usuarioId"]), 10, 64)
		if erro != nil {
			return 0, errors.New("Unexpected user extraction error!")
		}

		return usuarioID, nil
	}

	return 0, errors.New("Invalid Token")
}

func extractToken(r *http.Request) string {

	token := r.Header.Get("Authorization")

	if len(strings.Split(token, " ")) == 2 {
		return strings.Split(token, " ")[1]
	}

	return ""
}

func returnVerificationKey(token *jwt.Token) (interface{}, error) {

	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {

		return nil, fmt.Errorf("Unexpected signature method! %v", token.Header["alg"])
	}

	return []byte(tokenKeySecret), nil

}
