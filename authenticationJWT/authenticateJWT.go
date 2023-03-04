package authenticationJWT

import (
	"encoding/json"
	"log"
	"net/http"
)

// Logger escreve informações da requisição no terminal para visualização
func Logger(nextFunction http.HandlerFunc) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("\n %s %s %s", r.Method, r.RequestURI, r.Host)
		nextFunction(w, r)
	}

}

// Authenticate verifica se o usuário faz a requisição autenticado
func Authenticate(nextFunction http.HandlerFunc, isAuthenticated bool) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		if isAuthenticated {
			if erro := ValidateToken(r); erro != nil {
				errorInternal(w, http.StatusUnauthorized, erro)
				return
			}
		}

		nextFunction(w, r)
	}

}

// jsonInternal retorna uma resposta em Json para requisição
func jsonInternal(w http.ResponseWriter, statusCode int, dados interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if dados != nil {
		if erro := json.NewEncoder(w).Encode(dados); erro != nil {
			log.Fatal(erro)
		}
	}
}

// errorInternal retorna uma erro em formato Json
func errorInternal(w http.ResponseWriter, statusCode int, erro error) {
	jsonInternal(w, statusCode, struct {
		Erro string `json:"erro"`
	}{
		Erro: erro.Error(),
	})
}
