package main

import (
	"fmt"
	"net/http"
)

func main() {
	// Função que responde a uma rota específica
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Olá! Esta é a página inicial.")
	})

	// Inicializa o servidor web na porta 8080
	http.ListenAndServe(":8080", nil)
}
