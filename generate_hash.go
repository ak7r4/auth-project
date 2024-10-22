package main

import (
    "bufio"
    "fmt"
    "golang.org/x/crypto/bcrypt"
    "os"
)

func main() {
    // Cria um scanner para ler a entrada do usuário
    scanner := bufio.NewScanner(os.Stdin)

    // Solicita ao usuário que insira o nome de usuário
    fmt.Print("Digite o nome de usuário: ")
    scanner.Scan()
    username := scanner.Text()

    // Solicita ao usuário que insira a senha
    fmt.Print("Digite a senha: ")
    scanner.Scan()
    password := scanner.Text()

    // Gera o hash da senha
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        fmt.Println("Erro ao gerar hash:", err)
        return
    }

    // Aqui você pode inserir o usuário no banco de dados
    // Exemplo de comando SQL (não execute aqui, é só para referência)
    // INSERT INTO users (username, password) VALUES (username, hashedPassword)
    
    fmt.Printf("Usuário '%s' adicionado com a senha hashada: %s\n", username, string(hashedPassword))
}
