package main

import (
    "database/sql"
    "fmt"
    "log"
    "os"
    "path/filepath"
    "html/template"
    "net/http"
    "unicode"
    "github.com/gin-gonic/gin"
    "github.com/gin-contrib/sessions"
    "github.com/gin-contrib/sessions/cookie"
    "github.com/go-sql-driver/mysql"
    "github.com/joho/godotenv"
    "golang.org/x/crypto/bcrypt"
//    "regexp"
)

var db *sql.DB

// Initializes the connection to the database
func initDB() {
    var err error

    // Load environment variables from .env file in config directory
    envPath := filepath.Join("config", ".env")
    err = godotenv.Load(envPath)
    if err != nil {
        log.Fatal("Error loading .env file:", err)
    }

    // Retrieve configuration from environment variables
    username := os.Getenv("DB_USERNAME")
    password := os.Getenv("DB_PASSWORD")
    database := os.Getenv("DB_DATABASE")
    host := os.Getenv("DB_HOST")
    port := os.Getenv("DB_PORT")

    dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s",
        username, password, host, port, database)

    db, err = sql.Open("mysql", dsn)
    if err != nil {
        log.Fatal("Error connecting to the database:", err)
    }

    // Check the connection
    if err := db.Ping(); err != nil {
        log.Fatal("Error connecting to the database:", err)
    }
}

// Renders an HTML page
func render(c *gin.Context, tmpl string, data gin.H) {
    t, err := template.ParseFiles(tmpl)
    if err != nil {
        c.String(http.StatusInternalServerError, "Template error")
        return
    }
    t.Execute(c.Writer, data)
}

// Middleware to ensure the user is authenticated
func authRequired(c *gin.Context) {
    session := sessions.Default(c)
    user := session.Get("user")
    if user == nil {
        log.Println("No active session, redirecting to /login")
        // Se o usuário não estiver autenticado, redireciona para /login
        c.Redirect(http.StatusSeeOther, "/login")
        c.Abort()
        return
    }
    log.Println("User authenticated:", user)
    // Se o usuário estiver autenticado, permite o acesso
    c.Next()
}

// Insert into database credentials
func createUser(username, password string) error {
    // Gera o hash da senha
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        return err
    }

    // Executa o comando de inserção no banco de dados
    _, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", username, hashedPassword)
    if err != nil {
        // Verifica se o erro é de duplicação de nome de usuário
        if mysqlErr, ok := err.(*mysql.MySQLError); ok && mysqlErr.Number == 1062 { // código 1062 para chave duplicada no MySQL
            return fmt.Errorf("username already exists")
        }
        return err
    }

    return nil
}

// Strong password policy
func validatePassword(password string) bool {
    var hasMinLen, hasUpper, hasLower, hasNumber, hasSpecial bool
    if len(password) >= 12 {
        hasMinLen = true
    }
    for _, char := range password {
        switch {
        case unicode.IsUpper(char):
            hasUpper = true
        case unicode.IsLower(char):
            hasLower = true
        case unicode.IsDigit(char):
            hasNumber = true
        case unicode.IsPunct(char) || unicode.IsSymbol(char):
            hasSpecial = true
        }
    }
    return hasMinLen && hasUpper && hasLower && hasNumber && hasSpecial
}

// Handle signup logic
func handleSignup(c *gin.Context) {
    username := c.PostForm("username")
    password := c.PostForm("password")
    rpassword := c.PostForm("rpassword")

    // Validações de campos obrigatórios, tamanho e correspondência de senhas
    if username == "" || password == "" || rpassword == "" {
        render(c, "templates/signup.html", gin.H{"ErrorMessage": "Todos os campos são obrigatórios."})
        return
    }
    if len(username) > 50 {
        render(c, "templates/signup.html", gin.H{"ErrorMessage": "O nome de usuário não pode ter mais de 50 caracteres."})
        return
    }
    if password != rpassword {
        render(c, "templates/signup.html", gin.H{"ErrorMessage": "As senhas não coincidem."})
        return
    }
    if !validatePassword(password) {
        render(c, "templates/signup.html", gin.H{"ErrorMessage": "A senha deve ter pelo menos 12 caracteres, incluindo uma letra maiúscula, uma letra minúscula, um número e um caractere especial."})
        return
    }

    // Cria o usuário no banco de dados
    err := createUser(username, password)
    if err != nil {
        if err.Error() == "username already exists" {
            render(c, "templates/signup.html", gin.H{"ErrorMessage": "Nome de usuário já existe. Escolha outro."})
            return
        }
        log.Println("Erro ao criar usuário:", err)
        render(c, "templates/signup.html", gin.H{"ErrorMessage": "Erro ao criar conta. Tente novamente."})
        return
    }

    // Redireciona para a página de login após criar o usuário com sucesso
    c.Redirect(http.StatusSeeOther, "/login")
}


// handleChangePassword handles the password change logic
func handleChangePassword(c *gin.Context) {
    session := sessions.Default(c)
    username := session.Get("user").(string)

    //username := c.PostForm("username")
    currentPassword := c.PostForm("current_password")
    newPassword := c.PostForm("new_password")
    retypeNewPassword := c.PostForm("retype_new_password")

    if c.Request.Method == http.MethodGet {
        render(c, "templates/change.html", gin.H{"ErrorMessage": ""})
        return
    }

    if newPassword != retypeNewPassword {
        render(c, "templates/change.html", gin.H{"ErrorMessage": "The new passwords do not match."})
        return
    }

    // Verificar se a nova senha atende aos requisitos de segurança
//    passwordRegex := `^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$`
//    if matched, _ := regexp.MatchString(passwordRegex, newPassword); !matched {
//        render(c, "templates/change.html", gin.H{"ErrorMessage": "Password must be at least 12 characters, with at least one uppercase letter, one lowercase letter, one number, and one special character."})
//        return
//    }

    if !validatePassword(newPassword) {
        render(c, "templates/change.html", gin.H{"ErrorMessage": "Password must be at least 12 characters, with at least one uppercase letter, one lowercase letter, one number, and one special character."})
        return
    }

    // Fetch the stored hash for the user
    var storedHash string
    err := db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&storedHash)
    if err != nil {
        render(c, "templates/change.html", gin.H{"ErrorMessage": "Invalid current password."})
        return
    }

    // Verifica se a senha atual está correta
    if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(currentPassword)); err != nil {
        render(c, "templates/change.html", gin.H{"ErrorMessage": "Invalid current password."})
        return
    }

    // Gerar o hash da nova senha
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
    if err != nil {
        render(c, "templates/change.html", gin.H{"ErrorMessage": "An error occurred while processing your request."})
        return
    }

    // Atualizar a senha no banco de dados
    _, err = db.Exec("UPDATE users SET password = ? WHERE username = ?", hashedPassword, username)
    if err != nil {
        render(c, "templates/change.html", gin.H{"ErrorMessage": "An error occurred while updating your password."})
        return
    }

    log.Println("Password updated successfully for user:", username)
    render(c, "templates/change.html", gin.H{"ErrorMessage": "Password updated successfully!"})
}


// Handle login logic
func handleLogin(c *gin.Context) {
    if c.Request.Method == http.MethodGet {
        render(c, "templates/pagina.html", gin.H{"ErrorMessage": ""})
        return
    }

    username := c.PostForm("username")
    password := c.PostForm("password")

    if username == "" || password == "" {
        render(c, "templates/pagina.html", gin.H{"ErrorMessage": "Usuário ou senha incorretos."})
        return
    }

    if len(username) > 50 || len(password) > 300 {
        render(c, "templates/pagina.html", gin.H{"ErrorMessage": "Usuário ou senha incorretos."})
        return
    }

    // Search for the user in the database
    var storedHash string
    err := db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&storedHash)
    if err != nil {
        render(c, "templates/pagina.html", gin.H{"ErrorMessage": "Usuário ou senha incorretos."})
        return
    }

    // Verify the password
    err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password))
    if err != nil {
        render(c, "templates/pagina.html", gin.H{"ErrorMessage": "Usuário ou senha incorretos."})
        return
    }

    // Store session
    session := sessions.Default(c)
    session.Set("user", username)
    if err := session.Save(); err != nil {
        log.Println("Erro ao salvar sessão:", err)
        render(c, "templates/pagina.html", gin.H{"ErrorMessage": "Erro ao salvar a sessão. Tente novamente."})
        return
    }

    log.Println("User logged in successfully:", username)
    // Redirect to success page
    c.Redirect(http.StatusSeeOther, "/success")
}

func handleLogout(c *gin.Context) {
    session := sessions.Default(c)
    session.Clear()  // Limpa todos os dados da sessão
    session.Save()   // Salva a sessão vazia para encerrar
    log.Println("User logged out")
    c.Redirect(http.StatusSeeOther, "/login")  // Redireciona para a página de login
}

func main() {
    // Initialize the database
    initDB()

    // Initialize the Gin router
    r := gin.Default()

    // Session store middleware (using cookie store for simplicity)
    store := cookie.NewStore([]byte("hjkasd123789hiduwsSDFFDVGFGHJ45634557689HGDHFGDGDZXFHJSDFGNDSdfgsdfgsdfg4356ergh456hsb324v45h5e67kjDFGSDFG345435yudZGDZFGSDFG"))
    store.Options(sessions.Options{
	Path:     "/",
	HttpOnly: true,
	Secure:   false,
	MaxAge:   50,
    })
    r.Use(sessions.Sessions("mysession", store))

    // Serve static files from the assets directory
    r.Static("/assets", "./assets")

    // Public routes
    r.GET("/login", handleLogin)
    r.POST("/login", handleLogin)

    r.POST("/signup", handleSignup)  

    // Protected routes (require authentication)
    r.GET("/success", authRequired, func(c *gin.Context) {
        render(c, "templates/autenticado.html", gin.H{})
    })
    r.POST("/success", authRequired, func(c *gin.Context) {
        render(c, "templates/autenticado.html", gin.H{})
    })

    // Protected routes (require authentication)
    r.POST("/change", handleChangePassword)
    r.GET("/change", authRequired, func(c *gin.Context) {
        render(c, "templates/change.html", gin.H{})
    })

    // Root route redirects to login
    r.GET("/", func(c *gin.Context) {
        c.Redirect(http.StatusSeeOther, "/login")
    })

    // Root route redirects to signup
    r.GET("/signup", func(c *gin.Context) {
        render(c, "templates/signup.html", gin.H{})
    })

    r.POST("/logout", handleLogout)
    r.GET("/logout", func(c *gin.Context) {
        c.Redirect(http.StatusSeeOther, "/login")
    })

    r.POST("/change_password", authRequired, handleChangePassword)

    // Start the server on port 8080
    log.Println("Server running on port 8080...")
    r.Run(":8080")

}
