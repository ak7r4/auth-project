package main

import (
    "database/sql"
    "fmt"
    "log"
    "os"
    "path/filepath"
    "html/template"
    "net/http"
    "net/url"
    "strings"
    "unicode"
    "crypto/rand"
    "encoding/base64"
    "time"
    "github.com/gin-gonic/gin"
    "github.com/gin-contrib/sessions"
    "github.com/gin-contrib/sessions/cookie"
    "github.com/go-sql-driver/mysql"
    "github.com/joho/godotenv"
    "golang.org/x/crypto/bcrypt"
    "encoding/json"
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

func cleanExpiredSessions() {
    _, err := db.Exec("DELETE FROM sessions WHERE expires_at < NOW()")
    if err != nil {
        log.Println("Error cleaning expired sessions:", err)
    }
}

// Generate sessions to use in logout feature
func generateSessionID() string {
        b := make([]byte, 32)
        _, err := rand.Read(b)
        if err != nil {
                panic(err)
        }
        return base64.StdEncoding.EncodeToString(b)
}

// Middleware to ensure the user is authenticated
func authRequired(c *gin.Context) {
    session := sessions.Default(c)
    user := session.Get("user")
    sessionID := session.Get("sessionID")
    var exists bool
    err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM sessions WHERE cookie = ?)", sessionID).Scan(&exists)
    if err != nil {
        log.Println("Error checking session in database:", err)
        c.Redirect(http.StatusSeeOther, "/login")
        c.Abort()
        return
    }
    // Se o usuário não estiver autenticado, redireciona para /login
    if !exists {
        log.Println("Session not found in database, redirecting to /login")
        c.Redirect(http.StatusSeeOther, "/login")
        c.Abort()
        return
    }
    // Se o usuário não estiver autenticado, redireciona para /login
    if user == nil || sessionID == nil {
        log.Println("No active session, redirecting to /login")
        c.Redirect(http.StatusSeeOther, "/login")
        c.Abort()
        return
    }
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

    if !validateRecaptcha(c) {
        return
    }

    // Validações de campos obrigatórios, tamanho e correspondência de senhas
    if username == "" || password == "" || rpassword == "" {
        render(c, "templates/signup.html", gin.H{"ErrorMessage": "All fields are required."})
        return
    }
    if len(username) > 50 {
        render(c, "templates/signup.html", gin.H{"ErrorMessage": "The username cannot exceed 50 characters."})
        return
    }
    if len(password) > 150 {
        render(c, "templates/signup.html", gin.H{"ErrorMessage": "The password cannot exceed 150 characters."})
        return
    }
    if len(rpassword) > 150 {
        render(c, "templates/signup.html", gin.H{"ErrorMessage": "The password cannot exceed 150 characters."})
        return
    }
    if password != rpassword {
        render(c, "templates/signup.html", gin.H{"ErrorMessage": "Passwords do not match"})
        return
    }
    if !validatePassword(password) {
        render(c, "templates/signup.html", gin.H{"ErrorMessage": "The password must be at least 12 characters long and include an uppercase letter, a lowercase letter, a number, and a special character."})
        return
    }

    // Cria o usuário no banco de dados
    err := createUser(username, password)
    if err != nil {
        if err.Error() == "username already exists" {
            render(c, "templates/signup.html", gin.H{"ErrorMessage": "Username already exists. Please choose another."})
            return
        }
        log.Println("Erro ao criar usuário:", err)
        render(c, "templates/signup.html", gin.H{"ErrorMessage": "Error creating account. Please try again."})
        return
    }

    log.Println("Usuário criado com sucesso:", username)
    render(c, "templates/signup.html", gin.H{"SuccessMessage": "User created successfully!"})

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

    if len(currentPassword) > 150 {
        render(c, "templates/signup.html", gin.H{"ErrorMessage": "The password cannot exceed 150 characters."})
        return
    }
    if newPassword != retypeNewPassword {
        render(c, "templates/change.html", gin.H{"ErrorMessage": "The new passwords do not match."})
        return
    }
    if len(newPassword) > 150 {
        render(c, "templates/signup.html", gin.H{"ErrorMessage": "The password cannot exceed 150 characters."})
        return
    }
    if len(retypeNewPassword) > 150 {
        render(c, "templates/signup.html", gin.H{"ErrorMessage": "The password cannot exceed 150 characters."})
        return
    }

    // Verificar se a nova senha atende aos requisitos de segurança
    if !validatePassword(newPassword) {
        render(c, "templates/change.html", gin.H{"ErrorMessage": "Password must be at least 12 characters, with at least one uppercase letter, one lowercase letter, one number, and one special character."})
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
    render(c, "templates/change.html", gin.H{"SuccessMessage": "Password updated successfully!"})
}


// Estrutura para receber a resposta do reCAPTCHA
type RecaptchaResponse struct {
	Success bool `json:"success"`
	Errors	[]string `json:"error-codes"`
}

func verifyRecaptcha(responseToken string) bool {
	verifyURL := "https://www.google.com/recaptcha/api/siteverify"

        //Recaptcha key
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Erro ao carregar o arquivo .env")
	}
        var secretKey = os.Getenv("SECRET_CAPTCHA")

	// Construir os dados da requisição
	data := url.Values{}
	data.Set("secret", secretKey)
	data.Set("response", responseToken)

	// Fazer a requisição ao Google
	resp, err := http.Post(verifyURL, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		fmt.Println("Erro ao conectar ao reCAPTCHA:", err)
		return false
	}
	defer resp.Body.Close()

	// Decodificar a resposta
	var result RecaptchaResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Println("Erro ao decodificar resposta do reCAPTCHA:", err)
		return false
	}
	if !result.Success {
        	fmt.Println("Erro na verificação do reCAPTCHA:", result.Errors)
    	}

	return result.Success
}

//funcao para reutilizar para validar a resposta do recaptcha
func validateRecaptcha(c *gin.Context) bool {
    recaptchaResponse := c.DefaultPostForm("g-recaptcha-response", "")

    if recaptchaResponse == "" {
        fmt.Println("Erro: reCAPTCHA ausente") // Debug
        c.JSON(http.StatusBadRequest, gin.H{"error": "reCAPTCHA obrigatório"})
        return false
    }

    if !verifyRecaptcha(recaptchaResponse) {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "reCAPTCHA inválido"})
        return false
    }
    return true
}

// Handle login logic
func handleLogin(c *gin.Context) {
    if c.Request.Method == http.MethodGet {
        c.HTML(http.StatusOK, "pagina.html", gin.H{
            "ErrorMessage": "",
        })
        return
    }

    username := c.PostForm("username")
    password := c.PostForm("password")

    if !validateRecaptcha(c) {
        return
    }

    if username == "" || password == "" {
        c.HTML(http.StatusOK, "pagina.html", gin.H{
            "ErrorMessage": "Incorrect username or password.",
        })
        return
    }

    if len(username) > 50 || len(password) > 300 {
        c.HTML(http.StatusOK, "pagina.html", gin.H{
            "ErrorMessage": "Incorrect username or password.",
        })
        return
    }

    // Search for the user in the database
    var storedHash string
    err := db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&storedHash)
    if err != nil {
        c.HTML(http.StatusOK, "pagina.html", gin.H{
            "ErrorMessage": "Incorrect username or password.",
        })
        return
    }

    // Verify the password
    err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password))
    if err != nil {
        c.HTML(http.StatusOK, "pagina.html", gin.H{
            "ErrorMessage": "Incorrect username or password.",
        })
        return
    }

    // Store session
    sessionID := generateSessionID()
    session := sessions.Default(c)
    session.Set("user", username)
    session.Set("sessionID", sessionID)
    if err := session.Save(); err != nil {
        c.HTML(http.StatusOK, "pagina.html", gin.H{
		"ErrorMessage": "Error saving the session, please try again.",
        })
        log.Println("Erro ao salvar sessão:", err)
        return
    }
    _, err = db.Exec("INSERT INTO sessions (cookie, user_id, expires_at) VALUES (?, ?, ?)", sessionID, username, time.Now().Add(30 * time.Minute))
    if err != nil {
        c.HTML(http.StatusOK, "pagina.html", gin.H{
            "ErrorMessage": "Error saving session to database please try again",
        })
        log.Println("Error inserting session into database:", err)
        return
    }
    cleanExpiredSessions()
    log.Println("User logged in successfully:", username)
    // Redirect to success page
    c.Redirect(http.StatusSeeOther, "/success")
}

func handleLogout(c *gin.Context) {
    session := sessions.Default(c)
    sessionID := session.Get("sessionID")
    _, err := db.Exec("DELETE FROM sessions WHERE cookie = ?", sessionID)
    if err != nil {
        log.Println("Error removing from database:", err)
        render(c, "templates/pagina.html", gin.H{"ErrorMessage": "Error removing from database, please try again."})
        return
    }
    user := session.Get("user")
    log.Println("User logged out: ", user)
    session.Clear()
    session.Save()
    c.Redirect(http.StatusSeeOther, "/login")
}

func main() {
    // Initialize the database
    initDB()

    // Initialize the Gin router
    r := gin.Default()
    r.LoadHTMLGlob("templates/pagina.html")

    // Change to Secure True when finish
    secretKey := os.Getenv("SECRET_KEY")
    store := cookie.NewStore([]byte(secretKey))
    store.Options(sessions.Options{
        Path:     "/",
        HttpOnly: true,
        Secure:   false,
        MaxAge:   1800,
    })
    r.Use(sessions.Sessions("session", store))

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
