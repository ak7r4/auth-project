<h1>Login Page Project</h1><br>
<br>
## ⚠️ This repo is depricated, I created 2 new repositories for this project.<br>
## Basicaly this is a monolithic and in the new repositories I separated the frontend from the backend. <br>
## Checkout: [Front-end](https://github.com/ak7r4/Auth-Front) and Back-end (comming soon)
<br>
Project created to improve my programming skills.<br>
This is a login page that has the following architecture:
<br><br><br>

![image](https://github.com/user-attachments/assets/68c52c9a-c838-41ab-b383-caec99a3dd6e)


How to set up your database as the application expects:
```
CREATE DATABASE golang_api;
USE golang_api;
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL
);
CREATE TABLE sessions (
    cookie VARCHAR(255) PRIMARY KEY,
    user_id TEXT,
    expires_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```
.env example:
```
DB_HOST=localhost
DB_USERNAME=root
DB_PASSWORD='root'
DB_DATABASE=golang_api
DB_PORT=3306
SECRET_KEY=Secret_key_to_encrypt_cookies
```
