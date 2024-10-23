document.addEventListener("DOMContentLoaded", function() {
    const params = new URLSearchParams(window.location.search);
    const error = params.get("error");

    if (error) {
        const errorMessage = document.createElement("p");
        errorMessage.textContent = "Usuário ou senha incorreto";
        errorMessage.style.color = "red";
        const form = document.querySelector("form");
        form.parentElement.insertBefore(errorMessage, form);
    }
});
