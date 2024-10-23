document.querySelector('form').addEventListener('submit', function(e) {
    var username = document.getElementById('username').value;
    var password = document.getElementById('password').value;

    // Aqui você pode fazer a validação antes de enviar o formulário
    if (username === "" || password === "") {
        e.preventDefault(); // Impede o envio do formulário
        alert("Por favor, preencha todos os campos.");
    }
});
