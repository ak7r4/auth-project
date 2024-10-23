document.addEventListener("DOMContentLoaded", function() {
    const errorMessage = new URLSearchParams(window.location.search).get('error');
    if (errorMessage) {
        const errorDiv = document.createElement('div');
        errorDiv.textContent = errorMessage;
        errorDiv.style.color = 'red';
        errorDiv.style.marginBottom = '15px';
        document.querySelector('.login-container').insertBefore(errorDiv, document.querySelector('form'));
    }
});
