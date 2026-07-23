document.addEventListener("DOMContentLoaded", () => {
    
    const loginForm = document.getElementById('loginForm');
    const signupForm = document.getElementById('signupForm');

    // Handle Login Routing
    if (loginForm) {
        loginForm.addEventListener('submit', (e) => {
            e.preventDefault(); // Stop default form submission
            
            // BACKEND NOTE: Call API here to verify user
            // e.g., await fetch('/api/login', { body: email/password })
            
            console.log("Mock Login Successful");
            window.location.href = "dashboard.html"; // Route to dashboard
        });
    }

    // Handle Sign Up Routing
    if (signupForm) {
        signupForm.addEventListener('submit', (e) => {
            e.preventDefault(); // Stop default form submission
            
            // BACKEND NOTE: Call API here to create user
            // e.g., await fetch('/api/signup', { body: email/password })
            
            console.log("Mock Sign Up Successful");
            window.location.href = "dashboard.html"; // Route to dashboard
        });
    }
});