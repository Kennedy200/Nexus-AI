setTimeout(() => {
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', (e) => {
            e.preventDefault();
            
            // BACKEND NOTE: Clear user tokens or cookies here if applicable
            // localStorage.removeItem('authToken');
            
            console.log("User logged out successfully.");
            
            // Redirect to landing page
            window.location.href = "index.html";
        });
    }
}, 100);