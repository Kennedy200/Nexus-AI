async function loadComponent(elementId, folderName) {
    try {
        const response = await fetch(`components/${folderName}/${folderName}.html`);
        
        // This stops the 404 text from injecting into your page!
        if (!response.ok) {
            console.warn(`Component ${folderName} not found yet.`);
            return; 
        }

        const html = await response.text();
        document.getElementById(elementId).innerHTML = html;

        // Dynamically load the component's CSS file
        const link = document.createElement('link');
        link.rel = 'stylesheet';
        link.href = `components/${folderName}/${folderName}.css`;
        document.head.appendChild(link);

    } catch (error) {
        console.error(`Error loading component: ${folderName}`, error);
    }
}

// Load all landing page components in order
document.addEventListener("DOMContentLoaded", () => {
    loadComponent("header-container", "header");
    loadComponent("hero-container", "hero");
    loadComponent("features-container", "features");
    loadComponent("how-it-works-container", "how-it-works");
    loadComponent("about-container", "about");
    loadComponent("contact-container", "contact");
    loadComponent("footer-container", "footer");
});