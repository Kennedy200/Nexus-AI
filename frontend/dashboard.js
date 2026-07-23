// --- BACKEND API CONNECTOR ---
const NexusAPI = {
    BASE_URL: "http://localhost:8000/api",
    
    getOverviewStats: async () => {
        return {
            totalLogs: "145,200",
            anomalies: 34,
            critical: 2,
            threatLevel: "High"
        };
    },

    uploadLog: async (file) => {
        console.log(`Uploading ${file.name} to Python Backend...`);
        return { status: "success", message: "File processing started." };
    }
};

// --- COMPONENT & ROUTING ENGINE ---
async function loadDashboardComponent(elementId, folderName, loadScript = false) {
    try {
        const basePath = `dashboard-components/${folderName}`;
        const response = await fetch(`${basePath}/${folderName}.html`);
        if (!response.ok) return;

        document.getElementById(elementId).innerHTML = await response.text();

        // Load CSS dynamically
        if (!document.querySelector(`link[href="${basePath}/${folderName}.css"]`)) {
            const link = document.createElement('link');
            link.rel = 'stylesheet';
            link.href = `${basePath}/${folderName}.css`;
            document.head.appendChild(link);
        }

        // Only load JS file if explicitly specified for views that need it
        if (loadScript) {
            // Remove previous instances of the script if switching back
            const oldScript = document.getElementById(`script-${folderName}`);
            if (oldScript) oldScript.remove();

            const script = document.createElement('script');
            script.id = `script-${folderName}`;
            script.src = `${basePath}/${folderName}.js`;
            document.body.appendChild(script);
        }
    } catch (error) { 
        console.error(`Failed to load ${folderName}:`, error); 
    }
}

// Router: Changes the main content area when sidebar links are clicked
window.navigateTo = function(viewFolder) {
    // FIXED: Added 'servers' to this list so its JS file loads properly!
    const viewsWithJS = ['overview', 'log-ingestion', 'ai-investigator', 'threat-alerts', 'servers', 'settings'];
    const hasScript = viewsWithJS.includes(viewFolder);

    loadDashboardComponent("main-content", viewFolder, hasScript);
    
    // Highlight the active sidebar link
    document.querySelectorAll('.sidebar-nav li, .sidebar-bottom li').forEach(li => li.classList.remove('active'));
    const activeLink = document.querySelector(`[onclick="navigateTo('${viewFolder}')"]`);
    if(activeLink && activeLink.parentElement) {
        activeLink.parentElement.classList.add('active');
    }
}

// Initial Load
document.addEventListener("DOMContentLoaded", async () => {
    await loadDashboardComponent("sidebar-container", "sidebar", true);
    await loadDashboardComponent("header-container", "header", false);
    
    // Load Overview by default
    navigateTo('overview'); 
});