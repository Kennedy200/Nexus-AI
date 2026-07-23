setTimeout(async () => {
    // 1. Fetch Backend Data
    const stats = await NexusAPI.getOverviewStats();
    
    // 2. Update UI
    document.getElementById('kpi-logs').innerText = stats.totalLogs;
    document.getElementById('kpi-anomalies').innerText = stats.anomalies;
    document.getElementById('kpi-critical').innerText = stats.critical;
    document.getElementById('kpi-level').innerText = stats.threatLevel;

    // 3. Initialize Sleek Chart.js
    const ctx = document.getElementById('dashboardChart').getContext('2d');
    
    // Create a sleek gradient fill
    const gradient = ctx.createLinearGradient(0, 0, 0, 300);
    gradient.addColorStop(0, 'rgba(37, 99, 235, 0.4)'); // Blue at top
    gradient.addColorStop(1, 'rgba(37, 99, 235, 0.0)'); // Transparent at bottom

    new Chart(ctx, {
        type: 'line', // Changed from bar to line
        data: {
            labels: ['1AM', '2AM', '3AM', '4AM', '5AM'],
            datasets: [{
                label: 'Log Volume',
                data: [100, 150, 15000, 200, 50],
                borderColor: '#2563eb', // Solid blue line
                backgroundColor: gradient, // Gradient fill
                borderWidth: 3,
                pointBackgroundColor: '#ffffff',
                pointBorderColor: '#2563eb',
                pointBorderWidth: 2,
                pointRadius: 4,
                fill: true,
                tension: 0.4 // This makes the line curved and smooth!
            }]
        },
        options: { 
            responsive: true, 
            maintainAspectRatio: false,
            plugins: { legend: { display: false } }, // Hides the legend
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { display: false }, // Hides horizontal grid lines
                    border: { display: false }
                },
                x: {
                    grid: { display: false }, // Hides vertical grid lines
                    border: { display: false }
                }
            }
        }
    });
}, 100);