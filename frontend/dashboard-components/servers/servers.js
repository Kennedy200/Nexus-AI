setTimeout(() => {
    const mockServers = [
        { name: 'Firewall-Main', ip: '10.0.0.1', type: 'Cisco ASA', status: 'online', rate: '240 logs/sec', totalToday: '1.2M' },
        { name: 'Web-Server-01', ip: '192.168.1.104', type: 'Ubuntu 22.04', status: 'online', rate: '85 logs/sec', totalToday: '420K' },
        { name: 'Database-Cluster', ip: '192.168.1.200', type: 'PostgreSQL Linux', status: 'warning', rate: '12 logs/sec', totalToday: '95K' },
        { name: 'Auth-Server-02', ip: '192.168.1.105', type: 'Windows Server 2022', status: 'online', rate: '45 logs/sec', totalToday: '180K' }
    ];

    const grid = document.getElementById('servers-grid');
    const modal = document.getElementById('add-server-modal');
    const btnAddServer = document.getElementById('btn-add-server');
    const modalCloseX = document.getElementById('modal-server-close');
    const btnCancel = document.getElementById('btn-modal-cancel');
    const btnCopy = document.getElementById('btn-copy-script');
    const installScript = document.getElementById('install-script');
    const typeBtns = document.querySelectorAll('.type-btn');

    function renderServers() {
        if (!grid) return;
        grid.innerHTML = '';
        mockServers.forEach(server => {
            const card = document.createElement('div');
            card.className = 'server-card';

            const statusClass = server.status === 'online' ? 'status-online' : 'status-warning';
            const statusLabel = server.status === 'online' ? 'Streaming' : 'High Latency';

            card.innerHTML = `
                <div>
                    <div class="server-card-top">
                        <div class="server-info-header">
                            <div class="server-icon-box">
                                <i class="fa-solid fa-server"></i>
                            </div>
                            <div>
                                <div class="server-name">${server.name}</div>
                                <div class="server-ip">${server.ip}</div>
                            </div>
                        </div>
                        <span class="status-pill ${statusClass}">
                            <span class="status-dot"></span> ${statusLabel}
                        </span>
                    </div>

                    <div class="server-metrics">
                        <div>
                            <div class="metric-label">Rate</div>
                            <div class="metric-val">${server.rate}</div>
                        </div>
                        <div>
                            <div class="metric-label">Today</div>
                            <div class="metric-val">${server.totalToday}</div>
                        </div>
                    </div>
                </div>

                <div class="server-card-footer">
                    <span>OS: <strong>${server.type}</strong></span>
                    <button class="btn-icon" title="Server Settings"><i class="fa-solid fa-ellipsis-vertical"></i></button>
                </div>
            `;
            grid.appendChild(card);
        });
    }

    // Modal Triggers
    if (btnAddServer && modal) {
        btnAddServer.addEventListener('click', () => {
            modal.classList.remove('hidden');
        });
    }

    function closeModal() { 
        if (modal) modal.classList.add('hidden'); 
    }
    
    if (modalCloseX) modalCloseX.addEventListener('click', closeModal);
    if (btnCancel) btnCancel.addEventListener('click', closeModal);

    if (modal) {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeModal();
        });
    }

    // Toggle Linux / Windows installation script preview
    typeBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            typeBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            const type = btn.getAttribute('data-type');
            if (type === 'linux') {
                installScript.innerText = "curl -sSL https://get.nexusai.com/agent.sh | bash -s -- --token nx_agent_8f92j3n8v47";
            } else {
                installScript.innerText = "iex ((New-Object System.Net.WebClient).DownloadString('https://get.nexusai.com/agent.ps1'))";
            }
        });
    });

    // Copy Installer Script
    if (btnCopy) {
        btnCopy.addEventListener('click', () => {
            navigator.clipboard.writeText(installScript.innerText);
            btnCopy.innerHTML = `<i class="fa-solid fa-check"></i> Copied!`;
            setTimeout(() => {
                btnCopy.innerHTML = `<i class="fa-regular fa-copy"></i> Copy Installation Script`;
            }, 2000);
        });
    }

    renderServers();
}, 150);