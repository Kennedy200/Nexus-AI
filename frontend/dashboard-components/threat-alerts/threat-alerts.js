setTimeout(() => {
    // Mock Data
    const mockThreats = [
        { id: 1, severity: 'Critical', time: '2026-07-22 04:15:10', server: 'Database-Cluster', category: 'Unauthorized DB Export', ip: '192.168.1.104', summary: 'A database dump command was executed immediately following a brute force SSH entry.', raw: '2026-07-22 04:15:10 Database-Cluster mysqldump: Dumped table users_audit to /tmp/dump.sql' },
        { id: 2, severity: 'Critical', time: '2026-07-22 03:45:00', server: 'Web-Server-01', category: 'Coordinated SSH Brute Force', ip: '192.168.1.104', summary: '15,420 failed login attempts detected within a 2-hour window.', raw: '2026-07-22 03:45:00 Web-Server-01 sshd[4012]: Failed password for invalid user root from 192.168.1.104' },
        { id: 3, severity: 'High', time: '2026-07-22 02:10:33', server: 'Firewall-Main', category: 'Port Scanning Activity', ip: '45.142.214.12', summary: 'Sequential SYN packets detected across 1,024 closed ports.', raw: '2026-07-22 02:10:33 Firewall-Main kernel: [BLOCK] IN=eth0 OUT= SRC=45.142.214.12 PROTO=TCP SYN' },
        { id: 4, severity: 'Medium', time: '2026-07-22 01:05:12', server: 'Web-Server-01', category: 'SQL Injection Attempt', ip: '185.220.101.5', summary: 'HTTP GET request contained malformed SQL payload in URL parameters.', raw: '2026-07-22 01:05:12 Web-Server-01 nginx: GET /api/user?id=1%20OR%201=1 HTTP/1.1 400' }
    ];

    const tbody = document.getElementById('threats-tbody');
    const searchInput = document.getElementById('alert-search');
    const filterBtns = document.querySelectorAll('.filter-btn');

    const modal = document.getElementById('threat-modal');
    const modalXBtn = document.getElementById('modal-close');
    const modalCloseBtn = document.getElementById('modal-close-btn');
    const modalInvestigateBtn = document.getElementById('modal-investigate-btn');

    let currentFilter = 'all';

    function renderTable(data) {
        tbody.innerHTML = '';
        if (data.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:30px; color:var(--text-muted);">No threats found matching criteria.</td></tr>`;
            return;
        }

        data.forEach(item => {
            const tr = document.createElement('tr');
            
            let badgeClass = 'badge-medium';
            if (item.severity === 'Critical') badgeClass = 'badge-critical';
            if (item.severity === 'High') badgeClass = 'badge-high';

            tr.innerHTML = `
                <td><span class="severity-badge ${badgeClass}">${item.severity}</span></td>
                <td>${item.time}</td>
                <td><strong>${item.server}</strong></td>
                <td>${item.category}</td>
                <td><code>${item.ip}</code></td>
                <td>
                    <div class="action-btns">
                        <button class="btn-icon" onclick="openThreatModal(${item.id})" title="View Details"><i class="fa-regular fa-eye"></i></button>
                        <button class="btn-icon" onclick="navigateTo('ai-investigator')" title="Investigate in AI Chat"><i class="fa-solid fa-robot"></i></button>
                    </div>
                </td>
            `;
            tbody.appendChild(tr);
        });
    }

    // Modal Global Opener Function
    window.openThreatModal = (id) => {
        const item = mockThreats.find(t => t.id === id);
        if (!item) return;

        const sevBadge = document.getElementById('modal-severity');
        sevBadge.innerText = item.severity;
        sevBadge.className = `severity-badge badge-${item.severity.toLowerCase()}`;

        document.getElementById('modal-server').innerText = item.server;
        document.getElementById('modal-time').innerText = item.time;
        document.getElementById('modal-summary').innerText = item.summary;
        document.getElementById('modal-raw-log').innerText = item.raw;

        modal.classList.remove('hidden');
    };

    // Close Modal Functions
    function closeModal() {
        modal.classList.add('hidden');
    }

    modalXBtn.addEventListener('click', closeModal);
    modalCloseBtn.addEventListener('click', closeModal);
    
    // Close modal if clicking outside on dark overlay
    modal.addEventListener('click', (e) => {
        if (e.target === modal) closeModal();
    });

    // "Investigate with AI" button handler
    modalInvestigateBtn.addEventListener('click', () => {
        closeModal();
        navigateTo('ai-investigator');
    });

    // Filtering
    filterBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            filterBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            currentFilter = btn.getAttribute('data-filter');
            applyFilters();
        });
    });

    searchInput.addEventListener('input', applyFilters);

    function applyFilters() {
        const query = searchInput.value.toLowerCase();
        const filtered = mockThreats.filter(item => {
            const matchesFilter = currentFilter === 'all' || item.severity === currentFilter;
            const matchesQuery = item.server.toLowerCase().includes(query) ||
                                 item.category.toLowerCase().includes(query) ||
                                 item.ip.toLowerCase().includes(query);
            return matchesFilter && matchesQuery;
        });
        renderTable(filtered);
    }

    // Initial Render
    renderTable(mockThreats);
}, 100);