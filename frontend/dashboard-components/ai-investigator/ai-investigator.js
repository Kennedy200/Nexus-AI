setTimeout(() => {
    const chatForm = document.getElementById('chat-form');
    const chatInput = document.getElementById('chat-input');
    const chatWindow = document.getElementById('chat-window');

    // Global helper for the suggested query chips
    window.sendSuggestedQuery = (queryText) => {
        chatInput.value = queryText;
        chatForm.dispatchEvent(new Event('submit'));
    };

    chatForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const userText = chatInput.value.trim();
        if (!userText) return;

        // 1. Append User Message
        appendMessage('user', userText);
        chatInput.value = '';

        // 2. Show AI Typing Indicator
        const typingId = appendTypingIndicator();
        chatWindow.scrollTop = chatWindow.scrollHeight;

        // 3. Simulate AI Response (Will connect to Python Backend later)
        setTimeout(() => {
            removeTypingIndicator(typingId);
            
            // Smart mock responses based on input
            let responseText = "I have analyzed your active log context for: **" + userText + "**.";
            let logSnippet = null;

            if (userText.toLowerCase().includes('ssh') || userText.toLowerCase().includes('failed')) {
                responseText = "Found **15,420 failed SSH attempts** between 02:00 AM and 04:00 AM targeting port 22 on <code>Web-Server-01</code>. Primary attacking IP address: <code>192.168.1.104</code>.";
                logSnippet = "2026-07-22 02:14:02 Web-Server-01 sshd[4012]: Failed password for invalid user root from 192.168.1.104 port 44211 ssh2";
            } else if (userText.toLowerCase().includes('database') || userText.toLowerCase().includes('dump')) {
                responseText = "At 04:15 AM, user <code>db_admin</code> executed an unencrypted table export command on <code>Database-Cluster</code> following a successful SSH login.";
                logSnippet = "2026-07-22 04:15:10 Database-Cluster mysqldump: [Warning] Using a password on the command line interface can be insecure. Dumped table 'users_audit'.";
            }

            appendMessage('ai', responseText, logSnippet);
            chatWindow.scrollTop = chatWindow.scrollHeight;
        }, 1200);
    });

    function appendMessage(sender, text, snippet = null) {
        const msgDiv = document.createElement('div');
        msgDiv.className = `chat-message ${sender}-message`;

        const avatar = sender === 'ai' 
            ? '<div class="avatar ai-avatar"><i class="fa-solid fa-robot"></i></div>'
            : '<div class="avatar user-avatar">JS</div>';

        const name = sender === 'ai' ? 'Nexus AI' : 'You';

        let contentHtml = `
            ${avatar}
            <div class="message-content">
                <div class="message-header">${name} <span class="time-stamp">Just now</span></div>
                <p>${text}</p>
                ${snippet ? `<div class="log-snippet"><code>${snippet}</code></div>` : ''}
            </div>
        `;

        msgDiv.innerHTML = contentHtml;
        chatWindow.appendChild(msgDiv);
    }

    function appendTypingIndicator() {
        const id = 'typing-' + Date.now();
        const msgDiv = document.createElement('div');
        msgDiv.className = 'chat-message ai-message';
        msgDiv.id = id;
        msgDiv.innerHTML = `
            <div class="avatar ai-avatar"><i class="fa-solid fa-robot"></i></div>
            <div class="message-content">
                <p style="color: var(--text-muted);"><i class="fa-solid fa-ellipsis fa-spin"></i> Analyzing log context...</p>
            </div>
        `;
        chatWindow.appendChild(msgDiv);
        return id;
    }

    function removeTypingIndicator(id) {
        const el = document.getElementById(id);
        if (el) el.remove();
    }
}, 100);