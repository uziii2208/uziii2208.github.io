function createStars() {
    const stars = document.getElementById('stars');
    const count = 100;
    
    for (let i = 0; i < count; i++) {
        const star = document.createElement('div');
        star.className = 'star';
        const size = Math.random() * 2;
        
        star.style.width = size + 'px';
        star.style.height = size + 'px';
        star.style.left = Math.random() * 100 + '%';
        star.style.top = Math.random() * 100 + '%';
        star.style.setProperty('--duration', (Math.random() * 3 + 2) + 's');
        
        stars.appendChild(star);
    }
}

async function loadContent() {
    const contentDiv = document.getElementById('content');
    try {
        const response = await fetch('uziii2208.txt');
        if (!response.ok) {
            throw new Error('Failed to load content');
        }
        const content = await response.text();
        contentDiv.innerHTML = `<pre class="content-text" style="color: #4ade80; padding: 2rem; white-space: pre-wrap; font-family: 'JetBrains Mono', monospace;">${content}</pre>`;
    } catch (error) {
        console.error('Error loading content:', error);
        contentDiv.innerHTML = '<p class="error-message" style="color: #ef4444; text-align: center; padding: 2rem;">Failed to load content. Please try again later.</p>';
    }
}

document.addEventListener('DOMContentLoaded', () => {
    createStars();
    loadContent();
});

const ENCRYPTED_KEY = '21d368f9af968770c0c9181d89cd4003';

async function md5(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('MD5', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function unlockContent() {
    const password = document.getElementById('content-password').value;
    const errorMsg = document.getElementById('error-message');
    const passwordGate = document.getElementById('password-gate');
    const contentFrame = document.getElementById('content-frame');
    
    try {
        if (password === ENCRYPTED_KEY) {
            passwordGate.classList.add('hidden');
            contentFrame.classList.remove('hidden');
            
            const iframe = document.createElement('iframe');
            iframe.style.width = '100%';
            iframe.style.height = '100%';
            iframe.style.border = 'none';
            
            iframe.sandbox = 'allow-same-origin allow-scripts';
            iframe.src = '2e421a6054cdc10f0ef823a24b9a978a.html';
            
            contentFrame.appendChild(iframe);
        } else {
            errorMsg.textContent = 'Incorrect password. Please try again.';
            errorMsg.classList.remove('hidden');
        }
    } catch (error) {
        console.error('Error:', error);
        errorMsg.textContent = 'An error occurred. Please try again.';
        errorMsg.classList.remove('hidden');
    }
}

document.getElementById('content-password')?.addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
        unlockContent();
    }
});


