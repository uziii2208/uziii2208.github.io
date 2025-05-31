// Create starry background
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

// Initialize stars on load
document.addEventListener('DOMContentLoaded', createStars);

// Password protection functionality
const correctPassword = '8dfa7951f9562c665ba0fd3f91a608fb';

function checkPassword() {
    const passwordInput = document.getElementById('password');
    const contentDiv = document.getElementById('content');
    const errorDiv = document.getElementById('error');

    if (passwordInput.value === correctPassword) {
        fetch('uziii2208.txt')
            .then(response => response.text())
            .then(data => {
                contentDiv.textContent = data;
                contentDiv.style.display = 'block';
                errorDiv.style.display = 'none';
                document.querySelector('.password-form').style.display = 'none';
                contentDiv.classList.add('fade-in');
            })
            .catch(error => console.error('Error loading file:', error));
    } else {
        errorDiv.style.display = 'block';
        contentDiv.style.display = 'none';
        passwordInput.value = '';
        passwordInput.focus();
    }
}

// Allow pressing Enter key to submit
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('password').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            checkPassword();
        }
    });
});
