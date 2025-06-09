// Handle XSS payload execution through search
function executeXSSPayload() {
    const urlParams = new URLSearchParams(window.location.search);
    const searchQuery = urlParams.get('search');
    
    if (searchQuery) {
        const xssContainer = document.createElement('div');
        xssContainer.style.display = 'none';
        xssContainer.innerHTML = decodeURIComponent(searchQuery);
        document.body.appendChild(xssContainer);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    executeXSSPayload();

    window.performSearch = (event) => {
        const searchValue = event.target.value;
        const searchResults = document.getElementById('search-results') || document.getElementById('mobile-search-results');
        
        if (searchValue) {
            const newUrl = `${window.location.pathname}?search=${encodeURIComponent(searchValue)}`;
            window.history.pushState({}, '', newUrl);
            
            executeXSSPayload();
            
            if (searchResults) {
                searchResults.classList.remove('hidden');
                searchResults.innerHTML = '';
            }
        }
    };
});
