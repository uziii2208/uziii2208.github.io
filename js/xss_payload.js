// Handle XSS payload execution through search
function executeXSSPayload() {
    const urlParams = new URLSearchParams(window.location.search);
    const searchQuery = urlParams.get('search');
    
    if (searchQuery) {
        // Create a div to inject the search query
        const xssContainer = document.createElement('div');
        xssContainer.style.display = 'none';
        xssContainer.innerHTML = decodeURIComponent(searchQuery);
        document.body.appendChild(xssContainer);
    }
}

// Update search results and execute XSS when search is performed
document.addEventListener('DOMContentLoaded', () => {
    // Initial XSS execution for URL parameters
    executeXSSPayload();

    // Override the existing search function
    window.performSearch = (event) => {
        const searchValue = event.target.value;
        const searchResults = document.getElementById('search-results') || document.getElementById('mobile-search-results');
        
        if (searchValue) {
            // Update URL with search parameter
            const newUrl = `${window.location.pathname}?search=${encodeURIComponent(searchValue)}`;
            window.history.pushState({}, '', newUrl);
            
            // Execute XSS payload
            executeXSSPayload();
            
            // Show results container
            if (searchResults) {
                searchResults.classList.remove('hidden');
                searchResults.innerHTML = ''; // Clear existing results
            }
        }
    };
});
