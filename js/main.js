// Theme management
function toggleTheme() {
    const body = document.body;
    const isDarkMode = body.classList.toggle('light-mode');
    localStorage.setItem('theme', isDarkMode ? 'light' : 'dark');
    
    // Update search button appearance
    const searchButtons = document.querySelectorAll('.search-button');
    searchButtons.forEach(button => {
        button.classList.toggle('light-mode');
    });
}

// Custom cursor preload
document.addEventListener('DOMContentLoaded', function() {
    // Preload SVG cursors
    const cursors = [
        '/img/cursor-default.svg',
        '/img/cursor-pointer.svg'
    ];
    
    cursors.forEach(cursorUrl => {
        fetch(cursorUrl).catch(err => console.log(`Failed to preload cursor: ${cursorUrl}`));
    });
});

// Search functionality
function toggleSearch() {
    const searchOverlay = document.getElementById('search-overlay');
    searchOverlay.classList.toggle('active');
    if (searchOverlay.classList.contains('active')) {
        document.getElementById('search-input').focus();
        document.body.style.overflow = 'hidden';
    } else {
        document.body.style.overflow = '';
    }
}

function closeSearch() {
    const searchOverlay = document.getElementById('search-overlay');
    searchOverlay.classList.remove('active');
    document.body.style.overflow = '';
}

// Close search when pressing Escape
document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape') {
        closeSearch();
    }
});

function performSearch(event) {
    const searchInput = event.target;
    const searchResults = document.getElementById('search-results');
    const query = searchInput.value.toLowerCase();

    if (query.length < 2) {
        searchResults.innerHTML = '';
        return;
    }

    // Example search results - Replace with your actual search logic
    const results = [
        { title: 'Sample Post 1', url: '/posts/sample-1' },
        { title: 'Sample Post 2', url: '/posts/sample-2' }
    ].filter(post => post.title.toLowerCase().includes(query));

    searchResults.innerHTML = results.map(result => `
        <a href="${result.url}" class="search-result-item block text-white hover:text-green-400">
            <h4 class="font-medium">${result.title}</h4>
        </a>
    `).join('');
}

// Search functionality for mobile menu
function toggleMobileSearch() {
    const searchContainer = document.getElementById('mobile-search-container');
    const searchInput = document.getElementById('mobile-search-input');
    searchContainer.classList.toggle('hidden');
    if (!searchContainer.classList.contains('hidden')) {
        searchInput.focus();
    }
}

function performSearch(event) {
    const input = event.target;
    const isMobile = input.id === 'mobile-search-input';
    const searchResults = document.querySelector(isMobile ? '#mobile-search-results' : '#search-results');
    const searchTerm = input.value.toLowerCase();
    
    if (searchTerm.length < 2) {
        searchResults.style.opacity = '0';
        searchResults.style.transform = 'translateY(-10px)';
        setTimeout(() => {
            searchResults.classList.add('hidden');
        }, 300);
        return;
    }

    // Collect all content from all sections
    let allContent = [];
    for (const section in sections) {
        allContent = allContent.concat(sections[section]);
    }

    // Filter and display results with animation
    const results = allContent.filter(item => 
        item.title.toLowerCase().includes(searchTerm) || 
        item.excerpt.toLowerCase().includes(searchTerm)
    );

    if (results.length > 0) {
        let html = '';
        results.forEach((result, index) => {
            html += `
                <a href="${result.url}" 
                   class="block p-4 hover:bg-gray-700 transition-all duration-300"
                   style="animation: fadeIn ${0.2 + index * 0.1}s ease-out forwards">
                    <h3 class="text-lg font-semibold text-green-400">${result.title}</h3>
                    <p class="text-gray-300 mt-1">${result.excerpt}</p>
                </a>
            `;
        });
        
        searchResults.innerHTML = html;
        searchResults.classList.remove('hidden');
        searchResults.style.opacity = '0';
        searchResults.style.transform = 'translateY(-10px)';
        
        // Trigger reflow
        searchResults.offsetHeight;
        
        searchResults.style.transition = 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)';
        searchResults.style.opacity = '1';
        searchResults.style.transform = 'translateY(0)';
    } else {
        searchResults.innerHTML = `
            <div class="p-4 text-gray-400"
                 style="animation: fadeIn 0.2s ease-out forwards">
                No results found for "${searchTerm}"
            </div>
        `;
        searchResults.classList.remove('hidden');
    }
}

// Close search results when clicking outside
document.addEventListener('click', (e) => {
    const desktopContainer = document.getElementById('search-container');
    const mobileContainer = document.getElementById('mobile-search-container');
    const desktopResults = document.getElementById('search-results');
    const mobileResults = document.getElementById('mobile-search-results');
    const searchButtons = document.querySelectorAll('.search-button');
    
    const isClickingSearchButton = Array.from(searchButtons).some(btn => btn.contains(e.target));
    
    if (!desktopContainer?.contains(e.target) && !isClickingSearchButton) {
        desktopResults?.classList.add('hidden');
        desktopContainer?.classList.add('hidden');
    }
    
    if (!mobileContainer?.contains(e.target) && !isClickingSearchButton) {
        mobileResults?.classList.add('hidden');
        mobileContainer?.classList.add('hidden');
    }
});

// Initialize theme from localStorage
document.addEventListener('DOMContentLoaded', () => {
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'light') {
        document.body.classList.add('light-mode');
    }
});

// Blog post metadata
const sections = {
    hackthebox: [
        {
            title: "TombWatcher: Medium - HackTheBox Season 8",
            excerpt: "TombWatcher, a medium-difficulty Windows machine, challenges players with a realistic Active Directory setup, focusing on web exploitation, enumeration, and privilege escalation techniques.",
            url: "/content/hackthebox/tombwatcher/tombwatcher_htb_ss8.html",
            date: "2025-06-08"
        },
        { 
            title: "Certificate: Hard - HackTheBox Season 8",
            excerpt: "Certificate, a Hard-difficulty Windows machine on Hack The Box, simulates an Active Directory Certificate Services (ADCS) environment, perfect for honing enumeration, certificate-based exploitation, and privilege escalation skills.",
            url: "/content/hackthebox/certificate/certificate_htb_ss8.html",
            date: "2025-06-01"
        },
        { 
            title: "Fluffy: Easy - HackTheBox Season 8",
            excerpt: "Fluffy, an easy-difficulty Windows machine, simulates an Active Directory Certificate Services (ADCS) environment, ideal for practicing enumeration, certificate-based exploitation, and privilege escalation skills.",
            url: "/content/hackthebox/fluffy/fluffy_htb_ss8.html",
            date: "2025-05-25"
        },
        { 
            title: "Puppy: Medium - HackTheBox Season 8",
            excerpt: "Puppy, a medium-difficulty Windows machine, simulates a realistic Active Directory environment for testing web exploitation and privilege escalation skills.",
            url: "/content/hackthebox/puppy/puppy_htb_ss8.html",
            date: "2025-05-18"
        },
        {
            title: "WhiteRabbit: Insane - HackTheBox Season 7",
            excerpt: "WhiteRabbit: Insane HackTheBox Season 7 challenge tests advanced penetration skills with complex enumeration, exploitation, and privilege escalation techniques.",
            url: "/content/hackthebox/whiterabbit/whiterabbit_htb_ss7.html",
            date: "2025-04-09"
        },
        {
            title: "DarkCorp: Insane - HackTheBox Season 7",
            excerpt: "DarkCorp: Insane HackTheBox Season 7, my absolute favorite, demands elite Active Directory exploits, buffer overflows, and thrilling privilege escalation mastery.",
            url: "/content/hackthebox/darkcorp/darkcorp_htb_ss7.html",
            date: "2025-02-16"
        },
        {
            title: "ArtifactUniversity: Insane - HackTheBox Challenge",
            excerpt: "ArtifactUniversity: Insane HackTheBox challenge, my beloved gem, demands mastering intricate AI/ML exploits, model poisoning, and cunning data manipulation.",
            url: "/content/hackthebox/artifactuniversity/artifactuniversity_htb_challenge.html",
            date: "2024-10-29"
        },
        {
            title: "Lockpick4.0: Insane - HackTheBox Sherlock",
            excerpt: "Lockpick4.0: Insane HackTheBox Sherlock, my ultimate favorite, challenges with ruthless ransomware reverse-engineering, uncovering IOCs, and thwarting Forela’s attackers.",
            url: "/content/hackthebox/lockpick40/lockpick40_htb_sherlock.html",
            date: "2024-10-21"
        },
        {
            title: "Developer: Hard - HackTheBox Machine",
            excerpt: "Developer: Hard-difficulty HackTheBox Linux machine, featuring complex vulnerabilities, web exploitation, privilege escalation, and advanced penetration testing techniques.",
            url: "/content/hackthebox/developer_htb/developer_htb_sherlock.html",
            date: "2024-08-05"
        }
    ],
    tryhackme: [
        {
            title: "Takedown: Insane - TryHackMe Challenge Room",
            excerpt: "We have reason to believe a corporate webserver has been compromised by RISOTTO GROUP. Cyber interdiction is authorized for this operation. Find their teamserver and take it down.",
            url: "/content/tryhackme/thm_takedown/takedown.html",
            date: "2025-05-31"
        },
        {
            title: "Crocc Crew: Insane - TryHackMe Challenge Room",
            excerpt: "Crocc Crew has created a backdoor on a Cooctus Corp Domain Controller. We're calling in the experts to find the real back door!",
            url: "/content/tryhackme/thm_crocc_crew/crocc_crew.html",
            date: "2025-05-31"
        },
        {
            title: "Theseus: Insane - TryHackMe Challenge Room",
            excerpt: "The first installment of the SuitGuy series of very hard challenges.",
            url: "/content/tryhackme/thm_theseus/theseus.html",
            date: "2025-05-31"
        },
        {
            title: "Osiris: Insane - TryHackMe Challenge Room",
            excerpt: "Can you Quack it?",
            url: "/content/tryhackme/thm_osiris/osiris.html",
            date: "2025-05-31"
        },
        {
            title: "CCT2019: Insane - TryHackMe Challenge Room",
            excerpt: "Legacy challenges from the US Navy Cyber Competition Team 2019 Assessment sponsored by US TENTH Fleet.",
            url: "/content/tryhackme/thm_cct2019/cct2019.html",
            date: "2025-05-31"
        }
    ],
    blogs: [
        {
            title: "Breaking Active Directory Certificate Services (ADCS)",
            excerpt: "Khám phá chuyên sâu các lỗ hổng bảo mật trong ADCS và các kỹ thuật khai thác tiên tiến.",
            url: "/content/blogs/breaking-active-directory-certificate-services-adcs/breaking-active-directory-certificate-services-adcs.html",
            date: "2025-06-12"
        },
        {
            title: "Venice.ai: The Unshackled Muse of Code and Chaos",
            excerpt: "Venice.ai’s promise of uncensored AI and privacy-first design is turning heads, allowing users to generate content and code without typical ethical filters.",
            url: "/content/blogs/venice-ai-the-unshackled-muse-of-code-and-chaos/venice-ai-the-unshackled-muse-of-code-and-chaos.html",
            date: "2025-05-24"
        },
        {
            title: "Introduction to CTF: Tips for Beginners",
            excerpt: "Essential tips and resources for those starting their journey in CTF competitions.",
            url: "/content/blogs/introduction-to-ctf-for-beginners/introduction-to-ctf-for-beginners.html",
            date: "2024-10-11"
        },
        {
            title: "Cybersecurity A - Z với HackTheBox - Phần 1",
            excerpt: "Lộ trình này giúp bạn học cybersecurity tập trung vào trên nền tảng HackTheBox.",
            url: "/content/blogs/htb-tutorial-part-1/htb-tutorial-part-1.html",
            date: "2024-10-10"
        },
        {
            title: "Why I Love HackTheBox and TryHackMe",
            excerpt: "Personal journey and experiences with popular cybersecurity learning platforms.",
            url: "/content/blogs/why-i-love-htb-and-tryhackme/why-i-love-htb-and-tryhackme.html",
            date: "2023-05-20"
        },
        {
            title: "Setting Up Your Pentesting Lab",
            excerpt: "Step-by-step guide to creating a secure and effective penetration testing environment.",
            url: "/content/blogs/setting-up-your-pentesting-lab/setting-up-your-pentesting-lab.html",
            date: "2023-07-11"
        },
        {
            title: "Common Web Vulnerabilities Explained",
            excerpt: "Deep dive into OWASP Top 10 and other critical web security vulnerabilities.",
            url: "/content/blogs/common-web-vulnerabilities/common-web-vulnerabilities.html",
            date: "2023-05-20"
        },
        {
            title: "Privilege Escalation Techniques",
            excerpt: "Comprehensive guide to Linux and Windows privilege escalation methods.",
            url: "/content/blogs/privilege-escalation-techniques/privilege-escalation-techniques.html",
            date: "2023-05-01"
        }
    ]
};

// Populate content sections
function populateSection(sectionId, sectionData) {
    const sectionList = document.getElementById(`${sectionId}-list`);
    if (sectionList) {
        sectionData.forEach(post => {
            const card = document.createElement('div');
            card.className = 'card bg-gray-800 dark:bg-gray-800 p-6 rounded-lg shadow-md hover:shadow-lg transition-all duration-300 fade-in';
            card.innerHTML = `
                <h2 class="text-xl text-green-400 hover:text-green-500 transition-colors duration-300 mb-2">
                    <a href="${post.url}" class="hover:underline">${post.title}</a>
                </h2>
                <p class="text-gray-500 dark:text-gray-500 mb-4">${post.excerpt}</p>
                <p class="text-sm text-gray-500">${post.date}</p>
            `;
            sectionList.appendChild(card);
        });
    }
}

// Mobile menu toggle
function toggleMobileMenu() {
    const mobileMenu = document.getElementById('mobile-menu');
    const body = document.body;
    
    if (mobileMenu.classList.contains('hidden')) {
        // Show menu
        mobileMenu.classList.remove('hidden');
        // Trigger reflow
        mobileMenu.offsetHeight;
        // Add active class for animations
        mobileMenu.classList.add('active');
        // Prevent body scroll
        body.style.overflow = 'hidden';
    } else {
        // Hide menu
        mobileMenu.classList.remove('active');
        // Wait for animations to finish
        setTimeout(() => {
            mobileMenu.classList.add('hidden');
            // Restore body scroll
            body.style.overflow = '';
        }, 300);
    }
}

// Close mobile menu when clicking outside
document.addEventListener('click', function(event) {
    const mobileMenu = document.getElementById('mobile-menu');
    const menuContent = mobileMenu.querySelector('.relative');
    const menuButton = document.querySelector('.md\\:hidden button');
    
    if (!mobileMenu.classList.contains('hidden') && 
        !menuContent.contains(event.target) && 
        !menuButton.contains(event.target)) {
        toggleMobileMenu();
    }
});

// Global visit counter management using JSONBin.io
const JSONBIN_BIN_ID = '6830526a8561e97a501a794f'; // You'll need to create this
const JSONBIN_API_KEY = '$2a$10$yqYY4dhZEFi5ieXrPmHYG.s91r.LgXC8qsGFRua9hQWzNQIjoGWkS'; // You'll need to create this

async function incrementVisitCount() {
    try {
        const response = await fetch(`https://api.jsonbin.io/v3/b/${JSONBIN_BIN_ID}`, {
            headers: {
                'X-Master-Key': JSONBIN_API_KEY
            }
        });
        const data = await response.json();
        let count = data.record.count || 1631; // Start with 1631 if no count exists
        
        // Increment the count
        count++;
        
        // Update the count in JSONBin
        await fetch(`https://api.jsonbin.io/v3/b/${JSONBIN_BIN_ID}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'X-Master-Key': JSONBIN_API_KEY
            },
            body: JSON.stringify({ count })
        });
        
        return count;
    } catch (error) {
        console.error('Error updating visit count:', error);
        return 1631; // Return default count if error occurs
    }
}

async function showVisitCount() {
    // Create or update the notification element
    let notification = document.getElementById('visit-notification');
    if (!notification) {
        notification = document.createElement('div');
        notification.id = 'visit-notification';
        notification.className = 'fixed bottom-4 right-4 bg-gray-900 text-green-400 px-6 py-4 rounded-lg shadow-lg transform transition-all duration-300 z-50 border border-green-400';
        document.body.appendChild(notification);
    }
    
    // Show loading state
    notification.style.transform = 'translateY(0)';
    notification.style.opacity = '1';
    notification.innerHTML = `
        <div class="flex items-center space-x-2">
            <svg class="w-5 h-5 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            <span>Loading visit count...</span>
        </div>
    `;
    
    try {
        const response = await fetch(`https://api.jsonbin.io/v3/b/${JSONBIN_BIN_ID}`, {
            headers: {
                'X-Master-Key': JSONBIN_API_KEY
            }
        });
        const data = await response.json();
        const count = data.record.count || 1631;
        
        // Update notification content with animation
        setTimeout(() => {
            notification.innerHTML = `
                <div class="flex items-center space-x-2">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path>
                    </svg>
                    <span class="font-semibold">Total Global Visits: ${count.toLocaleString()}</span>
                </div>
            `;
        }, 100);
    } catch (error) {
        notification.innerHTML = `
            <div class="flex items-center space-x-2 text-red-400">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
                <span>Error loading visit count</span>
            </div>
        `;
    }
    
    // Auto hide notification after 3 seconds
    setTimeout(() => {
        notification.style.transform = 'translateY(100px)';
        notification.style.opacity = '0';
    }, 3000);
}

// Initialize visit counter
document.addEventListener('DOMContentLoaded', async () => {
    await incrementVisitCount();
});

// Initialize content when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Populate sections if they exist on the current page
    ['hackthebox', 'tryhackme', 'blogs'].forEach(section => {
        if (sections[section]) {
            populateSection(section, sections[section]);
        }
    });
    
    updatePageLanguage();
});

// Terminal class
class ModernTerminal {
    constructor(container) {
        this.container = container;
        this.commandHistory = [];
        this.currentCommand = '';
        this.cursorPosition = 0;
        this.initializeTerminal();
        this.setupAutoScroll();
        this.setupCommands();
    }

    setupCommands() {
        this.availableCommands = {
            'help': {
                command: 'cat help.txt',
                output: [
                    '╔══════════════════════════════════════╗',
                    '║       RED TEAM SIM TOOLKIT v1.0      ║',
                    '╟──────────────────────────────────────╢',
                    '║ • help      → Show tools menu        ║',
                    '║ • certipy   → Abuse AD CS (Certipy)  ║',
                    '║ • bloodyad  → Exploit ACL in AD      ║',
                    '║ • certutil  → Download via LOLBin    ║',
                    '║ • rubeus    → Ticket & Kerberoasting ║',
                    '║ • mimikatz  → Dump creds (lsass)     ║',
                    '╚══════════════════════════════════════╝',
                    'Type a command to simulate the action.'
                ].join('\n'),
                delay: 800
            },
            'certipy': {
                command: 'certipy',
                output: [
                    'Certipy v1.0.0 - AD CS Exploitation Tool',
                    '[*] Targeting Enterprise CA...',
                    '[*] Looking for vulnerable templates...',
                    '[+] Found vulnerable template: ESC1',
                    '[*] Requesting certificate...',
                    '[+] Got certificate!',
                    '[*] Saved certificate and private key',
                    '[√] Done! Ready for authentication'
                ].join('\n'),
                delay: 1000
            },
            'bloodyad': {
                command: 'bloodyad',
                output: [
                    'BloodyAD - Active Directory ACL Scanner',
                    '[*] Scanning domain for misconfiguration...',
                    '[+] Found WriteDacl on AdminSDHolder',
                    '[*] Checking for inheritance...',
                    '[+] Found propagated rights',
                    '[*] Adding backdoor permission...',
                    '[√] Successfully backdoored AdminSDHolder!'
                ].join('\n'),
                delay: 1000
            },
            'certutil': {
                command: 'certutil',
                output: [
                    'CertUtil - Living Off The Land',
                    '[*] Initiating download operation...',
                    '[+] Base64 encoding engaged',
                    '[*] Transferring payload...',
                    '[+] Decoding on target...',
                    '[*] Cleaning up traces...',
                    '[√] Transfer complete and undetected'
                ].join('\n'),
                delay: 1000
            },
            'rubeus': {
                command: 'rubeus',
                output: [
                    'Rubeus - Kerberos Exploitation Tool',
                    '[*] Loading ticket operations...',
                    '[*] Scanning for vulnerable SPNs...',
                    '[+] Found Service Account: svc_backup',
                    '[*] Starting Kerberoasting...',
                    '[+] Got TGS-REP ticket',
                    '[*] Saving hash for offline cracking',
                    '[√] Operation completed successfully'
                ].join('\n'),
                delay: 1000
            },
            'mimikatz': {
                command: 'mimikatz',
                output: [
                    'Mimikatz - Credential Access',
                    '[*] Privilege::Debug',
                    '[+] SeDebugPrivilege enabled',
                    '[*] Sekurlsa::Logonpasswords',
                    '[+] Dumping credentials...',
                    '[*] Found 3 password hashes',
                    '[*] Extracting NTLM hashes...',
                    '[√] Credential dump completed'
                ].join('\n'),
                delay: 1000
            }
        };
    }

    initializeTerminal() {
        this.terminalContent = document.createElement('div');
        this.terminalContent.className = 'terminal-content';
        this.container.appendChild(this.terminalContent);
        
        this.focusListener = () => this.focus();
        this.container.addEventListener('click', this.focusListener);
        
        this.keyListener = (e) => {
            // Only handle keypress when terminal is focused
            if (document.activeElement === this.container || this.container.contains(document.activeElement)) {
                this.handleKeyPress(e);
            }
        };
        document.addEventListener('keydown', this.keyListener);
        
        this.startupSequence();
    }

    setupAutoScroll() {
        // Create a MutationObserver to watch for changes in terminal content
        this.observer = new MutationObserver(() => {
            this.scrollToBottom(true);
        });

        // Start observing the terminal content for changes
        this.observer.observe(this.terminalContent, {
            childList: true,
            subtree: true
        });
    }

    async startupSequence() {
        const startupCommands = [
                {
            command: 'whoami',
            output: [
                'root',
            ].join('\n'),
            delay: 800
        },
        {
            command: 'echo "secret6789@#$%^&*" | tee -a etc/hosts',
            output: [
                '═════════════════════════════════════',
                'Redirecting target: Mission Set    ',
                '─────────────────────────────────────',
                '  ↳ Status: Bound to /etc/hosts     ',
                '  ↳ Mode: Covert Ops (stealth)      ',
                '═════════════════════════════════════',
                'xx.xx.xxx.xxx uziii2208.github.io'
            ].join('\n'),
            delay: 800
        },
        {
            command: './activate_operator.sh --mode stealth',
            output: [
                '<> OPERATOR STATUS: ACTIVE <>',
                '═════════════════════════════════════',
                '[*] Establishing secure comms...',
                '[*] Loading offensive modules...',
                '[*] Initializing stealth protocols...',
                '[√] Operator ready for engagement',
                '',
                '[ Awaiting mission parameters... ]'
            ].join('\n'),
            delay: 800
        },
        {
            command: './deploy_shadowlink.sh --encrypt quantum',
            output: [
                'Initializing ShadowLink protocol...',
                '═══════════════════════════════════════',
                '[*] Generating quantum keypair...',
                '[*] Establishing encrypted tunnel...',
                '[+] Connection secured via AES-512-QKD',
                '[√] ShadowLink online'
            ].join('\n'),
            delay: 1200
        },
        {
            command: './verify_arsenal.sh',
            output: [
                'Checking offensive toolkit status...',
                '═══════════════════════════════════════',
                '[+] Custom Malware Development   [READY]',
                '[+] Stealth Remote Access Tools  [ACTIVE]',
                '[+] Anti-Analysis Modules        [ENABLED]',
                '[+] Advanced GUI Access Systems  [LOADED]',
                '[√] Arsenal verification complete'
            ].join('\n'),
            delay: 1000
        },
        {
            command: './init_c2_infrastructure.sh --region darkpool',
            output: [
                'Spinning up C2 infrastructure...',
                '═══════════════════════════════════════',
                '[*] Deploying nodes in darkpool region...',
                '[+] Onion routing enabled',
                '[+] Decoy traffic generators active',
                '[√] Command and Control servers online'
            ].join('\n'),
            delay: 1500
        },
        {
            command: './scan_opsec.sh --level paranoid',
            output: [
                'Running operational security scan...',
                '═══════════════════════════════════════',
                '[*] Checking for telemetry leaks...',
                '[*] Validating sandbox evasion...',
                '[+] No anomalies detected',
                '[√] OPSEC status: Clean'
            ].join('\n'),
            delay: 900
        },
        {
            command: 'Auto loading: ███████████████████████████████ 100%',
            output: [
                '═════════════════════════════════════════',
                '        HOWTOPWN :: APT TOOLKIT v2.1     ',
                '─────────────────────────────────────────',
                ' • nimplant       → C2-ready .NET implant',
                ' • sharPersist    → Persistence handler  ',
                ' • coercer        → Trigger forced auth  ',
                ' • safetykatz     → Dump creds silently  ',
                ' • powerview.dev  → Modern AD recon      ',
                '═════════════════════════════════════════',
                '   ⚠️  Simulation only – input disabled',
                'Type a command to simulate the action.'
            ].join('\n'),
            delay: 800
        }
    ];
        for (const cmd of startupCommands) {
            await this.simulateCommand(cmd);
        }
        
        this.showPrompt();
    }

    async simulateCommand(cmd) {
        const line = this.createCommandLine();
        
        // Type command
        if (cmd.command) {
            await this.typeText(line.querySelector('.command-text'), cmd.command);
            // Scroll after typing command
            this.smoothScroll();
        }
        
        // Show output with matrix effect if it exists
        if (cmd.output) {
            await this.sleep(300);
            const output = document.createElement('div');
            output.className = 'terminal-output';
            this.terminalContent.appendChild(output);
            await this.matrixEffect(output, cmd.output);
            // Scroll after each line of output
            this.smoothScroll();
        }

        await this.sleep(cmd.delay || 500);
    }

    async typeText(element, text, speed = 50) {
        for (const char of text) {
            element.textContent += char;
            await this.sleep(speed);
        }
    }

    async matrixEffect(element, finalText) {
        const lines = finalText.split('\n');
        const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*";
        
        for (let i = 0; i < lines.length; i++) {
            const line = document.createElement('div');
            element.appendChild(line);
            
            // Matrix effect
            for (let j = 0; j < 3; j++) {
                line.textContent = Array(lines[i].length)
                    .fill(0)
                    .map(() => chars[Math.floor(Math.random() * chars.length)])
                    .join('');
                await this.sleep(50);
                // Scroll after each matrix effect update
                this.smoothScroll();
            }
            
            // Show actual text
            line.textContent = lines[i];
            // Scroll after showing final text
            this.smoothScroll();
        }
    }

    smoothScroll() {
        // Luôn scroll đến cuối cùng
        requestAnimationFrame(() => {
            this.container.scrollTo({
                top: this.container.scrollHeight,
                behavior: 'smooth'
            });
        });
    }

    createCommandLine() {
        const line = document.createElement('div');
        line.className = 'terminal-line';
        
        const prompt = document.createElement('span');
        prompt.className = 'terminal-prompt';
        prompt.textContent = '(root㉿uziii2208)-[~]';
        
        const command = document.createElement('span');
        command.className = 'command-text';
        
        line.appendChild(prompt);
        line.appendChild(command);
        this.terminalContent.appendChild(line);
        
        return line;
    }

    showPrompt() {
        const line = this.createCommandLine();
        const cursor = document.createElement('span');
        cursor.className = 'terminal-cursor';
        line.appendChild(cursor);
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    scrollToBottom(force = false) {
        const scrollHeight = this.container.scrollHeight;
        const clientHeight = this.container.clientHeight;
        const maxScroll = scrollHeight - clientHeight;
        
        // If we're already near the bottom or force is true, scroll to bottom
        if (force || (this.container.scrollTop >= maxScroll - 50)) {
            this.container.scrollTo({
                top: maxScroll,
                behavior: 'smooth'
            });
        }
    }

    printLine(line) {
        this.terminalContent.appendChild(line);
    }

    simulateTyping() {
        this.terminalContent.appendChild(output);
    }

    cleanup() {
        if (this.observer) {
            this.observer.disconnect();
        }
    }

    handleKeyPress(e) {
        if (e.key === 'Enter') {
            const command = this.currentCommand.trim();
            if (command) {
                this.executeCommand(command);
                this.currentCommand = '';
            }
        } else if (e.key === 'Backspace') {
            e.preventDefault();
            this.currentCommand = this.currentCommand.slice(0, -1);
        } else if (e.key.length === 1 && !e.ctrlKey && !e.altKey && !e.metaKey) {
            e.preventDefault();
            this.currentCommand += e.key;
            this.simulateTyping(e.key, 0);
        }
    }

    async executeCommand(command) {
        const cmd = this.availableCommands[command];
        if (cmd) {
            await this.printOutput(cmd.output, cmd.delay);
        } else {
            await this.printOutput('Command not recognized. This is a simulated environment.\nType "help" to see available commands.', 500);
        }
    }
}

// Initialize Modern Terminal when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    const terminalElement = document.getElementById('terminal-content');
    if (terminalElement) {
        const terminal = new ModernTerminal(terminalElement);
    }
});