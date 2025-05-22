// Theme management
function toggleTheme() {
    const body = document.body;
    const isDarkMode = body.classList.toggle('light-mode');
    localStorage.setItem('theme', isDarkMode ? 'light' : 'dark');
}

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
            title: "Puppy: Medium - HackTheBox Season 8",
            excerpt: "Puppy, a medium-difficulty Windows machine, simulates a realistic Active Directory environment for testing web exploitation and privilege escalation skills.",
            url: "/content/hackthebox/puppy/puppy_htb_ss8.html",
            date: "2025-05-18"
        },
        {
            title: "WhiteRabbit: Insane - HackTheBox Season 7",
            excerpt: "WhiteRabbit: Insane HackTheBox Season 7 challenge tests advanced penetration skills with complex enumeration, exploitation, and privilege escalation techniques.",
            url: "/content/hackthebox/white/whiterabbit_htb_ss7.html",
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
            date: "2025-10-22"
        },
        {
            title: "Lockpick4.0: Insane - HackTheBox Sherlock",
            excerpt: "Lockpick4.0: Insane HackTheBox Sherlock, my ultimate favorite, challenges with ruthless ransomware reverse-engineering, uncovering IOCs, and thwarting Forela’s attackers.",
            url: "/content/hackthebox/lockpick40/lockpick40_htb_sherlock.html",
            date: "2024-10-21"
        }
    ],
    tryhackme: [
        {
            title: "Room: Basic Pentesting - Web Enum Basics",
            excerpt: "Essential web enumeration techniques for beginners in penetration testing.",
            url: "/content/tryhackme/post1.html",
            date: "2024-05-20"
        },
        {
            title: "Room: VulnNet - Active Directory Attacks",
            excerpt: "Comprehensive guide to attacking and exploiting Active Directory environments.",
            url: "/content/tryhackme/post2.html",
            date: "2024-05-20"
        },
        {
            title: "Room: Pickle Rick - Rickrolling Exploits",
            excerpt: "Fun walkthrough of the Rick and Morty themed room with Linux privilege escalation.",
            url: "/content/tryhackme/post3.html",
            date: "2024-05-20"
        },
        {
            title: "Room: Overpass - Password Cracking 101",
            excerpt: "Introduction to password cracking techniques and tools.",
            url: "/content/tryhackme/post4.html",
            date: "2024-05-20"
        },
        {
            title: "Room: Blue - MS17-010 Walkthrough",
            excerpt: "Detailed analysis of the EternalBlue exploit in a controlled environment.",
            url: "/content/tryhackme/post5.html",
            date: "2024-05-20"
        }
    ],
    blogs: [
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
            url: "/content/blogs/post2.html",
            date: "2023-05-20"
        },
        {
            title: "Setting Up Your Pentesting Lab",
            excerpt: "Step-by-step guide to creating a secure and effective penetration testing environment.",
            url: "/content/blogs/post3.html",
            date: "2023-07-11"
        },
        {
            title: "Common Web Vulnerabilities Explained",
            excerpt: "Deep dive into OWASP Top 10 and other critical web security vulnerabilities.",
            url: "/content/blogs/post4.html",
            date: "2023-05-20"
        },
        {
            title: "Privilege Escalation Techniques",
            excerpt: "Comprehensive guide to Linux and Windows privilege escalation methods.",
            url: "/content/blogs/post5.html",
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
            card.className = 'bg-gray-800 dark:bg-gray-800 p-6 rounded-lg shadow-md hover:shadow-lg transition-all duration-300 fade-in';
            card.innerHTML = `
                <h2 class="text-xl text-green-400 hover:text-green-500 transition-colors duration-300 mb-2">
                    <a href="${post.url}" class="hover:underline">${post.title}</a>
                </h2>
                <p class="text-gray-300 dark:text-gray-400 mb-4">${post.excerpt}</p>
                <p class="text-sm text-gray-500">${post.date}</p>
            `;
            sectionList.appendChild(card);
        });
    }
}

// Mobile menu toggle
function toggleMobileMenu() {
    const mobileMenu = document.getElementById('mobile-menu');
    mobileMenu.classList.toggle('hidden');
}

// Initialize content when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Populate sections if they exist on the current page
    ['hackthebox', 'tryhackme', 'blogs'].forEach(section => {
        if (sections[section]) {
            populateSection(section, sections[section]);
        }
    });
});
