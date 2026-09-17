/* ─────────────────────────────────────────────────────────────
   zeropwn — Security Research Blog Application Logic (app.js)
   Author: @uziii2208 (Tong Hoang Gia)
───────────────────────────────────────────────────────────── */

/* ─── GLOBAL APPLICATION STATE ─── */
let posts = [];
let activeFilter = 'all';
let currentSearchQuery = '';
let sfxEnabled = localStorage.getItem('zeropwn_sfx') !== 'false';
let audioCtx = null;
let cmdSelectedIndex = 0;
let cmdFilteredList = [];

// Cyberpunk SVG Lock Icon (Vector - Zero raw emoji fallback)
const LOCK_ICON_SVG = '<svg class="ui-icon lock-icon-inline" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="vertical-align:-1px;margin-right:5px;"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>';

/* ─── 1. SYNTHESIZED MINECRAFT & CASUAL-GAME AUDIO ENGINE (ZERO EXTERNAL ASSETS) ─── */
function initAudio() {
  if (!audioCtx && (window.AudioContext || window.webkitAudioContext)) {
    try {
      const AudioContextClass = window.AudioContext || window.webkitAudioContext;
      audioCtx = new AudioContextClass();
    } catch (e) {
      console.warn('Web Audio API not supported', e);
    }
  }
}

function playCyberSound(type = 'click') {
  if (!sfxEnabled) return;
  try {
    initAudio();
    if (!audioCtx) return;
    if (audioCtx.state === 'suspended') {
      audioCtx.resume();
    }
    const now = audioCtx.currentTime;

    if (type === 'click') {
      // Authentic Minecraft UI Wooden Button Click
      // Layer 1: Crisp attack transient (950Hz -> 200Hz in 22ms)
      const osc1 = audioCtx.createOscillator();
      const gain1 = audioCtx.createGain();
      osc1.type = 'triangle';
      osc1.frequency.setValueAtTime(950, now);
      osc1.frequency.exponentialRampToValueAtTime(200, now + 0.022);
      gain1.gain.setValueAtTime(0.32, now);
      gain1.gain.exponentialRampToValueAtTime(0.001, now + 0.022);
      osc1.connect(gain1);
      gain1.connect(audioCtx.destination);
      osc1.start(now);
      osc1.stop(now + 0.022);

      // Layer 2: Hollow wooden resonance body (380Hz -> 310Hz over 55ms)
      const osc2 = audioCtx.createOscillator();
      const gain2 = audioCtx.createGain();
      osc2.type = 'sine';
      osc2.frequency.setValueAtTime(380, now);
      osc2.frequency.exponentialRampToValueAtTime(310, now + 0.055);
      gain2.gain.setValueAtTime(0.28, now);
      gain2.gain.exponentialRampToValueAtTime(0.001, now + 0.055);
      osc2.connect(gain2);
      gain2.connect(audioCtx.destination);
      osc2.start(now);
      osc2.stop(now + 0.055);

    } else if (type === 'pop' || type === 'pickup') {
      // Minecraft Item Pickup Bubble Pop (Rapid upward resonant chirp)
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(420, now);
      osc.frequency.exponentialRampToValueAtTime(1350, now + 0.07);
      gain.gain.setValueAtTime(0.35, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.075);
      osc.connect(gain);
      gain.connect(audioCtx.destination);
      osc.start(now);
      osc.stop(now + 0.075);

    } else if (type === 'copy' || type === 'success') {
      // Minecraft XP Orb / Casual Game Level-Up Chime (Dual Crystal Harmonic Bells)
      // Bell 1: C6 (1046.5Hz)
      const osc1 = audioCtx.createOscillator();
      const gain1 = audioCtx.createGain();
      osc1.type = 'sine';
      osc1.frequency.setValueAtTime(1046.5, now);
      gain1.gain.setValueAtTime(0.26, now);
      gain1.gain.exponentialRampToValueAtTime(0.001, now + 0.15);
      osc1.connect(gain1);
      gain1.connect(audioCtx.destination);
      osc1.start(now);
      osc1.stop(now + 0.15);

      // Bell 2: G6 (1567.98Hz)
      const osc2 = audioCtx.createOscillator();
      const gain2 = audioCtx.createGain();
      osc2.type = 'sine';
      osc2.frequency.setValueAtTime(1567.98, now + 0.04);
      gain2.gain.setValueAtTime(0.001, now);
      gain2.gain.setValueAtTime(0.30, now + 0.04);
      gain2.gain.exponentialRampToValueAtTime(0.001, now + 0.22);
      osc2.connect(gain2);
      gain2.connect(audioCtx.destination);
      osc2.start(now + 0.04);
      osc2.stop(now + 0.22);

    } else if (type === 'open') {
      // Minecraft Chest Open / Casual Window Reveal (Wood friction sweep)
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      osc.type = 'triangle';
      osc.frequency.setValueAtTime(220, now);
      osc.frequency.exponentialRampToValueAtTime(490, now + 0.085);
      gain.gain.setValueAtTime(0.28, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.09);
      osc.connect(gain);
      gain.connect(audioCtx.destination);
      osc.start(now);
      osc.stop(now + 0.09);

    } else if (type === 'close') {
      // Minecraft Chest Shut / Modal Dismiss (Snap Thud)
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      osc.type = 'triangle';
      osc.frequency.setValueAtTime(480, now);
      osc.frequency.exponentialRampToValueAtTime(150, now + 0.06);
      gain.gain.setValueAtTime(0.28, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.065);
      osc.connect(gain);
      gain.connect(audioCtx.destination);
      osc.start(now);
      osc.stop(now + 0.065);

    } else if (type === 'error') {
      // Minecraft Block Thud / Action Denied
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(180, now);
      osc.frequency.exponentialRampToValueAtTime(80, now + 0.09);
      gain.gain.setValueAtTime(0.26, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.09);
      osc.connect(gain);
      gain.connect(audioCtx.destination);
      osc.start(now);
      osc.stop(now + 0.09);
    }
  } catch (e) {
    // AudioContext blocked or not allowed
  }
}

function toggleSFX() {
  sfxEnabled = !sfxEnabled;
  localStorage.setItem('zeropwn_sfx', sfxEnabled ? 'true' : 'false');
  updateSFXButtonUI();
  if (sfxEnabled) playCyberSound('pop');
  showToast(`Sound Effects: ${sfxEnabled ? 'MINECRAFT / CASUAL ON' : 'MUTED'}`);
}

function updateSFXButtonUI() {
  const btn = document.getElementById('sfx-toggle');
  const statusEl = document.getElementById('sfx-status');
  if (!btn) return;
  if (sfxEnabled) {
    btn.classList.remove('muted');
    if (statusEl) statusEl.textContent = 'ON';
  } else {
    btn.classList.add('muted');
    if (statusEl) statusEl.textContent = 'OFF';
  }
}

/* ─── 2. HACKER TEXT SCRAMBLE / DECODER EFFECT ─── */
const SCRAMBLE_CHARS = '0123456789ABCDEF_#%*<>/\\!$+-';

function scrambleText(element, finalText, duration = 650) {
  if (!element) return;
  const start = performance.now();
  const original = finalText || element.textContent;
  element.style.display = 'inline-block';
  element.style.whiteSpace = 'nowrap';

  function update(now) {
    const elapsed = now - start;
    const progress = Math.min(1, elapsed / duration);
    const resolvedChars = Math.floor(progress * original.length);

    let output = '';
    for (let i = 0; i < original.length; i++) {
      if (original[i] === ' ') {
        output += ' ';
      } else if (i < resolvedChars) {
        output += original[i];
      } else {
        output += SCRAMBLE_CHARS[Math.floor(Math.random() * SCRAMBLE_CHARS.length)];
      }
    }

    element.textContent = output;

    if (progress < 1) {
      requestAnimationFrame(update);
    } else {
      element.textContent = original;
    }
  }

  requestAnimationFrame(update);
}

function initScrambleEffects() {
  // Scramble on hero title on load using its actual HTML text
  const heroRed = document.querySelector('#hero h1 .red');
  if (heroRed) {
    const targetText = (heroRed.getAttribute('data-text') || heroRed.textContent).trim();
    if (targetText) {
      setTimeout(() => {
        scrambleText(heroRed, targetText, 850);
      }, 200);
    }
  }

  // Scramble hover on logo and headers
  document.querySelectorAll('.scramble-hover').forEach(el => {
    el.addEventListener('mouseenter', () => {
      scrambleText(el, el.textContent, 350);
      playCyberSound('click');
    });
  });
}

/* ─── 3. DYNAMIC CYBER CONSTELLATION CANVAS ─── */
function initCyberCanvas() {
  const canvas = document.getElementById('cyber-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  const isFixed = document.body.classList.contains('page-post') || 
                  document.body.classList.contains('page-post-index') || 
                  canvas.parentElement === document.body;

  let width = (canvas.width = isFixed ? window.innerWidth : canvas.parentElement.offsetWidth);
  let height = (canvas.height = isFixed ? window.innerHeight : canvas.parentElement.offsetHeight);

  const particles = [];
  const particleCount = Math.min(55, Math.floor(width / (isFixed ? 28 : 24)));
  const maxDistance = 115;

  const mouse = { x: null, y: null, radius: 140 };

  window.addEventListener('resize', () => {
    if (isFixed) {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    } else if (canvas.parentElement) {
      width = canvas.width = canvas.parentElement.offsetWidth;
      height = canvas.height = canvas.parentElement.offsetHeight;
    }
  });

  const mouseTarget = isFixed ? window : canvas.parentElement;
  mouseTarget.addEventListener('mousemove', (e) => {
    if (isFixed) {
      mouse.x = e.clientX;
      mouse.y = e.clientY;
    } else {
      const rect = canvas.getBoundingClientRect();
      mouse.x = e.clientX - rect.left;
      mouse.y = e.clientY - rect.top;
    }
  });

  mouseTarget.addEventListener('mouseleave', () => {
    mouse.x = null;
    mouse.y = null;
  });

  // Particle Class
  for (let i = 0; i < particleCount; i++) {
    particles.push({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.65,
      vy: (Math.random() - 0.5) * 0.65,
      size: Math.random() * 1.8 + 1,
      baseAlpha: Math.random() * 0.45 + 0.25
    });
  }

  function animate() {
    ctx.clearRect(0, 0, width, height);

    for (let i = 0; i < particles.length; i++) {
      const p = particles[i];
      p.x += p.vx;
      p.y += p.vy;

      if (p.x < 0) p.x = width;
      if (p.x > width) p.x = 0;
      if (p.y < 0) p.y = height;
      if (p.y > height) p.y = 0;

      // Mouse attraction / interaction
      if (mouse.x !== null && mouse.y !== null) {
        const dx = mouse.x - p.x;
        const dy = mouse.y - p.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < mouse.radius) {
          const force = (1 - dist / mouse.radius) * 0.04;
          p.x += dx * force;
          p.y += dy * force;

          // Draw laser connection to mouse
          ctx.beginPath();
          ctx.strokeStyle = `rgba(232, 25, 44, ${0.45 * (1 - dist / mouse.radius)})`;
          ctx.lineWidth = 1;
          ctx.moveTo(p.x, p.y);
          ctx.lineTo(mouse.x, mouse.y);
          ctx.stroke();
        }
      }

      // Draw particle
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(232, 25, 44, ${p.baseAlpha})`;
      ctx.fill();

      // Connect near particles
      for (let j = i + 1; j < particles.length; j++) {
        const p2 = particles[j];
        const dx = p.x - p2.x;
        const dy = p.y - p2.y;
        const dist = Math.sqrt(dx * dx + dy * dy);

        if (dist < maxDistance) {
          ctx.beginPath();
          ctx.strokeStyle = `rgba(232, 25, 44, ${0.2 * (1 - dist / maxDistance)})`;
          ctx.lineWidth = 0.7;
          ctx.moveTo(p.x, p.y);
          ctx.lineTo(p2.x, p2.y);
          ctx.stroke();
        }
      }
    }

    requestAnimationFrame(animate);
  }

  animate();
}

/* ─── 4. READING PROGRESS LASER (ON POST PAGES) ─── */
function initReadingProgressBar() {
  const bar = document.getElementById('reading-progress');
  if (!bar) return;

  function updateBar() {
    const docHeight = document.documentElement.scrollHeight - window.innerHeight;
    if (docHeight <= 0) {
      bar.style.width = '0%';
      return;
    }
    const scrolled = (window.scrollY / docHeight) * 100;
    bar.style.width = Math.min(100, Math.max(0, scrolled)) + '%';
  }

  window.addEventListener('scroll', updateBar, { passive: true });
  updateBar();
}

/* ─── 5. CODE BLOCKS HIGHLIGHTING & CYBER COPY ─── */
function processCodeBlocks(container) {
  if (!container) return;
  const blocks = container.querySelectorAll('pre code');
  blocks.forEach(codeBlock => {
    if (window.hljs) {
      hljs.highlightElement(codeBlock);
    }

    const pre = codeBlock.parentElement;
    if (pre && !pre.querySelector('.code-header-bar')) {
      // Determine language
      let lang = 'CODE';
      codeBlock.classList.forEach(cls => {
        if (cls.startsWith('language-')) {
          lang = cls.replace('language-', '').toUpperCase();
        }
      });

      // Create Cyber Header Bar
      const bar = document.createElement('div');
      bar.className = 'code-header-bar';
      bar.innerHTML = `
        <div class="code-header-left">
          <span class="code-dot" style="background:#e8192c;"></span>
          <span class="code-dot" style="background:#ffaa44;"></span>
          <span class="code-dot" style="background:#38ef7d;"></span>
          <span class="code-lang-badge">${escapeHtml(lang)}</span>
        </div>
      `;

      // Copy Button
      const copyBtn = document.createElement('button');
      copyBtn.className = 'code-copy-btn';
      copyBtn.innerHTML = 'copy';
      copyBtn.onclick = () => {
        playCyberSound('copy');
        copyCode(codeBlock, copyBtn);
      };

      pre.appendChild(bar);
      pre.appendChild(copyBtn);
    }
  });
}

function copyCode(codeEl, btn) {
  const text = codeEl.innerText || codeEl.textContent;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => {
      showCopiedState(btn);
    }).catch(() => {
      fallbackCopyText(text, btn);
    });
  } else {
    fallbackCopyText(text, btn);
  }
}

function showCopiedState(btn) {
  btn.classList.add('copied');
  btn.innerHTML = '✓ copied // 0x00';
  showToast('Code snippet copied');
  setTimeout(() => {
    btn.classList.remove('copied');
    btn.innerHTML = 'copy';
  }, 2200);
}

function fallbackCopyText(text, btn) {
  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.style.position = 'fixed';
  textarea.style.opacity = '0';
  document.body.appendChild(textarea);
  textarea.select();
  try {
    document.execCommand('copy');
    if (btn && btn.classList) showCopiedState(btn);
    else showToast('Copied to clipboard');
  } catch (err) {
    if (btn) btn.textContent = 'failed';
  }
  document.body.removeChild(textarea);
}

/* ─── 6. IMAGE LIGHTBOX FOR EXPLOIT SCREENSHOTS ─── */
function initImageLightbox() {
  const overlay = document.getElementById('image-lightbox');
  const lbImg = document.getElementById('lightbox-img');
  const lbCaption = document.getElementById('lightbox-caption');
  if (!overlay || !lbImg) return;

  document.querySelectorAll('.md-content img').forEach(img => {
    img.style.cursor = 'zoom-in';
    img.addEventListener('click', () => {
      playCyberSound('open');
      lbImg.src = img.src;
      lbCaption.textContent = img.alt || 'Proof of Concept Screenshot';
      overlay.classList.add('active');
    });
  });
}

function closeLightbox() {
  const overlay = document.getElementById('image-lightbox');
  if (overlay) overlay.classList.remove('active');
  playCyberSound('click');
}

/* ─── 7. FLOATING COMMAND PALETTE HUD (Ctrl+K or /) ─── */
function openCmdPalette() {
  const palette = document.getElementById('cmd-palette');
  const input = document.getElementById('cmd-input');
  if (!palette || !input) return;

  playCyberSound('open');
  palette.classList.add('active');
  input.value = '';
  cmdSelectedIndex = 0;
  filterCmdPalette('');
  input.focus();
}

function closeCmdPalette() {
  const palette = document.getElementById('cmd-palette');
  if (palette) palette.classList.remove('active');
}

function filterCmdPalette(query) {
  const q = (query || '').toLowerCase().trim();
  const resultsContainer = document.getElementById('cmd-results');
  if (!resultsContainer) return;

  const dataset = Array.isArray(posts) && posts.length ? posts : (window.POSTS_DATA || []);
  
  if (!q) {
    cmdFilteredList = dataset;
  } else {
    cmdFilteredList = dataset.filter(p => {
      const inTitle = (p.title || '').toLowerCase().includes(q);
      const inExcerpt = (p.excerpt || '').toLowerCase().includes(q);
      const inTags = (p.tags || []).some(t => t.toLowerCase().includes(q));
      return inTitle || inExcerpt || inTags;
    });
  }

  if (cmdFilteredList.length === 0) {
    resultsContainer.innerHTML = '<div style="padding:18px;text-align:center;font-family:var(--font-meta);color:var(--text-muted);font-size:0.75rem;">no matching targets found</div>';
    return;
  }

  resultsContainer.innerHTML = cmdFilteredList.map((p, idx) => {
    // Resolve clean URL to post/<slug>/
    const isPostPage = document.body.classList.contains('page-post');
    const isPostIndex = document.body.classList.contains('page-post-index');
    const postSlug = p.slug || p.id;
    let href = '';

    if (window.location.protocol === 'file:') {
      if (isPostPage) {
        href = `../../post/${postSlug}/index.html`;
      } else if (isPostIndex) {
        href = `${postSlug}/index.html`;
      } else {
        href = `post/${postSlug}/index.html`;
      }
    } else {
      if (isPostPage) {
        href = `../../post/${postSlug}/`;
      } else if (isPostIndex) {
        href = `${postSlug}/`;
      } else {
        href = `post/${postSlug}/`;
      }
    }

    const isLocked = Boolean(p.locked);
    return `
      <a href="${href}" class="cmd-item ${idx === cmdSelectedIndex ? 'selected' : ''}" data-index="${idx}">
        <div class="cmd-item-title">${isLocked ? LOCK_ICON_SVG : ''}${escapeHtml(p.title)}</div>
        <div class="cmd-item-meta">
          <span>${p.date || ''}</span>
          ${isLocked ? `<span class="tag tag-locked" style="padding:1px 6px;font-size:0.65rem;border-radius:2px;display:inline-flex;align-items:center;">${LOCK_ICON_SVG}LOCKED</span>` : ''}
          <span>${(p.tags || []).map(t => `[${t}]`).join(' ')}</span>
        </div>
      </a>
    `;
  }).join('');
}

/* ─── 8. POST DETAIL PAGE ACTIONS (RAW TOGGLE & SHARE) ─── */
let isRawActive = false;
function toggleRawView() {
  const contentEl = document.getElementById('post-view-content');
  const rawViewEl = document.getElementById('raw-markdown-view');
  const labelEl = document.getElementById('raw-btn-label');
  const tocSidebar = document.getElementById('post-toc-sidebar');

  isRawActive = !isRawActive;
  playCyberSound('click');

  if (isRawActive) {
    if (contentEl) contentEl.style.display = 'none';
    if (rawViewEl) rawViewEl.style.display = 'block';
    if (labelEl) labelEl.textContent = 'RENDERED VIEW';
    if (tocSidebar) tocSidebar.style.display = 'none';
    showToast('Viewing raw Markdown source');
  } else {
    if (contentEl) contentEl.style.display = 'block';
    if (rawViewEl) rawViewEl.style.display = 'none';
    if (labelEl) labelEl.textContent = 'RAW .MD';
    if (tocSidebar) tocSidebar.style.display = 'block';
    showToast('Viewing rendered article');
  }
}

function copyCurrentMarkdown() {
  const rawViewEl = document.getElementById('raw-markdown-view');
  if (!rawViewEl) return;
  const content = rawViewEl.textContent;
  playCyberSound('copy');
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(content).then(() => {
      showToast('Complete Markdown copied to clipboard');
    });
  } else {
    fallbackCopyText(content, null);
  }
}

function sharePost() {
  playCyberSound('copy');
  const url = window.location.href;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(url).then(() => {
      showToast('Article URL copied to clipboard');
    });
  } else {
    fallbackCopyText(url, null);
  }
}

/* ─── 9. HOMEPAGE SEARCH & FILTERING ─── */
function initData() {
  // 1. Primary: load pre-compiled data
  if (Array.isArray(window.POSTS_DATA) && window.POSTS_DATA.length > 0) {
    posts = [...window.POSTS_DATA];
  }

  // 2. Fallback: fetch posts.json if posts array still empty
  if (posts.length === 0) {
    const isPostIndex = document.body.classList.contains('page-post-index');
    const jsonPath = isPostIndex ? '../posts.json' : 'posts.json';
    fetch(jsonPath)
      .then(res => res.json())
      .then(data => {
        if (Array.isArray(data) && data.length > 0) {
          posts = data;
          if (activeFilter !== 'all' || currentSearchQuery) {
            applyFiltersAndRender();
          }
          updateStats();
        }
      })
      .catch(() => {});
  }

  // 3. Fallback: extract from pre-rendered DOM elements
  if (posts.length === 0) {
    const existingCards = document.querySelectorAll('#post-list .post-item');
    if (existingCards.length > 0) {
      const isPostIndex = document.body.classList.contains('page-post-index');
      posts = Array.from(existingCards).map(card => {
        const titleEl = card.querySelector('.post-title');
        const excerptEl = card.querySelector('.post-excerpt');
        const dateEl = card.querySelector('.meta-date') || card.querySelector('.post-date');
        const readTimeEl = card.querySelector('.meta-readtime') || card.querySelector('.post-readtime');
        const href = card.getAttribute('href') || '';
        const tags = Array.from(card.querySelectorAll('.tag')).map(t => t.textContent.trim().toLowerCase());
        let slug = href;
        if (isPostIndex) {
          slug = href.replace(/\/index\.html$/, '').replace(/\/$/, '');
        } else {
          slug = href.replace(/^post\//, '').replace(/\/index\.html$/, '').replace(/\/$/, '');
        }
        return {
          id: slug,
          slug: slug,
          url: href,
          title: titleEl ? titleEl.textContent : '',
          excerpt: excerptEl ? excerptEl.textContent : '',
          date: dateEl ? dateEl.textContent : '',
          readTime: readTimeEl ? readTimeEl.textContent : '5 min read',
          tags: tags
        };
      });
    }
  }

  // Check URL parameters (e.g. ?tag=cve)
  const urlParams = new URLSearchParams(window.location.search);
  const tagParam = urlParams.get('tag');
  if (tagParam) {
    activeFilter = tagParam.toLowerCase();
    updateFilterButtons();
    applyFiltersAndRender();
  } else {
    // If no filter active and cards already in DOM, ensure list is rendered if DOM is empty
    const listEl = document.getElementById('post-list');
    if (listEl && listEl.children.length === 0 && posts.length > 0) {
      applyFiltersAndRender();
    }
  }

  updateStats();
}

function onSearchInput(query) {
  currentSearchQuery = query.trim().toLowerCase();
  const clearBtn = document.getElementById('search-clear-btn');
  if (clearBtn) clearBtn.style.display = query ? 'block' : 'none';
  applyFiltersAndRender();
}

function clearSearch() {
  const input = document.getElementById('search-input');
  if (input) {
    input.value = '';
    onSearchInput('');
    input.focus();
  }
}

function focusSearch() {
  const input = document.getElementById('search-input');
  if (input) {
    input.focus();
    input.scrollIntoView({ behavior: 'smooth', block: 'center' });
  } else {
    openCmdPalette();
  }
}

function filterPosts(tag) {
  playCyberSound('click');
  activeFilter = tag;
  updateFilterButtons();
  applyFiltersAndRender();
}

function filterByTag(tag) {
  playCyberSound('click');
  activeFilter = tag.toLowerCase();
  updateFilterButtons();
  applyFiltersAndRender();
  const postsSection = document.getElementById('posts');
  if (postsSection) {
    postsSection.scrollIntoView({ behavior: 'smooth' });
  }
}

function resetSearchAndFilter() {
  activeFilter = 'all';
  clearSearch();
  updateFilterButtons();
  applyFiltersAndRender();
}

function updateFilterButtons() {
  const buttons = document.querySelectorAll('#tag-filters .filter-btn');
  buttons.forEach(btn => {
    if (btn.dataset.tag === activeFilter) {
      btn.classList.add('active');
    } else {
      btn.classList.remove('active');
    }
  });
}

function applyFiltersAndRender() {
  let list = posts;

  // Filter by tag
  if (activeFilter !== 'all') {
    list = list.filter(p => (p.tags || []).some(t => t.toLowerCase() === activeFilter));
  }

  // Filter by search query
  if (currentSearchQuery) {
    list = list.filter(p => {
      const matchTitle = (p.title || '').toLowerCase().includes(currentSearchQuery);
      const matchExcerpt = (p.excerpt || '').toLowerCase().includes(currentSearchQuery);
      const matchTags = (p.tags || []).some(t => t.toLowerCase().includes(currentSearchQuery));
      const matchContent = (p.content || '').toLowerCase().includes(currentSearchQuery);
      return matchTitle || matchExcerpt || matchTags || matchContent;
    });
  }

  renderPostList(list);
  updateSearchFeedback(list.length);
}

function updateSearchFeedback(matchCount) {
  const statusEl = document.getElementById('search-status-text');
  const countIndicator = document.getElementById('posts-count-indicator');
  
  let label = '';
  if (currentSearchQuery) {
    label = `Found <strong>${matchCount}</strong> match${matchCount === 1 ? '' : 'es'} for "<em>${escapeHtml(currentSearchQuery)}</em>"`;
  } else if (activeFilter !== 'all') {
    label = `Showing <strong>${matchCount}</strong> write-up${matchCount === 1 ? '' : 's'} tagged [${activeFilter}]`;
  } else {
    label = `Displaying ${matchCount} write-ups`;
  }
  
  if (statusEl) statusEl.innerHTML = label;
  if (countIndicator) countIndicator.textContent = `${matchCount} write-up${matchCount === 1 ? '' : 's'}`;
}

function navigateToHome(event) {
  playCyberSound('click');
  const isHome = !document.body.classList.contains('page-post') && 
                 !document.body.classList.contains('page-post-index');
  if (isHome) {
    if (event) event.preventDefault();
    window.scrollTo({ top: 0, behavior: 'smooth' });
    if (window.location.hash) {
      history.replaceState(null, '', window.location.pathname);
    }
    return false;
  }
  if (window.location.protocol === 'file:') {
    if (event) event.preventDefault();
    const isPostPage = document.body.classList.contains('page-post');
    const isPostIndex = document.body.classList.contains('page-post-index');
    const rel = isPostPage ? '../../' : (isPostIndex ? '../' : '');
    window.location.href = `${rel}index.html`;
    return false;
  }
}

function navigateToTag(event, tag) {
  playCyberSound('click');
  if (window.location.protocol === 'file:') {
    if (event) event.preventDefault();
    const isPostPage = document.body.classList.contains('page-post');
    const isPostIndex = document.body.classList.contains('page-post-index');
    const rel = isPostPage ? '../../' : (isPostIndex ? '../' : '');
    window.location.href = `${rel}post/index.html?tag=${encodeURIComponent(tag)}`;
    return false;
  }
}

function navigateToPost(event, slug) {
  playCyberSound('open');
  if (window.location.protocol === 'file:') {
    event.preventDefault();
    const isPostIndex = document.body.classList.contains('page-post-index');
    const prefix = isPostIndex ? '' : 'post/';
    window.location.href = `${prefix}${slug}/index.html`;
    return false;
  }
}

function renderPostList(items) {
  const listEl = document.getElementById('post-list');
  const noPostsEl = document.getElementById('no-posts');
  if (!listEl) return;

  if (items.length === 0) {
    listEl.innerHTML = '';
    if (noPostsEl) noPostsEl.style.display = 'block';
    return;
  }

  if (noPostsEl) noPostsEl.style.display = 'none';

  const isPostIndex = document.body.classList.contains('page-post-index');
  const prefix = isPostIndex ? '' : 'post/';

  listEl.innerHTML = items.map(post => {
    const slug = post.slug || post.id;
    const isLocked = Boolean(post.locked);
    const actionCue = isLocked ? 'ENTER ACCESS KEY' : 'ACCESS WRITE-UP';
    const authBadge = isLocked ? 'CLASSIFIED // RESTRICTED' : 'RESEARCH // VERIFIED';
    const lockTag = isLocked ? `<span class="tag tag-locked" title="Password Protected">${LOCK_ICON_SVG}LOCKED</span>` : '';
    // Under file:// use <prefix><slug>/index.html; on HTTP use <prefix><slug>/
    const url = window.location.protocol === 'file:' ? `${prefix}${slug}/index.html` : `${prefix}${slug}/`;

    return `
      <a href="${url}" class="post-item cyber-card${isLocked ? ' is-locked-card' : ''}" onclick="return navigateToPost(event, '${slug}')">
        <div class="post-header-row">
          <div class="post-meta-inline">
            <span class="meta-date">${formatDate(post.date)}</span>
            <span class="meta-sep">/</span>
            <span class="meta-readtime">${post.readTime || '5 min read'}</span>
          </div>
          <div class="post-tags-inline">
            ${lockTag}
            ${(post.tags || []).map(t => `
              <span class="tag tag-${getTagClass(t)}" onclick="event.preventDefault(); event.stopPropagation(); filterByTag('${t}')" title="Filter by tag: ${escapeHtml(t)}">
                ${escapeHtml(t)}
              </span>
            `).join('')}
          </div>
        </div>
        <div class="post-title-block">
          <div class="post-title">${escapeHtml(post.title)}</div>
          <div class="post-excerpt">${escapeHtml(post.excerpt || '')}</div>
        </div>
        <div class="post-footer-row">
          <span class="post-action-cue">
            ${actionCue}
            <svg class="arrow-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>
          </span>
          <span class="post-auth-badge">${authBadge}</span>
        </div>
      </a>
    `;
  }).join('');
}

function getTagClass(tag) {
  const t = (tag || '').toLowerCase();
  if (t.includes('cve')) return 'cve';
  if (t.includes('ctf')) return 'ctf';
  if (t.includes('htb') || t.includes('hackthebox')) return 'htb';
  if (t.includes('research')) return 'research';
  if (t.includes('windows') || t.includes('win')) return 'windows';
  if (t.includes('linux')) return 'linux';
  if (t.includes('challenge')) return 'challenge';
  return 'generic';
}

function updateStats() {
  const dataset = Array.isArray(posts) && posts.length > 0 ? posts : (window.POSTS_DATA || []);
  const total = dataset.length;

  const postsCountEl = document.getElementById('stat-posts');
  const cveCountEl = document.getElementById('stat-cve');
  if (postsCountEl) postsCountEl.textContent = total || '5';
  if (cveCountEl) cveCountEl.textContent = '15+';

  // For post/index.html telemetry cards
  const statsTotalPosts = document.getElementById('stats-total-posts');
  const statsCveCount = document.getElementById('stats-cve-count');
  const statsLabCount = document.getElementById('stats-lab-count');
  const statusCountNum = document.querySelector('.archive-status-badge .count-num');

  if (statsTotalPosts || statsCveCount || statsLabCount || statusCountNum) {
    let cveTotal = 0;
    let labTotal = 0;

    dataset.forEach(p => {
      const tags = (p.tags || []).map(t => (t || '').toLowerCase());
      if (tags.includes('cve')) {
        cveTotal++;
      }
      if (tags.some(t => t === 'htb' || t === 'ctf' || t === 'hackthebox' || t === 'pentest' || t === 'lab')) {
        labTotal++;
      }
    });

    if (statsTotalPosts) statsTotalPosts.textContent = total;
    if (statsCveCount) statsCveCount.textContent = cveTotal;
    if (statsLabCount) statsLabCount.textContent = labTotal;
    if (statusCountNum) statusCountNum.textContent = total;
  }
}

/* ─── 10. SCROLLSPY FOR TABLE OF CONTENTS ─── */
function initScrollSpy() {
  const headings = document.querySelectorAll('.md-content h2, .md-content h3');
  if (headings.length === 0) return;

  function onScroll() {
    const scrollPos = window.scrollY + 130;
    let currentId = null;

    headings.forEach(h => {
      if (h.offsetTop <= scrollPos) {
        currentId = h.id;
      }
    });

    if (!currentId && headings[0]) {
      currentId = headings[0].id;
    }

    document.querySelectorAll('#toc-nav .toc-link').forEach(link => {
      if (link.dataset.slug === currentId) {
        link.classList.add('active');
      } else {
        link.classList.remove('active');
      }
    });
  }

  window.addEventListener('scroll', onScroll, { passive: true });
  onScroll();
}

/* ─── 11. FLOATING BACK TO TOP BUTTON ─── */
function initBackToTop() {
  const btn = document.getElementById('back-to-top');
  if (!btn) return;

  window.addEventListener('scroll', () => {
    if (window.scrollY > 380) {
      btn.classList.add('show');
    } else {
      btn.classList.remove('show');
    }
  }, { passive: true });
}

function scrollToTop() {
  playCyberSound('click');
  window.scrollTo({ top: 0, behavior: 'smooth' });
}
window.scrollToTop = scrollToTop;

/* ─── 12. KEYBOARD SHORTCUTS ─── */
document.addEventListener('keydown', (e) => {
  const activeElement = document.activeElement;
  const isEditing = activeElement && (
    activeElement.tagName === 'INPUT' ||
    activeElement.tagName === 'TEXTAREA'
  );

  // Command Palette Open: Ctrl+K or Cmd+K or / (when not typing in form)
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault();
    openCmdPalette();
    return;
  }

  if (e.key === '/' && !isEditing) {
    e.preventDefault();
    openCmdPalette();
    return;
  }

  // Escape key: close overlays or smoothly scroll to top of page
  if (e.key === 'Escape') {
    const palette = document.getElementById('cmd-palette');
    const isPaletteOpen = palette && palette.classList.contains('active');
    const lb = document.getElementById('image-lightbox');
    const isLbOpen = lb && lb.classList.contains('active');

    if (isPaletteOpen) {
      closeCmdPalette();
      return;
    }
    if (isLbOpen) {
      closeLightbox();
      return;
    }
    if (activeElement && activeElement.id === 'search-input') {
      clearSearch();
      activeElement.blur();
      return;
    }

    // Default global action when no modals are open: scroll smoothly to top
    scrollToTop();
    return;
  }

  // Inside Command Palette: Arrow navigation and Enter
  const palette = document.getElementById('cmd-palette');
  if (palette && palette.classList.contains('active')) {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (cmdFilteredList.length) {
        cmdSelectedIndex = (cmdSelectedIndex + 1) % cmdFilteredList.length;
        updateCmdSelection();
      }
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (cmdFilteredList.length) {
        cmdSelectedIndex = (cmdSelectedIndex - 1 + cmdFilteredList.length) % cmdFilteredList.length;
        updateCmdSelection();
      }
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const selectedItem = document.querySelector('.cmd-item.selected');
      if (selectedItem) {
        playCyberSound('open');
        window.location.href = selectedItem.getAttribute('href');
      }
    }
  }
});

function updateCmdSelection() {
  document.querySelectorAll('.cmd-item').forEach((item, idx) => {
    if (idx === cmdSelectedIndex) {
      item.classList.add('selected');
      item.scrollIntoView({ block: 'nearest' });
    } else {
      item.classList.remove('selected');
    }
  });
}

// Live filter in command palette input
document.addEventListener('DOMContentLoaded', () => {
  const cmdInput = document.getElementById('cmd-input');
  if (cmdInput) {
    cmdInput.addEventListener('input', (e) => {
      cmdSelectedIndex = 0;
      filterCmdPalette(e.target.value);
    });
  }
});

/* ─── 13. BANNER LOGIC ─── */
function initBanner() {
  const isDismissed = localStorage.getItem('zeropwn_migration_banner_dismissed') === 'true';
  const banner = document.getElementById('migration-banner');
  if (!isDismissed && banner) {
    banner.style.display = 'block';
    const height = banner.offsetHeight || 36;
    document.documentElement.style.setProperty('--banner-h', height + 'px');
  } else {
    if (banner) banner.style.display = 'none';
    document.documentElement.style.setProperty('--banner-h', '0px');
  }
}

function dismissBanner() {
  playCyberSound('click');
  localStorage.setItem('zeropwn_migration_banner_dismissed', 'true');
  const banner = document.getElementById('migration-banner');
  if (banner) banner.style.display = 'none';
  document.documentElement.style.setProperty('--banner-h', '0px');
}

/* ─── 14. UTILITIES & TOAST ─── */
function formatDate(d) {
  if (!d) return '';
  try {
    return new Date(d + 'T12:00:00').toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: '2-digit'
    });
  } catch (e) {
    return d;
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

let toastTimer = null;
function showToast(text) {
  const toast = document.getElementById('toast');
  const toastText = document.getElementById('toast-text');
  if (!toast || !toastText) return;
  toastText.textContent = text;
  toast.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    toast.classList.remove('show');
  }, 2200);
}

/* ─── INITIAL EXECUTION (ROBUST BOOT WITH READYSTATE CHECK) ─── */
function boot() {
  try { initBanner(); } catch (e) { console.warn('Banner init:', e); }
  try { updateSFXButtonUI(); } catch (e) { console.warn('SFX UI init:', e); }
  try { initScrambleEffects(); } catch (e) { console.warn('Scramble init:', e); }

  // Canvas background (Hero, post detail view, or post archive view)
  if (document.getElementById('cyber-canvas')) {
    try { initCyberCanvas(); } catch (e) { console.warn('Canvas init:', e); }
  }

  // If on homepage or post archive list
  if (document.getElementById('post-list')) {
    try { initData(); } catch (e) { console.error('Data init error:', e); }
  }

  // If on single post page
  if (document.body.classList.contains('page-post')) {
    try { initReadingProgressBar(); } catch (e) { console.warn('Progress bar:', e); }
    try { processCodeBlocks(document.getElementById('post-view-content')); } catch (e) { console.warn('Code blocks:', e); }
    try { initImageLightbox(); } catch (e) { console.warn('Lightbox:', e); }
    try { initScrollSpy(); } catch (e) { console.warn('ScrollSpy:', e); }
  }

  try { initBackToTop(); } catch (e) { console.warn('BackToTop:', e); }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot);
} else {
  boot();
}
