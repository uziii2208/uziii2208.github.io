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
  const mobileStatusEl = document.getElementById('mobile-sfx-status');
  if (btn) {
    if (sfxEnabled) {
      btn.classList.remove('muted');
      if (statusEl) statusEl.textContent = 'ON';
    } else {
      btn.classList.add('muted');
      if (statusEl) statusEl.textContent = 'OFF';
    }
  }
  if (mobileStatusEl) {
    mobileStatusEl.textContent = sfxEnabled ? 'ON' : 'OFF';
    mobileStatusEl.style.color = sfxEnabled ? 'var(--red)' : 'var(--text-muted)';
  }
}

/* ─── MOBILE NAVIGATION DRAWER ─── */
function toggleMobileMenu() {
  if (document.body.classList.contains('mobile-menu-open')) {
    closeMobileMenu();
  } else {
    openMobileMenu();
  }
}

function openMobileMenu() {
  document.body.classList.add('mobile-menu-open');
  const btn = document.getElementById('nav-hamburger-btn');
  const drawer = document.getElementById('mobile-menu-drawer');
  if (btn) {
    btn.classList.add('is-active');
    btn.setAttribute('aria-expanded', 'true');
  }
  if (drawer) {
    drawer.setAttribute('aria-hidden', 'false');
  }
  playCyberSound('open');
}

function closeMobileMenu() {
  document.body.classList.remove('mobile-menu-open');
  const btn = document.getElementById('nav-hamburger-btn');
  const drawer = document.getElementById('mobile-menu-drawer');
  if (btn) {
    btn.classList.remove('is-active');
    btn.setAttribute('aria-expanded', 'false');
  }
  if (drawer) {
    drawer.setAttribute('aria-hidden', 'true');
  }
  playCyberSound('close');
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

  // Full viewport dimensions on all pages
  let width = (canvas.width = window.innerWidth);
  let height = (canvas.height = window.innerHeight);

  const particles = [];
  const particleCount = Math.min(45, Math.max(20, Math.floor(width / 32)));
  const maxDistance = 110;

  const mouse = { x: null, y: null, radius: 145 };

  window.addEventListener('resize', () => {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
  });

  window.addEventListener('mousemove', (e) => {
    mouse.x = e.clientX;
    mouse.y = e.clientY;
  });

  window.addEventListener('mouseleave', () => {
    mouse.x = null;
    mouse.y = null;
  });

  // Background Constellation Particles
  for (let i = 0; i < particleCount; i++) {
    particles.push({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.55,
      vy: (Math.random() - 0.5) * 0.55,
      size: Math.random() * 1.6 + 1,
      baseAlpha: Math.random() * 0.4 + 0.2
    });
  }

  // ─── RETRO 8-BIT ARCADE SPRITE DEFINITIONS ───
  const RETRO_SPRITES = [
    // 0: Classic Space Invader Bug (9x7)
    {
      w: 9, h: 7,
      frames: [
        [
          '..X...X..',
          '...X.X...',
          '..XXXXX..',
          '.XXOXOXX.',
          '.XXXXXXX.',
          '..X.X.X..',
          '.X.....X.'
        ],
        [
          '..X...X..',
          '...X.X...',
          '..XXXXX..',
          '.XXOXOXX.',
          '.XXXXXXX.',
          '...X.X...',
          '..X...X..'
        ]
      ],
      color: '#ff2a4b', eyeColor: '#00ffee'
    },
    // 1: Galaga Arcade Beetle (9x7)
    {
      w: 9, h: 7,
      frames: [
        [
          'X.......X',
          '.X.XXX.X.',
          '.XXOXOXX.',
          'XXXXXXXXX',
          'X.XXXXX.X',
          'X.X.X.X.X',
          '..X...X..'
        ],
        [
          'X.......X',
          '.X.XXX.X.',
          '.XXOXOXX.',
          'XXXXXXXXX',
          '.XXXXXXX.',
          '.X.XXX.X.',
          'X.......X'
        ]
      ],
      color: '#e8192c', eyeColor: '#38ef7d'
    },
    // 2: Mini Cyber Drone (5x5)
    {
      w: 5, h: 5,
      frames: [
        [
          'X...X',
          '.X.X.',
          'XOXOX',
          'XXXXX',
          '.X.X.'
        ],
        [
          'X...X',
          '.X.X.',
          'XOXOX',
          'XXXXX',
          'X...X'
        ]
      ],
      color: '#ff5566', eyeColor: '#ffffff'
    },
    // 3: 8-bit Micro Fly (7x6)
    {
      w: 7, h: 6,
      frames: [
        [
          '..X.X..',
          '.XXXXX.',
          'XXOXOXX',
          'XXXXXXX',
          '.X.X.X.',
          'X.....X'
        ],
        [
          'X.....X',
          '.XXXXX.',
          'XXOXOXX',
          'XXXXXXX',
          '..X.X..',
          '.X...X.'
        ]
      ],
      color: '#ff3366', eyeColor: '#00f0ff'
    }
  ];

  // ─── RETRO 8-BIT ARCADE BUGS (CUTE FLOATING OPERATIVES) ───
  const bugs = [];
  const bugCount = Math.min(18, Math.max(8, Math.floor(width / 120)));

  class RetroArcadeBug {
    constructor() {
      this.reset(true);
    }

    reset(initial = false) {
      this.x = Math.random() * width;
      this.y = initial ? Math.random() * height : (Math.random() < 0.5 ? -25 : height + 25);
      this.spriteIdx = Math.floor(Math.random() * RETRO_SPRITES.length);
      this.sprite = RETRO_SPRITES[this.spriteIdx];

      // Smooth floating velocities (gentle drift)
      const angle = Math.random() * Math.PI * 2;
      const speed = 0.35 + Math.random() * 0.4;
      this.vx = Math.cos(angle) * speed;
      this.vy = Math.sin(angle) * speed;
      this.targetVx = this.vx;
      this.targetVy = this.vy;

      // Sinusoidal bobbing wave
      this.bobPhase = Math.random() * Math.PI * 2;
      this.bobSpeed = 0.02 + Math.random() * 0.025;
      this.bobAmp = 0.35 + Math.random() * 0.45;

      // 2-frame retro flapping animation (swaps every ~20-28 ticks)
      this.animTick = Math.floor(Math.random() * 60);
      this.animSpeed = 20 + Math.floor(Math.random() * 10);

      // Pixel block size: crisp 8-bit scale
      this.pixelSize = this.sprite.w === 5 ? 2.4 : (this.sprite.w === 7 ? 2.0 : 1.8);
      this.alpha = 0.7 + Math.random() * 0.25;

      // Direction wander timer
      this.changeTimer = Math.floor(140 + Math.random() * 220);

      // Cute star sparkles on hover
      this.sparkles = [];
    }

    update() {
      this.animTick++;
      this.bobPhase += this.bobSpeed;

      // Gentle mouse evasion: glides smoothly away when cursor approaches
      if (mouse.x !== null && mouse.y !== null) {
        const dx = this.x - mouse.x;
        const dy = this.y - mouse.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 130 && dist > 0) {
          const push = (1 - dist / 130) * 1.3;
          this.targetVx += (dx / dist) * push;
          this.targetVy += (dy / dist) * push;

          // Emit tiny retro pixel sparkle
          if (Math.random() < 0.25) {
            this.sparkles.push({
              x: this.x + (Math.random() - 0.5) * 12,
              y: this.y + (Math.random() - 0.5) * 12,
              size: Math.random() < 0.5 ? 2 : 1.5,
              life: 22,
              maxLife: 22,
              color: this.sprite.eyeColor
            });
          }
        }
      }

      // Smooth velocity interpolation towards target
      this.vx += (this.targetVx - this.vx) * 0.045;
      this.vy += (this.targetVy - this.vy) * 0.045;

      // Gentle speed clamp
      const spd = Math.sqrt(this.vx * this.vx + this.vy * this.vy);
      if (spd > 1.6) {
        this.vx = (this.vx / spd) * 1.6;
        this.vy = (this.vy / spd) * 1.6;
      }

      // Periodic gentle course change
      this.changeTimer--;
      if (this.changeTimer <= 0) {
        const angle = Math.random() * Math.PI * 2;
        const baseSpeed = 0.35 + Math.random() * 0.4;
        this.targetVx = Math.cos(angle) * baseSpeed;
        this.targetVy = Math.sin(angle) * baseSpeed;
        this.changeTimer = Math.floor(160 + Math.random() * 240);
      }

      // Apply coordinates with subtle sinusoidal wave
      this.x += this.vx;
      this.y += this.vy + Math.sin(this.bobPhase) * this.bobAmp;

      // Canvas boundary wrap
      const margin = 28;
      if (this.x < -margin) this.x = width + margin;
      if (this.x > width + margin) this.x = -margin;
      if (this.y < -margin) this.y = height + margin;
      if (this.y > height + margin) this.y = -margin;

      // Update sparkles
      for (let i = this.sparkles.length - 1; i >= 0; i--) {
        const sp = this.sparkles[i];
        sp.life--;
        if (sp.life <= 0) {
          this.sparkles.splice(i, 1);
        }
      }
    }

    draw(cCtx) {
      // Draw retro sparkles
      for (let i = 0; i < this.sparkles.length; i++) {
        const sp = this.sparkles[i];
        const sAlpha = sp.life / sp.maxLife;
        cCtx.save();
        cCtx.fillStyle = sp.color;
        cCtx.globalAlpha = sAlpha * 0.85;
        cCtx.fillRect(Math.round(sp.x), Math.round(sp.y), sp.size, sp.size);
        cCtx.restore();
      }

      // Draw 8-bit retro arcade sprite
      const frameIdx = Math.floor(this.animTick / this.animSpeed) % 2;
      const matrix = this.sprite.frames[frameIdx];
      const ps = this.pixelSize;
      const w = this.sprite.w;
      const h = this.sprite.h;
      const startX = Math.round(this.x - (w * ps) / 2);
      const startY = Math.round(this.y - (h * ps) / 2);

      cCtx.save();
      cCtx.globalAlpha = this.alpha;

      for (let r = 0; r < h; r++) {
        const row = matrix[r];
        for (let c = 0; c < w; c++) {
          const ch = row[c];
          if (ch === 'X') {
            cCtx.fillStyle = this.sprite.color;
            cCtx.fillRect(startX + c * ps, startY + r * ps, ps, ps);
          } else if (ch === 'O') {
            cCtx.fillStyle = this.sprite.eyeColor;
            cCtx.fillRect(startX + c * ps, startY + r * ps, ps, ps);
          }
        }
      }

      cCtx.restore();
    }
  }

  for (let i = 0; i < bugCount; i++) {
    bugs.push(new RetroArcadeBug());
  }

  function animate() {
    ctx.clearRect(0, 0, width, height);

    // Update and draw cyber pixel bugs
    for (let i = 0; i < bugs.length; i++) {
      bugs[i].update();
      bugs[i].draw(ctx);
    }

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

/* ─── 5b. LATEX & KATEX MATH FORMULA RENDERING ENGINE ─── */
function renderLaTeX(root = document) {
  if (typeof katex === 'undefined') {
    return;
  }

  const targetRoot = root || document;

  // 1. Render all structured math elements (.math.inline and .math.block)
  const mathEls = targetRoot.querySelectorAll ? targetRoot.querySelectorAll('.math.inline, .math.block') : [];
  mathEls.forEach(el => {
    if (el.dataset.katexRendered === 'true') return;

    // Strict guard: Never render inside code blocks
    if (el.closest('pre') || el.closest('code') || el.closest('.code-block')) return;

    const isBlock = el.classList.contains('block');
    const rawTex = el.textContent.trim();
    if (!rawTex) return;

    try {
      katex.render(rawTex, el, {
        displayMode: isBlock,
        throwOnError: false,
        strict: false
      });
      el.dataset.katexRendered = 'true';
    } catch (err) {
      console.warn('KaTeX render error:', err);
    }
  });

  // 2. Fallback auto-render for raw TeX delimiters outside code blocks
  if (typeof renderMathInElement === 'function') {
    try {
      renderMathInElement(targetRoot, {
        delimiters: [
          { left: '$$', right: '$$', display: true },
          { left: '$', right: '$', display: false },
          { left: '\\(', right: '\\)', display: false },
          { left: '\\[', right: '\\]', display: true }
        ],
        throwOnError: false,
        ignoredTags: ['script', 'noscript', 'style', 'textarea', 'pre', 'code', 'kbd'],
        ignoredClasses: ['code-block', 'code-line', 'hljs', 'bash', 'powershell', 'python']
      });
    } catch (e) {
      console.warn('KaTeX auto-render error:', e);
    }
  }
}
window.renderLaTeX = renderLaTeX;

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
    if (document.body.classList.contains('mobile-menu-open')) {
      closeMobileMenu();
      return;
    }
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

/* ─── 15. CYBER OPERATIVE COMPANION (KIRA // 0x0D) ─── */
const COMPANION_GREETINGS = [
  "Welcome back. Có gì hay để đọc hôm nay không?",
  "Blog mới lên rồi đó - ghé tab writeups xem thử.",
  "Hôm nay đang làm gì? Reversing, web, hay AD stuff?",
  "Bắt đầu từ đâu? Search bar ở trên, tags ở sidebar.",
  "uziii2208 Security Blogs - mọi thứ đều có nguồn, không có bullshit.",
  "Chào. Cứ tự nhiên như ở nhà - blog này không log IP."
];

const COMPANION_QUOTES = [
  { text: "There is no patch for human stupidity.", author: "Kevin Mitnick" },
  { text: "Security is not a product, but a process.", author: "Bruce Schneier" },
  { text: "Given enough eyeballs, all bugs are shallow.", author: "Linus's Law" },
  { text: "In theory, there is no difference between theory and practice. In practice, there is.", author: "Benjamin Brewster" },
  { text: "Complexity is the worst enemy of security.", author: "Bruce Schneier" },
  { text: "88 bytes to overwrite RIP and the shell drops. Assembly doesn't lie.", author: "0x0D Research" },
  { text: "Ring-0 bug không chỉ là crash - đó là ticket lên SYSTEM nếu biết cách dùng.", author: "Kira" },
  { text: "Trust the primitive, not the password. AES-GCM + PBKDF2 với iteration đủ cao thì brute force chỉ là lãng phí điện.", author: "0x0D" },
  { text: "Client-side validation là decoration. Server-side mới là gate.", author: "0x0D" },
  { text: "ROP chain là nghệ thuật ghép gadget - mỗi địa chỉ đều có lý do để ở đó.", author: "0x0D Research" },
  { text: "Trước khi nghĩ kernel exploit, check sudo -l và SUID trước. Low-hanging fruit vẫn là fruit.", author: "Kira" },
  { text: "Unconstrained delegation trong AD là dấu hiệu admin chưa đọc BloodHound output.", author: "0x0D" },
  { text: "Hack to understand, understand to defend.", author: "@uziii2208" },
  { text: "Hôm nay là 0-day, ngày mai là CVE, năm sau là conference talk.", author: "0x0D" },
  { text: "Offensive và defensive không phải đối lập - chúng là hai mặt của cùng một tư duy.", author: "Kira" }
];

const COMPANION_REACTIONS = [
  "Ơ, click tôi làm gì vậy?",
  "Đang rảnh à? Có writeup mới trong blog đó.",
  "Cần tìm gì thì dùng search bar tiện hơn - tôi không có full-text index đâu.",
  "Bạn vừa click vào một AI character trong một security blog. Cuộc đời thú vị nhỉ.",
  "Ok ok, tôi thấy bạn rồi. Cần gợi ý bài đọc không?",
  "Next click tôi sẽ random một quote. Hoặc không. Tôi chưa quyết."
];

let companionDialogueTimer = null;
let companionTypewriterTimer = null;
let companionIdleInterval = null;

function getContextualGreeting() {
  const hour = new Date().getHours();
  if (hour >= 5 && hour < 12) {
    return "Buổi sáng. Cà phê xong chưa? Blog có bài mới.";
  } else if (hour >= 12 && hour < 18) {
    return "Chiều rồi. Đang stuck chỗ nào không, hay chỉ đang đọc?";
  } else if (hour >= 18 && hour < 23) {
    return "Tối là giờ làm việc tốt nhất. Ít distraction, nhiều focus.";
  } else {
    return "Khuya thế này mà vẫn online. Respect - nhưng ngủ đủ giấc đấy.";
  }
}

function showCompanionDialogue(message, author = null, duration = 8500) {
  const dialogue = document.getElementById('companion-dialogue');
  const textEl = document.getElementById('dialogue-text');
  if (!dialogue || !textEl) return;

  clearTimeout(companionDialogueTimer);
  clearInterval(companionTypewriterTimer);

  dialogue.classList.remove('show');
  textEl.innerHTML = '';

  // Trigger DOM reflow for smooth animation replay
  void dialogue.offsetWidth;
  dialogue.classList.add('show');

  if (typeof playCyberSound === 'function') {
    try { playCyberSound('pop'); } catch (e) {}
  }

  let idx = 0;
  const chars = Array.from(message);
  companionTypewriterTimer = setInterval(() => {
    if (idx < chars.length) {
      textEl.textContent += chars[idx];
      idx++;
    } else {
      clearInterval(companionTypewriterTimer);
      if (author) {
        const authorEl = document.createElement('span');
        authorEl.className = 'quote-author';
        authorEl.textContent = `— ${author}`;
        textEl.appendChild(authorEl);
      }
    }
  }, 16);

  if (duration > 0) {
    companionDialogueTimer = setTimeout(() => {
      dismissDialogue();
    }, duration);
  }
}

function dismissDialogue() {
  const dialogue = document.getElementById('companion-dialogue');
  if (dialogue) {
    dialogue.classList.remove('show');
  }
  clearTimeout(companionDialogueTimer);
  clearInterval(companionTypewriterTimer);
}

function interactWithCompanion() {
  const companion = document.getElementById('cyber-companion');
  if (!companion) return;

  // If collapsed, clicking restores it
  if (companion.classList.contains('collapsed')) {
    toggleCompanionCollapse();
    return;
  }

  if (typeof playCyberSound === 'function') {
    try { playCyberSound('click'); } catch (e) {}
  }

  // Holographic re-sync glitch animation + tactical bounce feedback
  const modelWrap = companion.querySelector('.companion-model-wrap');
  if (modelWrap) {
    modelWrap.classList.add('is-syncing');
    modelWrap.style.transform = 'translateY(-8px) scale(1.03)';
    setTimeout(() => {
      modelWrap.classList.remove('is-syncing');
      modelWrap.style.transform = '';
    }, 350);
  }

  // 45% quote, 35% reaction, 20% greeting
  const rand = Math.random();
  if (rand < 0.45) {
    const q = COMPANION_QUOTES[Math.floor(Math.random() * COMPANION_QUOTES.length)];
    showCompanionDialogue(q.text, q.author, 9000);
  } else if (rand < 0.80) {
    const r = COMPANION_REACTIONS[Math.floor(Math.random() * COMPANION_REACTIONS.length)];
    showCompanionDialogue(r, "Kira // Operative", 8000);
  } else {
    const g = COMPANION_GREETINGS[Math.floor(Math.random() * COMPANION_GREETINGS.length)];
    showCompanionDialogue(g, "Security Telemetry", 8000);
  }
}

function toggleCompanionCollapse() {
  const companion = document.getElementById('cyber-companion');
  const toggleBtn = document.getElementById('companion-toggle-btn');
  if (!companion) return;

  const isCollapsed = companion.classList.toggle('collapsed');
  if (toggleBtn) {
    const icon = toggleBtn.querySelector('.toggle-icon') || toggleBtn;
    icon.textContent = isCollapsed ? '+' : '−';
    toggleBtn.title = isCollapsed ? 'Expand companion' : 'Minimize companion';
  }

  if (isCollapsed) {
    dismissDialogue();
  }

  try {
    localStorage.setItem('zeropwn_companion_collapsed', isCollapsed ? 'true' : 'false');
  } catch (e) {}

  if (typeof playCyberSound === 'function') {
    try { playCyberSound('click'); } catch (e) {}
  }
}

function initCompanion() {
  const companion = document.getElementById('cyber-companion');
  if (!companion) return;

  // Restore saved collapse state
  try {
    const isCollapsed = localStorage.getItem('zeropwn_companion_collapsed') === 'true';
    if (isCollapsed) {
      companion.classList.add('collapsed');
      const toggleBtn = document.getElementById('companion-toggle-btn');
      if (toggleBtn) {
        const icon = toggleBtn.querySelector('.toggle-icon') || toggleBtn;
        icon.textContent = '+';
        toggleBtn.title = 'Expand companion';
      }
    }
  } catch (e) {}

  // Load encrypted model stream into in-memory canvas
  try {
    loadSecuredCompanionModel();
  } catch (e) {
    console.warn('Companion model load error:', e);
  }

  // Initial greeting after 1.4s if not collapsed
  setTimeout(() => {
    if (!companion.classList.contains('collapsed')) {
      showCompanionDialogue(getContextualGreeting(), "Kira // 0x0D", 7500);
    }
  }, 1400);

  // Periodic random quote every 45s if idle & not collapsed
  clearInterval(companionIdleInterval);
  companionIdleInterval = setInterval(() => {
    if (!companion.classList.contains('collapsed')) {
      const dialogue = document.getElementById('companion-dialogue');
      if (!dialogue || !dialogue.classList.contains('show')) {
        const q = COMPANION_QUOTES[Math.floor(Math.random() * COMPANION_QUOTES.length)];
        showCompanionDialogue(q.text, q.author, 8500);
      }
    }
  }, 45000);
}

/* ═════════════════════════════════════════════════════════════════════
   CYBER DEFENSE: ZERO-BLOB JIGSAW MATRIX RECONSTRUCTOR
   Reassembles shredded, tile-permuted & XOR-scrambled matrix in RAM.
   NEVER generates Image, Blob, or ObjectURL — paints directly to canvas.
   ═════════════════════════════════════════════════════════════════════ */

let companionImageData = null;

async function loadSecuredCompanionModel() {
  const canvas = document.getElementById('companion-canvas');
  if (!canvas) return;

  const binPath = canvas.getAttribute('data-model-bin') || 'photos/model.bin';
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  ctx.clearRect(0, 0, canvas.width, canvas.height);

  let rawBuffer = null;

  // 1. Instantaneous in-memory matrix if available (supports local file:// and zero-latency load)
  if (typeof window.__KIRA_MATRIX_DATA__ === 'string' && window.__KIRA_MATRIX_DATA__.length > 100) {
    try {
      const binaryString = atob(window.__KIRA_MATRIX_DATA__);
      const len = binaryString.length;
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
      rawBuffer = bytes.buffer;
    } catch (e) {
      console.warn('[!] Memory matrix decode fallback:', e);
    }
  }

  // 2. Fetch binary stream if not preloaded (standard HTTP / HTTPS on GitHub Pages)
  if (!rawBuffer) {
    try {
      const resp = await fetch(binPath);
      if (resp.ok) {
        rawBuffer = await resp.arrayBuffer();
      }
    } catch (e) {
      console.warn('[!] Fetch matrix stream error:', e);
    }
  }

  if (!rawBuffer) {
    console.warn('[!] No valid companion matrix stream found.');
    return;
  }

  try {
    // Verify Custom Magic Header ('KZSH' = 0x4B 0x5A 0x53 0x48)
    const headerView = new DataView(rawBuffer, 0, 18);
    const magic = String.fromCharCode(
      headerView.getUint8(0),
      headerView.getUint8(1),
      headerView.getUint8(2),
      headerView.getUint8(3)
    );
    if (magic !== 'KZSH') {
      throw new Error('Corrupted or unauthorized asset stream');
    }

    const targetW = headerView.getUint16(4);
    const targetH = headerView.getUint16(6);
    const cols = headerView.getUint16(8);
    const rows = headerView.getUint16(10);
    const tileW = headerView.getUint16(12);
    const tileH = headerView.getUint16(14);
    const numTiles = headerView.getUint16(16);

    canvas.width = targetW;
    canvas.height = targetH;

    // Read Permutation Table
    const permOffset = 18;
    const perm = new Uint16Array(numTiles);
    for (let i = 0; i < numTiles; i++) {
      perm[i] = headerView.getUint16(permOffset + i * 2);
    }

    // Decompress Tile Stream via native Web Streams API
    const compressedBytes = rawBuffer.slice(permOffset + numTiles * 2);
    let decompressedArr;
    if (typeof DecompressionStream !== 'undefined') {
      const ds = new DecompressionStream('deflate');
      const decompressedStream = new Response(compressedBytes).body.pipeThrough(ds);
      decompressedArr = new Uint8Array(await new Response(decompressedStream).arrayBuffer());
    } else {
      throw new Error('DecompressionStream unsupported in this browser environment');
    }

    const tileSize = tileW * tileH * 4;
    const imgData = ctx.createImageData(targetW, targetH);
    const canvasPixels = imgData.data;

    // Unscramble, unmask and paint tiles directly into pixel buffer
    for (let pIdx = 0; pIdx < numTiles; pIdx++) {
      const origTileIdx = perm[pIdx];
      const origR = Math.floor(origTileIdx / cols);
      const origC = origTileIdx % cols;
      const mask = ((origR * 23) ^ (origC * 37) ^ 0x5A) & 0xFF;

      const tileBytesStart = pIdx * tileSize;
      for (let tr = 0; tr < tileH; tr++) {
        for (let tc = 0; tc < tileW; tc++) {
          const srcOffset = tileBytesStart + (tr * tileW + tc) * 4;
          const dstY = origR * tileH + tr;
          const dstX = origC * tileW + tc;
          const dstOffset = (dstY * targetW + dstX) * 4;

          canvasPixels[dstOffset]     = decompressedArr[srcOffset] ^ mask;
          canvasPixels[dstOffset + 1] = decompressedArr[srcOffset + 1] ^ mask;
          canvasPixels[dstOffset + 2] = decompressedArr[srcOffset + 2] ^ mask;
          canvasPixels[dstOffset + 3] = decompressedArr[srcOffset + 3] ^ mask;
        }
      }
    }

    companionImageData = imgData;
    ctx.putImageData(imgData, 0, 0);

  } catch (err) {
    console.warn('[!] Companion matrix reconstructor error:', err);
  }

  // Poison canvas export methods so console / scraper execution returns blank/error
  canvas.toDataURL = function() {
    return 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
  };
  canvas.toBlob = function(cb) {
    if (typeof cb === 'function') cb(new Blob([], { type: 'image/png' }));
  };
}

function initConsoleDefense() {
  try {
    const bannerStyle = 'color: #e8192c; font-size: 16px; font-weight: bold; font-family: monospace; text-shadow: 0 0 8px rgba(232, 25, 44, 0.7);';
    const infoStyle = 'color: #38ef7d; font-size: 11px; font-family: monospace;';
    const warnStyle = 'color: #8888aa; font-size: 10px; font-family: monospace;';
    console.log('%c[!] uziii2208 // LEVEL-5 ASSET & CONTENT DEFENSE ACTIVE', bannerStyle);
    console.log('%c[+] Anti-Tamper, Steganographic Provenance & OPSEC Shields Enforced.', infoStyle);
    console.log('%c[*] Unauthorized reproduction of Operative Kira (0x0D) & classified exploit research is strictly monitored.', warnStyle);
  } catch (e) {}
}

function initContentShield() {
  // 1. Global Context Menu Shield: Disable right-click across the ENTIRE document
  // (Neutralizes browser context menu shown in error.png)
  window.addEventListener('contextmenu', (e) => {
    const target = e.target;
    // Strictly allow right-click ONLY inside code blocks or text inputs
    const isInsideCode = target && (
      target.closest('pre') ||
      target.closest('code') ||
      target.closest('input') ||
      target.closest('textarea')
    );

    if (!isInsideCode) {
      e.preventDefault();
      if (typeof showToast === 'function') {
        showToast('[OPSEC ALERT] Context extraction locked // Level-5 defense active.');
      }
      if (typeof playCyberSound === 'function') {
        try { playCyberSound('error'); } catch (err) {}
      }
      return false;
    }
  }, true);

  // 2. Anti-Copy Engine: Strictly allow copying ONLY from code blocks or inputs
  document.addEventListener('copy', (e) => {
    const selection = window.getSelection();
    if (!selection || selection.rangeCount === 0 || selection.isCollapsed) return;

    let anchorNode = selection.anchorNode;
    if (anchorNode && anchorNode.nodeType === Node.TEXT_NODE) {
      anchorNode = anchorNode.parentElement;
    }

    const isInsideCode = anchorNode && (
      anchorNode.closest('pre') ||
      anchorNode.closest('code') ||
      anchorNode.closest('.code-block-wrap') ||
      anchorNode.closest('input') ||
      anchorNode.closest('textarea')
    );

    if (!isInsideCode) {
      e.preventDefault();
      if (e.clipboardData) {
        e.clipboardData.clearData();
      }
      if (typeof showToast === 'function') {
        showToast('[OPSEC] Prose copying prohibited. Only code blocks may be copied.');
      }
      if (typeof playCyberSound === 'function') {
        try { playCyberSound('error'); } catch (err) {}
      }
    }
  });

  // 3. Global Drag & Drop Shield: Prevent dragging any canvas, image, or text
  window.addEventListener('dragstart', (e) => {
    e.preventDefault();
    return false;
  }, true);

  // 4. Global Keyboard Shortcut Armor: Block DevTools (F12, Ctrl+Shift+I/J/C), View Source (Ctrl+U), Save (Ctrl+S), Select All (Ctrl+A)
  window.addEventListener('keydown', (e) => {
    const isCtrlOrCmd = e.ctrlKey || e.metaKey;
    const target = e.target;
    const isInput = target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA');

    if (isInput) return;

    // Prevent F12 and DevTools shortcuts (Ctrl+Shift+I / J / C)
    if (e.key === 'F12' || (isCtrlOrCmd && e.shiftKey && ['I', 'i', 'J', 'j', 'C', 'c'].includes(e.key))) {
      e.preventDefault();
      if (typeof showToast === 'function') {
        showToast('[DEFENSE] Debugger console hotkey blocked.');
      }
      return false;
    }

    // Prevent Ctrl+U / Cmd+U (View Source)
    if (isCtrlOrCmd && (e.key === 'u' || e.key === 'U')) {
      e.preventDefault();
      if (typeof showToast === 'function') {
        showToast('[OPSEC] Source payload inspection restricted.');
      }
      return false;
    }

    // Prevent Ctrl+S / Cmd+S (Save page as HTML)
    if (isCtrlOrCmd && (e.key === 's' || e.key === 'S')) {
      e.preventDefault();
      if (typeof showToast === 'function') {
        showToast('[OPSEC] Offline clone extraction blocked.');
      }
      if (typeof playCyberSound === 'function') {
        try { playCyberSound('error'); } catch (err) {}
      }
      return false;
    }

    // Prevent Ctrl+A / Cmd+A outside code blocks
    if (isCtrlOrCmd && (e.key === 'a' || e.key === 'A')) {
      const selection = window.getSelection();
      let isInsideCode = false;
      if (selection && selection.anchorNode) {
        let node = selection.anchorNode.nodeType === Node.TEXT_NODE ? selection.anchorNode.parentElement : selection.anchorNode;
        isInsideCode = node && (node.closest('pre') || node.closest('code'));
      }
      if (!isInsideCode) {
        e.preventDefault();
        if (typeof showToast === 'function') {
          showToast('[OPSEC] Bulk selection disabled.');
        }
        return false;
      }
    }
  }, true);
}

// Global exposure for onclick bindings
window.interactWithCompanion = interactWithCompanion;
window.dismissDialogue = dismissDialogue;
window.toggleCompanionCollapse = toggleCompanionCollapse;

/* ─── INITIAL EXECUTION (ROBUST BOOT WITH READYSTATE CHECK) ─── */
function boot() {
  try { initConsoleDefense(); } catch (e) {}
  try { initContentShield(); } catch (e) {}
  try { initBanner(); } catch (e) { console.warn('Banner init:', e); }
  try { updateSFXButtonUI(); } catch (e) { console.warn('SFX UI init:', e); }
  try { initScrambleEffects(); } catch (e) { console.warn('Scramble init:', e); }

  // Canvas background (Hero, post detail view, or post archive view)
  if (document.getElementById('cyber-canvas')) {
    try { initCyberCanvas(); } catch (e) { console.warn('Canvas init:', e); }
  }

  // Interactive Operative Companion
  if (document.getElementById('cyber-companion')) {
    try { initCompanion(); } catch (e) { console.warn('Companion init:', e); }
  }

  // If on homepage or post archive list
  if (document.getElementById('post-list')) {
    try { initData(); } catch (e) { console.error('Data init error:', e); }
  }

  // If on single post page
  if (document.body.classList.contains('page-post')) {
    try { initReadingProgressBar(); } catch (e) { console.warn('Progress bar:', e); }
    try { processCodeBlocks(document.getElementById('post-view-content')); } catch (e) { console.warn('Code blocks:', e); }
    try { renderLaTeX(document.getElementById('post-view-content') || document.body); } catch (e) { console.warn('LaTeX render:', e); }
    try { initImageLightbox(); } catch (e) { console.warn('Lightbox:', e); }
    try { initScrollSpy(); } catch (e) { console.warn('ScrollSpy:', e); }
  } else {
    try { renderLaTeX(document.body); } catch (e) { console.warn('LaTeX render:', e); }
  }

  try { initBackToTop(); } catch (e) { console.warn('BackToTop:', e); }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot);
} else {
  boot();
}

window.addEventListener('load', () => {
  try {
    const target = document.getElementById('post-view-content') || document.body;
    renderLaTeX(target);
  } catch (e) {}
});
