/* ============================================================
   CipherCore — cipher.js
   Ports enc.txt + dec.txt C++ logic to JavaScript exactly.
   ============================================================ */

'use strict';

// ─────────────────────────────────────────────
//  CORE CIPHER MATH  (mirrors C++ functions)
// ─────────────────────────────────────────────

/**
 * modInverse(a, m)
 * Finds x such that (a * x) % m === 1.
 * Mirrors the C++ brute-force loop over [1, m).
 * k2 must be odd for mod-32 inverse to exist.
 */
function modInverse(a, m) {
  a = ((a % m) + m) % m;
  for (let x = 1; x < m; x++) {
    if ((a * x) % m === 1) return x;
  }
  throw new Error('k2 has no modular inverse. It must be odd and coprime to 32.');
}

/**
 * encryptValue(val, k1, k2, k3)
 * E(x) = ((val + k1) * k2 + k3) mod 32
 */
function encryptValue(val, k1, k2, k3) {
  const step1 = (val + k1) % 32;
  const step2 = (step1 * k2) % 32;
  const step3 = (step2 + k3) % 32;
  return ((step3 % 32) + 32) % 32;
}

/**
 * decryptValue(val, k1, k2, k3)
 * D(y) = ((val - k3) * k2_inv - k1) mod 32
 */
function decryptValue(val, k1, k2, k3) {
  const k2inv = modInverse(k2, 32);
  const step1 = ((val - k3) % 32 + 32) % 32;
  const step2 = (step1 * k2inv) % 32;
  const step3 = ((step2 - k1) % 32 + 32) % 32;
  return step3;
}

/**
 * encryptText(plaintext, k1, k2, k3)
 * Converts letters → "0" + 5-bit encrypted value
 * Converts spaces  → "100000"
 * Returns: bitstream string
 */
function encryptText(plaintext, k1, k2, k3) {
  let bitstream = '';
  for (const ch of plaintext) {
    if (ch === ' ') {
      bitstream += '100000';
    } else if (/[a-zA-Z]/.test(ch)) {
      const val = ch.toUpperCase().charCodeAt(0) - 'A'.charCodeAt(0);
      const enc = encryptValue(val, k1, k2, k3);
      const bits = enc.toString(2).padStart(5, '0');
      bitstream += '0' + bits;
    }
    // non-alpha, non-space characters are silently skipped (same as C++)
  }
  return bitstream;
}

/**
 * decryptBitstream(bitstream, k1, k2, k3)
 * Reads 6 bits at a time:
 *   leading '1' → space (token "100000")
 *   leading '0' → letter (skip leading 0, decode next 5 bits)
 * Returns: { text, tokens }
 */
function decryptBitstream(bitstream, k1, k2, k3) {
  // Validate: only 0s and 1s
  if (!/^[01]*$/.test(bitstream)) {
    throw new Error('Bitstream must contain only 0s and 1s.');
  }
  if (bitstream.length % 6 !== 0) {
    throw new Error(`Bitstream length (${bitstream.length}) is not a multiple of 6. Each token is exactly 6 bits.`);
  }

  let result = '';
  const tokens = [];
  let i = 0;

  while (i < bitstream.length) {
    if (i + 6 > bitstream.length) {
      throw new Error('Incomplete token at position ' + i + '.');
    }
    const token = bitstream.substr(i, 6);

    if (token[0] === '1') {
      // Space marker
      result += ' ';
      tokens.push({ token, decoded: 'SPACE' });
    } else {
      // Letter: skip leading '0', read 5-bit value
      const chunk = token.substr(1, 5);
      const val   = parseInt(chunk, 2);
      const dec   = decryptValue(val, k1, k2, k3);
      const ch    = (dec >= 0 && dec <= 25) ? String.fromCharCode('A'.charCodeAt(0) + dec) : '?';
      result += ch;
      tokens.push({ token, val, dec, decoded: ch });
    }
    i += 6;
  }

  return { text: result, tokens };
}

// ─────────────────────────────────────────────
//  UI HELPERS
// ─────────────────────────────────────────────

function getIntVal(id) {
  const v = document.getElementById(id).value.trim();
  if (v === '' || isNaN(Number(v))) throw new Error(`Field "${id.replace('-', ' ').toUpperCase()}" must be a valid integer.`);
  return parseInt(v, 10);
}

function showError(panelId, msg) {
  const el = document.getElementById(panelId + '-error');
  el.textContent = '⚠ ' + msg;
  el.style.display = 'block';
}

function hideError(panelId) {
  document.getElementById(panelId + '-error').style.display = 'none';
}

function setProgress(panelId, pct) {
  document.getElementById(panelId + '-progress-bar').style.width = pct + '%';
}

function animateTyping(elementId, text, speed = 18) {
  const el = document.getElementById(elementId);
  el.textContent = '';
  let i = 0;
  const interval = setInterval(() => {
    el.textContent += text[i];
    i++;
    if (i >= text.length) clearInterval(interval);
  }, speed);
}

// ─────────────────────────────────────────────
//  ENCRYPT HANDLER
// ─────────────────────────────────────────────

function runEncrypt(isRealTime = false) {
  hideError('enc');
  if (!isRealTime) {
    document.getElementById('enc-output-group').style.display = 'none';
    setProgress('enc', 0);
  }

  let k1, k2, k3;
  try {
    k1 = getIntVal('enc-k1-display');
    k2 = getIntVal('enc-k2-display');
    k3 = getIntVal('enc-k3-display');
  } catch (e) {
    showError('enc', e.message);
    return;
  }

  if (k2 % 2 === 0) {
    showError('enc', 'k2 must be ODD (e.g. 3, 5, 7, 9, 11, ...). Even numbers have no modular inverse mod 32.');
    return;
  }

  const plaintext = document.getElementById('enc-input').value;
  if (!plaintext.trim()) {
    if (!isRealTime) showError('enc', 'Please enter a message to encrypt.');
    return;
  }

  const processAndShow = () => {
    try {
      const bitstream = encryptText(plaintext, k1, k2, k3);

      if (!bitstream) {
        throw new Error('No encryptable characters found. Use letters and spaces only.');
      }

      // Show output
      const outGroup = document.getElementById('enc-output-group');
      outGroup.style.display = 'block';

      const outBox = document.getElementById('enc-output');
      if (isRealTime) {
        outBox.textContent = bitstream;
      } else {
        outBox.textContent = '';
        animateTyping('enc-output', bitstream, 8);
        if (typeof fireSuccessAnimation === 'function') fireSuccessAnimation('ENCRYPTION SUCCESSFUL');
      }

      // Meta
      const letters = (plaintext.match(/[a-zA-Z]/g) || []).length;
      const spaces  = (plaintext.match(/ /g) || []).length;
      document.getElementById('enc-meta').innerHTML =
        `<span>📏 ${bitstream.length} bits</span>` +
        `<span>🔤 ${letters} letters</span>` +
        `<span>␣ ${spaces} spaces</span>` +
        `<span>🔑 k1=${k1} k2=${k2} k3=${k3}</span>`;

    } catch (e) {
      if (!isRealTime) setProgress('enc', 0);
      showError('enc', e.message);
    }
  };

  if (isRealTime) {
    processAndShow();
  } else {
    // Progress animation
    let p = 0;
    const progressInterval = setInterval(() => {
      p += 15;
      setProgress('enc', Math.min(p, 90));
      if (p >= 90) clearInterval(progressInterval);
    }, 60);

    setTimeout(() => {
      clearInterval(progressInterval);
      setProgress('enc', 100);
      processAndShow();
    }, 400);
  }
}

// ─────────────────────────────────────────────
//  DECRYPT HANDLER
// ─────────────────────────────────────────────

function runDecrypt(isRealTime = false) {
  hideError('dec');
  if (!isRealTime) {
    document.getElementById('dec-output-group').style.display = 'none';
    setProgress('dec', 0);
  }

  let k1, k2, k3;
  try {
    k1 = getIntVal('dec-k1-display');
    k2 = getIntVal('dec-k2-display');
    k3 = getIntVal('dec-k3-display');
  } catch (e) {
    showError('dec', e.message);
    return;
  }

  // Validate k2 has modular inverse
  try {
    modInverse(k2, 32);
  } catch (e) {
    showError('dec', 'Key error: ' + e.message);
    return;
  }

  const bitstream = document.getElementById('dec-input').value.trim();
  if (!bitstream) {
    if (!isRealTime) showError('dec', 'Please paste a bitstream to decrypt.');
    return;
  }

  const processAndShow = () => {
    try {
      const { text, tokens } = decryptBitstream(bitstream, k1, k2, k3);

      const outGroup = document.getElementById('dec-output-group');
      outGroup.style.display = 'block';

      const outBox = document.getElementById('dec-output');
      if (isRealTime) {
        outBox.textContent = text;
      } else {
        outBox.textContent = '';
        animateTyping('dec-output', text, 60);
        if (typeof fireSuccessAnimation === 'function') fireSuccessAnimation('DECRYPTION SUCCESSFUL');
      }

      document.getElementById('dec-meta').innerHTML =
        `<span>📡 ${bitstream.length} bits read</span>` +
        `<span>🔤 ${tokens.length} tokens</span>` +
        `<span>✅ ${text.trim().length} chars out</span>` +
        `<span>🔑 k1=${k1} k2=${k2} k3=${k3}</span>`;

    } catch (e) {
      if (!isRealTime) setProgress('dec', 0);
      showError('dec', e.message);
    }
  };

  if (isRealTime) {
    processAndShow();
  } else {
    let p = 0;
    const progressInterval = setInterval(() => {
      p += 15;
      setProgress('dec', Math.min(p, 90));
      if (p >= 90) clearInterval(progressInterval);
    }, 60);

    setTimeout(() => {
      clearInterval(progressInterval);
      setProgress('dec', 100);
      processAndShow();
    }, 400);
  }
}

// ─────────────────────────────────────────────
//  COPY TO CLIPBOARD
// ─────────────────────────────────────────────

function copyText(elementId, btn) {
  const text = document.getElementById(elementId).textContent;
  navigator.clipboard.writeText(text).then(() => {
    btn.textContent = '✓ COPIED';
    btn.classList.add('copied');
    setTimeout(() => {
      btn.textContent = '⎘ COPY';
      btn.classList.remove('copied');
    }, 2000);
  }).catch(() => {
    // Fallback for non-secure contexts
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    btn.textContent = '✓ COPIED';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = '⎘ COPY'; btn.classList.remove('copied'); }, 2000);
  });
}

// ─────────────────────────────────────────────
//  LIVE DEMO PIPELINE
// ─────────────────────────────────────────────

function runDemo() {
  const demoOut = document.getElementById('demo-output');
  demoOut.style.display = 'none';

  const msg  = 'HELLO WORLD';
  const k1   = 4, k2 = 7, k3 = 3;

  const bitstream = encryptText(msg, k1, k2, k3);
  const { text }  = decryptBitstream(bitstream, k1, k2, k3);

  // Build token table for step 1
  let tokenTable = '';
  for (const ch of msg) {
    if (ch === ' ') {
      tokenTable += `<tr><td>SPACE</td><td>—</td><td>—</td><td style="color:var(--orange)">100000</td></tr>`;
    } else {
      const val = ch.charCodeAt(0) - 'A'.charCodeAt(0);
      const enc = encryptValue(val, k1, k2, k3);
      const bits = '0' + enc.toString(2).padStart(5, '0');
      tokenTable += `<tr><td style="color:var(--green)">${ch}</td><td>${val}</td><td>${enc}</td><td style="color:var(--orange)">${bits}</td></tr>`;
    }
  }

  document.getElementById('demo-step-1').innerHTML = `
    <strong>① INPUT &nbsp;|&nbsp; Keys: k1=${k1}, k2=${k2}, k3=${k3}</strong><br/>
    Message: <span style="color:var(--cyan);font-size:1rem;letter-spacing:0.1em">${msg}</span><br/><br/>
    <table style="width:100%;border-collapse:collapse;font-size:0.72rem;">
      <thead><tr style="color:var(--text-dim)"><th align="left">Char</th><th align="left">Index</th><th align="left">Encrypted</th><th align="left">6-bit Token</th></tr></thead>
      <tbody>${tokenTable}</tbody>
    </table>`;

  document.getElementById('demo-step-2').innerHTML = `
    <strong>② ENCRYPTED BITSTREAM</strong><br/>
    <span class="bits">${bitstream}</span><br/>
    <span style="color:var(--text-dim);font-size:0.68rem;">${bitstream.length} bits total — ${msg.replace(/ /g,''  ).length} letters + ${(msg.match(/ /g)||[]).length} space(s)</span>`;

  document.getElementById('demo-step-3').innerHTML = `
    <strong>③ DECRYPTED OUTPUT</strong><br/>
    <span class="result">${text}</span><br/>
    <span style="color:var(--green);font-size:0.68rem;">✓ Perfect round-trip recovery confirmed</span>`;

  demoOut.style.display = 'flex';
}

// ─────────────────────────────────────────────
//  CHARACTER COUNTERS
// ─────────────────────────────────────────────

document.getElementById('enc-input').addEventListener('input', function () {
  document.getElementById('enc-char-count').textContent = this.value.length;
});

document.getElementById('dec-input').addEventListener('input', function () {
  const bits = this.value.replace(/[^01]/g, '').length;
  document.getElementById('dec-char-count').textContent = bits;
});

// ─────────────────────────────────────────────
//  HUD CLOCK
// ─────────────────────────────────────────────

function updateClock() {
  const now = new Date();
  const hh  = String(now.getHours()).padStart(2, '0');
  const mm  = String(now.getMinutes()).padStart(2, '0');
  const ss  = String(now.getSeconds()).padStart(2, '0');
  document.getElementById('hud-clock').textContent = `${hh}:${mm}:${ss}`;
}
updateClock();
setInterval(updateClock, 1000);

// ─────────────────────────────────────────────
//  MATRIX RAIN
// ─────────────────────────────────────────────

(function initMatrixRain() {
  const canvas  = document.getElementById('matrix-canvas');
  const ctx     = canvas.getContext('2d');
  const CHARS   = '0123456789アイウエオカキクケコサシスセソタチツテトナニヌネノ';
  let cols, drops;

  function resize() {
    canvas.width  = window.innerWidth;
    canvas.height = window.innerHeight;
    cols  = Math.floor(canvas.width / 16);
    drops = Array(cols).fill(1).map(() => Math.random() * -50);
  }

  function draw() {
    ctx.fillStyle = 'rgba(5,13,10,0.35)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    ctx.font = '15px "Share Tech Mono", monospace';

    for (let i = 0; i < drops.length; i++) {
      const char = CHARS[Math.floor(Math.random() * CHARS.length)];
      const x    = i * 16;
      const y    = drops[i] * 16;

      // Brighter head
      if (Math.random() > 0.75) {
        ctx.fillStyle = '#ffffff';
      } else if (Math.random() > 0.5) {
        ctx.fillStyle = `rgba(0,255,200,1.0)`;
      } else {
        const alpha = 0.75 + Math.random() * 0.25;
        ctx.fillStyle = `rgba(0,255,136,${alpha})`;
      }

      ctx.fillText(char, x, y);

      if (y > canvas.height && Math.random() > 0.975) {
        drops[i] = 0;
      }
      drops[i] += 0.5 + Math.random() * 0.3;
    }
  }

  resize();
  window.addEventListener('resize', resize);
  setInterval(draw, 50);
})();

// ─────────────────────────────────────────────
//  HERO CIPHER BOX ANIMATION
// ─────────────────────────────────────────────

(function initHeroAnimation() {
  const samples = [
    { label: 'INPUT',  val: () => randomWord() },
    { label: 'ENC',    val: () => randomBits(30) },
    { label: 'BITLEN', val: () => String(Math.floor(Math.random() * 80 + 30)) + ' bits' },
    { label: 'STATUS', val: () => 'SECURE ✓' }
  ];

  function randomWord() {
    const words = ['ALPHA', 'BRAVO', 'CIPHER', 'DELTA', 'ECHO', 'FOXTROT', 'GHOST', 'HELIX'];
    return words[Math.floor(Math.random() * words.length)];
  }

  function randomBits(len) {
    return Array.from({ length: len }, () => Math.random() > 0.5 ? '1' : '0').join('');
  }

  function update() {
    samples.forEach((s, idx) => {
      const el = document.getElementById(`anim-line-${idx + 1}`);
      if (el) el.textContent = `${s.label.padEnd(8)}→  ${s.val()}`;
    });
  }

  update();
  setInterval(update, 1800);
})();

// ─────────────────────────────────────────────
//  ENTER KEY SHORTCUTS
// ─────────────────────────────────────────────

document.getElementById('enc-input').addEventListener('keydown', function (e) {
  if (e.ctrlKey && e.key === 'Enter') runEncrypt();
});

document.getElementById('dec-input').addEventListener('keydown', function (e) {
  if (e.ctrlKey && e.key === 'Enter') runDecrypt();
});

// ─────────────────────────────────────────────
//  CYBERPUNK CONTROLS (SLIDERS & DIALS)
// ─────────────────────────────────────────────

function setupSliders() {
  document.querySelectorAll('.neon-slider').forEach(slider => {
    const displayId = slider.id + '-display';
    const displayEl = document.getElementById(displayId);

    const updateGlow = () => {
      const min = parseFloat(slider.min) || 0;
      const max = parseFloat(slider.max) || 31;
      const val = parseFloat(slider.value);
      const pct = ((val - min) / (max - min)) * 100;
      
      const glowLayer = slider.parentElement.querySelector('.slider-glow-layer');
      if (glowLayer) glowLayer.style.width = pct + '%';
      
      if (displayEl && document.activeElement !== displayEl) {
        displayEl.value = val;
      }
    };
    
    slider.addEventListener('input', () => {
      updateGlow();
      const isEnc = slider.id.startsWith('enc-');
      if (isEnc) runEncrypt(true);
      else runDecrypt(true);
    });
    
    if (displayEl) {
      displayEl.addEventListener('input', () => {
        const val = parseInt(displayEl.value, 10);
        if (!isNaN(val)) {
           slider.value = val;
           const min = parseFloat(slider.min) || 0;
           const max = parseFloat(slider.max) || 31;
           const pct = ((parseFloat(slider.value) - min) / (max - min)) * 100;
           const glowLayer = slider.parentElement.querySelector('.slider-glow-layer');
           if (glowLayer) glowLayer.style.width = pct + '%';
           
           const isEnc = slider.id.startsWith('enc-');
           if (isEnc) runEncrypt(true);
           else runDecrypt(true);
        }
      });
    }

    updateGlow();
  });
}

function setupDials() {
  document.querySelectorAll('.rotary-dial').forEach(dial => {
    const knob = dial.querySelector('.dial-knob');
    const hiddenInput = dial.parentElement.querySelector('input[type="hidden"]');
    const displayEl = dial.parentElement.querySelector('.dial-display');
    
    let isDragging = false;
    let startAngle = 0;
    let currentRotation = 0;
    let val = parseInt(displayEl.value || '7', 10);
    
    // Convert initial value to rotation
    currentRotation = ((val % 32) / 31) * 360;
    knob.style.transform = `rotate(${currentRotation}deg)`;
    checkOddWarning(val);
    
    function checkOddWarning(v) {
      if (v % 2 === 0) {
        dial.classList.add('error');
        displayEl.classList.add('error-glow');
      } else {
        dial.classList.remove('error');
        displayEl.classList.remove('error-glow');
      }
    }
    
    dial.addEventListener('mousedown', (e) => {
      isDragging = true;
      const rect = dial.getBoundingClientRect();
      const centerX = rect.left + rect.width / 2;
      const centerY = rect.top + rect.height / 2;
      startAngle = Math.atan2(e.clientY - centerY, e.clientX - centerX) * 180 / Math.PI - currentRotation;
      e.preventDefault();
    });
    
    document.addEventListener('mousemove', (e) => {
      if (!isDragging) return;
      const rect = dial.getBoundingClientRect();
      const centerX = rect.left + rect.width / 2;
      const centerY = rect.top + rect.height / 2;
      const angle = Math.atan2(e.clientY - centerY, e.clientX - centerX) * 180 / Math.PI;
      
      currentRotation = angle - startAngle;
      
      // Normalize rotation for value calculation (0 to 360)
      let normRot = currentRotation % 360;
      if (normRot < 0) normRot += 360;
      
      val = Math.round((normRot / 360) * 31);
      
      knob.style.transform = `rotate(${currentRotation}deg)`;
      hiddenInput.value = val;
      if (document.activeElement !== displayEl) {
        displayEl.value = val;
      }
      
      checkOddWarning(val);
      
      const isEnc = dial.id.startsWith('enc-');
      if (isEnc) runEncrypt(true);
      else runDecrypt(true);
    });
    
    document.addEventListener('mouseup', () => {
      isDragging = false;
    });

    if (displayEl) {
      displayEl.addEventListener('input', () => {
        val = parseInt(displayEl.value, 10);
        if (!isNaN(val)) {
           hiddenInput.value = val;
           currentRotation = ((Math.abs(val) % 32) / 31) * 360;
           knob.style.transform = `rotate(${currentRotation}deg)`;
           checkOddWarning(val);
           
           const isEnc = dial.id.startsWith('enc-');
           if (isEnc) runEncrypt(true);
           else runDecrypt(true);
        }
      });
    }
  });
}

document.addEventListener('DOMContentLoaded', () => {
  setupSliders();
  setupDials();
});

// ─────────────────────────────────────────────
//  SUCCESS ANIMATION
// ─────────────────────────────────────────────

function fireSuccessAnimation(message = 'ENCRYPTION SUCCESSFUL') {
  const overlay = document.getElementById('success-overlay');
  const canvas = document.getElementById('success-canvas');
  const text = document.getElementById('success-text');
  const ring = document.getElementById('ripple-ring');
  
  if (!overlay || !canvas || !text || !ring) return;
  text.textContent = message;
  
  overlay.style.display = 'flex';
  text.classList.remove('animate');
  ring.classList.remove('animate');
  document.body.classList.remove('glitch-flash');
  
  // Trigger reflow
  void overlay.offsetWidth;
  
  text.classList.add('animate');
  ring.classList.add('animate');
  document.body.classList.add('glitch-flash');
  
  const ctx = canvas.getContext('2d');
  canvas.width = window.innerWidth;
  canvas.height = window.innerHeight;
  
  const particles = [];
  const centerX = canvas.width / 2;
  const centerY = canvas.height / 2;
  
  for (let i = 0; i < 150; i++) {
    particles.push({
      x: centerX,
      y: centerY,
      vx: (Math.random() - 0.5) * 25,
      vy: (Math.random() - 0.5) * 25,
      size: Math.random() * 4 + 1,
      life: 1,
      color: Math.random() > 0.5 ? '#00ff88' : '#c8ffd4',
      char: Math.random() > 0.8 ? (Math.random() > 0.5 ? '0' : '1') : null
    });
  }
  
  let animationId;
  function renderParticles() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    let active = false;
    
    for (const p of particles) {
      if (p.life <= 0) continue;
      active = true;
      p.x += p.vx;
      p.y += p.vy;
      p.life -= 0.015; // fade out speed
      
      ctx.globalAlpha = Math.max(0, p.life);
      ctx.fillStyle = p.color;
      
      if (p.char) {
        ctx.font = 'bold 18px monospace';
        ctx.fillText(p.char, p.x, p.y);
      } else {
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 10;
        ctx.shadowColor = p.color;
      }
      ctx.shadowBlur = 0;
    }
    
    if (active) {
      animationId = requestAnimationFrame(renderParticles);
    }
  }
  
  renderParticles();
  
  setTimeout(() => {
    overlay.style.display = 'none';
    cancelAnimationFrame(animationId);
    text.classList.remove('animate');
    ring.classList.remove('animate');
    document.body.classList.remove('glitch-flash');
  }, 3500);
}
