# 🔐 CipherCore — Data Security Suite

A web-based encryption and decryption tool built on a **Triple-Key Affine Cipher** operating over a 32-symbol modular field. Messages are encoded as raw bitstreams, combining classical cryptography with a clean cyberpunk-themed UI.

---

## 📸 Preview

> Military-grade bitstream encryption and decryption using a triple-key affine cipher system.

The interface features a live Matrix rain canvas, animated scanlines, a real-time HUD clock, and a fully interactive encrypt/decrypt panel — all running in-browser with zero dependencies.

---

## 🚀 Features

- **Triple-key affine cipher** with three independently configurable key parameters
- **Bitstream encoding** — every character is converted to exactly 6 bits
- **Encrypt & Decrypt** in-browser with instant feedback
- **Animated cyberpunk UI** — Matrix rain, scanline overlay, glowing HUD elements
- **Input validation** — key constraints (k2 must be odd), bitstream format checking
- **C++ reference implementations** included (`enc.txt`, `dec.txt`) for the original CLI versions

---

## 🔢 How the Cipher Works

### Encryption
```
E(x) = ((x + k1) × k2 + k3) mod 32
```
Each letter (A–Z, mapped 0–25) is shifted by `k1`, scaled by `k2`, then shifted by `k3`. The result is encoded as a 6-bit token.

### Decryption
```
D(y) = ((y - k3) × k2⁻¹ - k1) mod 32
```
Reverses encryption using the **modular inverse** of `k2` (mod 32).

### Bitstream Encoding
| Character | Bit Token |
|-----------|-----------|
| Letter    | `0` + 5-bit encrypted value |
| Space     | `100000` (reserved, unambiguous) |

> **Key constraint:** `k2` must be **odd** so that its modular inverse mod 32 exists (i.e., gcd(k2, 32) = 1).

---

## 📁 Project Structure

```
data sec proj/
├── index.html     # Main UI — all sections, layout, and script imports
├── style.css      # Full cyberpunk theme — animations, HUD, responsive layout
├── cipher.js      # Core cipher logic (JS port of C++ algorithms)
├── enc.txt        # Original C++ encryption CLI program
└── dec.txt        # Original C++ decryption CLI program
```

---

## 🛠️ Getting Started

### Option 1 — Open Directly (No Setup Required)

Just open `index.html` in any modern browser. No server, no build step, no dependencies.

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/ciphercore.git
cd ciphercore

# Open in browser
open index.html          # macOS
start index.html         # Windows
xdg-open index.html      # Linux
```

### Option 2 — Run a Local Server (Recommended for Development)

```bash
# Using Python
python -m http.server 8080

# Using Node.js
npx serve .
```

Then visit `http://localhost:8080` in your browser.

---

## 💻 C++ CLI Programs

The original cipher logic was implemented as two standalone C++ programs.

### Compile & Run

```bash
# Encryption
g++ -o encrypt enc.txt
./encrypt

# Decryption
g++ -o decrypt dec.txt
./decrypt
```

Follow the prompts to enter keys and a message.

---

## 🔑 Key Rules

| Key | Rule |
|-----|------|
| `k1` | Any integer |
| `k2` | **Must be odd** (1, 3, 5, 7, 9, 11, ...) |
| `k3` | Any integer |

> If `k2` is even, decryption is mathematically impossible because no modular inverse exists mod 32.

---

## 🧰 Technologies Used

- **HTML5** / **CSS3** / **Vanilla JavaScript** — no frameworks or libraries
- **Google Fonts** — Orbitron, Share Tech Mono, Inter
- **CSS animations** — Matrix rain (Canvas API), scanlines, glitch effects
- **C++** — original CLI reference implementation

---

## 📄 License

This project was built for educational purposes as a data security coursework project. Feel free to fork and extend 
