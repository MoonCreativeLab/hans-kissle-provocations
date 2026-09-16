# deli-counter

Public hosting for a small set of self-contained, illustrative web demos — vanilla HTML/JS,
no build step to *run* them, no network calls, fully offline once open.

## Password-gated

Every published page here contains **only AES-256-GCM ciphertext** plus a tiny in-browser
decryptor (Web Crypto, no libraries). Entering the correct password derives the key
(PBKDF2-SHA256, 200,000 iterations) and decrypts the page in the browser. Without the
password the pages hold no readable content — only the lock screen you can see in the source.

Pages in a single build share one salt, so unlocking any one of them caches the *derived key*
(never the password) in `sessionStorage` and the rest of the set opens without a second
prompt. The cache is scoped to the tab, disappears when the tab closes, and is invalidated by
the next build, which draws a fresh salt.

## Why two repositories

- **This public repo** hosts only the *encrypted* pages, so they can be served on GitHub Pages
  at a public URL without exposing any readable content.
- The **editable plaintext source** lives in a **separate private repo** and is never committed
  here (see `.gitignore`). That keeps the source — and the data baked into it — off the public
  web, while still allowing a public, password-gated link.

In short: the plaintext never leaves the private repo; only ciphertext is ever published.

## Build / update

1. Edit the plaintext sources (in the private repo).
2. Regenerate the encrypted pages. The password is passed via an env var and is **never**
   committed:
   ```
   SITE_PW='<deployment-password>' node build-encrypt.js <path-to>/manifest.json
   ```
   The manifest (also private) lists each page: plaintext source in, encrypted page out, plus
   the title and hint shown on that page's lock screen. The build self-tests every blob by
   decrypting it again in Node before writing it, and refuses to ship one that doesn't
   round-trip.
3. Commit the regenerated pages here and push — GitHub Pages redeploys automatically.

To change the password, rebuild with a different `SITE_PW` and push. Note that rotating it
does **not** retroactively protect anything already published: assume any ciphertext that has
been public has been copied, and that it stays readable to anyone who had the old password.

## Running locally

Web Crypto needs a secure context, so serve over `http://localhost` (e.g.
`python3 -m http.server`) rather than opening the files via a `file://` path.
