#!/usr/bin/env node
// Builds encrypted, password-gated pages from plaintext HTML sources.
// AES-256-GCM, key = PBKDF2-SHA256(password, salt, ITER). A published page holds only
// ciphertext plus a small Web Crypto decryptor — no plaintext, no libraries, no network.
//
//   usage:  SITE_PW='<password>' node build-encrypt.js <manifest.json> [outDir]
//
// Every page in a build shares one salt, so unlocking any one of them caches a derived key
// that unlocks the others for the rest of the tab (sessionStorage — gone when the tab closes,
// and invalidated automatically by the next build, which draws a new salt).
//
// The manifest and the plaintext sources live in the private source repo. This file carries
// no content of its own, which is why it is safe to publish alongside the ciphertext.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ITER = 600000;
const MANIFEST = process.argv[2];
const PW = process.env.SITE_PW;
if (!MANIFEST || !PW) {
  console.error("usage: SITE_PW='<password>' node build-encrypt.js <manifest.json> [outDir]");
  process.exit(1);
}

const manifest = JSON.parse(fs.readFileSync(MANIFEST, 'utf8'));
const srcRoot = path.resolve(path.dirname(MANIFEST), manifest.srcRoot || '.');
const outRoot = process.argv[3]
  ? path.resolve(process.argv[3])                                  // explicit: relative to cwd
  : path.resolve(path.dirname(MANIFEST), manifest.outRoot || '.'); // manifest: relative to itself

// One salt per build: shared so a single unlock covers the whole site.
const salt = crypto.randomBytes(16);
const key = crypto.pbkdf2Sync(PW, salt, ITER, 32, 'sha256');
const b64 = b => Buffer.from(b).toString('base64');

function encrypt(plaintext) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(plaintext, 'utf8'), c.final()]);
  const tag = c.getAuthTag();
  // Prove the blob round-trips in Node before we ship it.
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
  d.setAuthTag(tag);
  if (Buffer.concat([d.update(ct), d.final()]).toString('utf8') !== plaintext) {
    console.error('SELFTEST FAILED'); process.exit(2);
  }
  return { salt: b64(salt), iv: b64(iv), data: b64(Buffer.concat([ct, tag])), iter: ITER };
}

// Reuse the source's own favicon for the gate, so the lock screen and the app it guards
// look like the same thing. Falls back to no mark if the source doesn't set one.
function faviconOf(html) {
  const m = html.match(/<link[^>]+rel=["']icon["'][^>]*>/i);
  const h = m && m[0].match(/href=["']([^"']+)["']/i);
  return h ? h[1] : null;
}

const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;');

function gatePage({ title, heading, hint, icon, enc }) {
  return `<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>${esc(title)}</title>
${icon ? `<link rel="icon" href="${esc(icon)}">` : ''}
<style>
  :root{--bg:#f3f2ed; --surface:#fff; --ink:#1c3c47; --ink-2:#5f757f; --line:#dbdbd2;
    --accent:#2a5b6c; --bad:#a8362c;
    --sans:Hind,-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
    --font:termina,"Avenir Next",Futura,"Century Gothic",Verdana,sans-serif}
  html,body{margin:0;height:100%}
  body{background:var(--bg);color:var(--ink);font-family:var(--sans);-webkit-font-smoothing:antialiased;
    display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}
  .card{visibility:hidden;background:var(--surface);border:1px solid var(--line);border-radius:14px;
    padding:30px 28px;width:100%;max-width:330px;text-align:center;
    box-shadow:0 1px 2px rgba(28,60,71,.07),0 8px 24px rgba(28,60,71,.09)}
  .mark{width:42px;height:42px;margin:0 auto 12px;display:block}
  h1{font-family:var(--font);font-size:19px;font-weight:700;letter-spacing:-.01em;margin:0}
  p{color:var(--ink-2);font-size:13px;line-height:1.45;margin:7px 0 18px}
  input{width:100%;box-sizing:border-box;font-family:inherit;font-size:15px;padding:11px 13px;
    background:#faf9f5;color:var(--ink);border:1px solid var(--line);border-radius:10px;margin-bottom:10px}
  input:focus{outline:none;border-color:var(--accent);background:#fff}
  button{width:100%;font-family:inherit;font-size:15px;font-weight:700;cursor:pointer;color:#fff;
    background:var(--ink);border:0;border-radius:10px;padding:12px}
  button:hover{background:var(--accent)}
  button:disabled{opacity:.6;cursor:default}
  #err{color:var(--bad);font-size:12.5px;min-height:17px;margin-top:10px}
</style>
<div class="card" id="card">
  ${icon ? `<img class="mark" alt="" src="${esc(icon)}">` : ''}
  <h1>${esc(heading)}</h1>
  <p>${esc(hint)}</p>
  <input id="pw" type="password" autocomplete="current-password" spellcheck="false" aria-label="Password">
  <button id="go">Enter</button>
  <div id="err" role="status"></div>
</div>
<script>
const ENC=${JSON.stringify(enc)};
const SK='gate:'+ENC.salt;                       // new salt each build => stale keys ignored
const b64d=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const card=document.getElementById('card'), pw=document.getElementById('pw'),
      go=document.getElementById('go'), err=document.getElementById('err');

function show(msg){ card.style.visibility='visible'; if(msg) err.textContent=msg; pw.focus(); }

async function keyFromPassword(p){
  const base=await crypto.subtle.importKey('raw', new TextEncoder().encode(p), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2', salt:b64d(ENC.salt), iterations:ENC.iter, hash:'SHA-256'},
    base, {name:'AES-GCM', length:256}, true, ['decrypt']);
}
// document.open() is a no-op while a parser-inserted script is still on the stack, which
// would append the app *into* the gate instead of replacing it. Always swap after load.
function afterLoad(){
  return document.readyState==='complete' ? Promise.resolve()
    : new Promise(r=>window.addEventListener('load', r, {once:true}));
}
async function reveal(key){
  const pt=await crypto.subtle.decrypt({name:'AES-GCM', iv:b64d(ENC.iv)}, key, b64d(ENC.data));
  const html=new TextDecoder().decode(pt);
  // Cache the derived key (not the password) before we tear this document down.
  try{
    const raw=new Uint8Array(await crypto.subtle.exportKey('raw', key));
    sessionStorage.setItem(SK, btoa(String.fromCharCode.apply(null, raw)));
  }catch(e){}
  await afterLoad();
  document.open(); document.write(html); document.close();
}
async function submit(){
  if(!pw.value) return;
  err.textContent=''; go.disabled=true; go.textContent='Unlocking…';
  try{ await reveal(await keyFromPassword(pw.value)); }
  catch(e){ go.disabled=false; go.textContent='Enter'; pw.value=''; show('Wrong password'); }
}
go.addEventListener('click', submit);
pw.addEventListener('keydown', e=>{ if(e.key==='Enter') submit(); });

(async function(){
  if(!(window.crypto && crypto.subtle)){
    return show('This page needs a secure context — open it over https:// or localhost.');
  }
  const cached=sessionStorage.getItem(SK);          // already unlocked in this tab?
  if(!cached) return show();
  try{
    await reveal(await crypto.subtle.importKey('raw', b64d(cached), {name:'AES-GCM', length:256}, true, ['decrypt']));
  }catch(e){ sessionStorage.removeItem(SK); await afterLoad(); show(); }
})();
</script>
`;
}

let total = 0;
for (const page of manifest.pages) {
  const srcPath = path.resolve(srcRoot, page.src);
  const outPath = path.resolve(outRoot, page.out);
  const plaintext = fs.readFileSync(srcPath, 'utf8');
  const html = gatePage({
    title: page.title,
    heading: page.heading || page.title,
    hint: page.hint || 'Enter the password to view.',
    icon: page.icon || faviconOf(plaintext),
    enc: encrypt(plaintext),
  });
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, html);
  total += html.length;
  console.log('  %s  %s -> %s (%dk plaintext, %dk page)',
    'ok', page.src, page.out, Math.round(plaintext.length / 1024), Math.round(html.length / 1024));
}
console.log('built %d page(s), %dk total, %d PBKDF2 iterations, salt %s',
  manifest.pages.length, Math.round(total / 1024), ITER, b64(salt));
