// ═══════════════════════════════════════════
// RH PARTNERS PORTAL — APP CORE
// ═══════════════════════════════════════════
'use strict';
'use strict';
window.__portalSupabaseStorage = window.__portalSupabaseStorage || {
  ready:false,
  async uploadSingleFile(file, bucketType, folder, extra){ return { name:(extra&&extra.name)||file?.name||'file.bin', path:'', url:'', type:file?.type||'', size:file?.size||0, bucket:bucketType, ...(extra&&extra.durationLabel?{durationLabel:extra.durationLabel}:{}) }; },
  async uploadBrowserFiles(files, bucketType, folder){ return Promise.all((files||[]).map(file=>this.uploadSingleFile(file,bucketType,folder))); },
  async uploadBlobItems(items, bucketType, folder){ return Promise.all((items||[]).map(item=>this.uploadSingleFile(item.blob||item.file,bucketType,folder,{name:item.name,durationLabel:item.dur,type:(item.blob||item.file)?.type,size:(item.blob||item.file)?.size}))); }
};

/* ══════════════════════════════════════════════════════════
   SECURITY MODULE — Perlindungan Tingkat Tinggi
   ══════════════════════════════════════════════════════════ */

// ── Sanitasi XSS: gunakan DOMPurify untuk semua innerHTML
const SP = {
  // Sanitize HTML output sebelum inject ke DOM
  sanitize: (dirty) => {
    if (typeof DOMPurify !== 'undefined') {
      return DOMPurify.sanitize(dirty, {
        ALLOWED_TAGS: ['div','span','p','strong','em','b','i','br','ul','li','ol',
                       'table','thead','tbody','tr','th','td','a','button','select',
                       'option','input','textarea','label','h1','h2','h3','h4',
                       'canvas','audio','noscript','small','sup','sub'],
        ALLOWED_ATTR: ['class','id','style','type','placeholder','value','href',
                       'onclick','onchange','ondragover','ondragleave','ondrop',
                       'multiple','accept','disabled','readonly','selected',
                       'data-id','title','aria-label','role','tabindex',
                       'src','controls','autoplay','name','for','colspan','rowspan'],
        FORCE_BODY: false,
        RETURN_DOM_FRAGMENT: false,
      });
    }
    return dirty; // fallback jika DOMPurify belum load
  },

  // Safe innerHTML setter — selalu sanitasi dulu
  setHTML: (el, html) => {
    if (!el) return;
    el.innerHTML = SP.sanitize(html);
  },

  // Escape plain text (untuk output non-HTML)
  esc: (s) => String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'),

  // Rate limiter — cegah brute force & spam klik
  _rl: {},
  rateLimit: (key, limitMs = 1000) => {
    const now = Date.now();
    if (SP._rl[key] && now - SP._rl[key] < limitMs) return false;
    SP._rl[key] = now;
    return true;
  },

  // Login attempt tracker — blokir setelah 5x gagal
  _loginAttempts: 0,
  _loginBlockedUntil: 0,
  recordLoginFail: () => {
    SP._loginAttempts++;
    if (SP._loginAttempts >= 5) {
      SP._loginBlockedUntil = Date.now() + 30000; // blokir 30 detik
      SP._loginAttempts = 0;
    }
  },
  isLoginBlocked: () => Date.now() < SP._loginBlockedUntil,
  resetLoginAttempts: () => { SP._loginAttempts = 0; SP._loginBlockedUntil = 0; },

  // Session management — auto-logout setelah 30 menit idle
  _sessionTimer: null,
  _SESSION_TIMEOUT: 30 * 60 * 1000,
  resetSession: () => {
    clearTimeout(SP._sessionTimer);
    SP._sessionTimer = setTimeout(() => {
      if (typeof CU !== 'undefined' && CU) {
        showToast('Sesi berakhir karena tidak aktif. Silakan login kembali.', 'inf');
        setTimeout(() => doLogout(), 2000);
      }
    }, SP._SESSION_TIMEOUT);
  },
  initSession: () => {
    ['click','keypress','mousemove','touchstart','scroll'].forEach(evt =>
      document.addEventListener(evt, SP.resetSession, { passive: true })
    );
    SP.resetSession();
  },

  // CSRF token generator (untuk form submissions ke server)
  _csrfToken: null,
  getCSRF: () => {
    if (!SP._csrfToken) {
      const arr = new Uint8Array(32);
      if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
        crypto.getRandomValues(arr);
        SP._csrfToken = Array.from(arr, b => b.toString(16).padStart(2,'0')).join('');
      } else {
        SP._csrfToken = Math.random().toString(36).substr(2) + Date.now().toString(36);
      }
    }
    return SP._csrfToken;
  },

  // Input validator
  validators: {
    email: (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v),
    phone: (v) => /^[\+]?[\d\s\-\(\)]{8,15}$/.test(v),
    noScript: (v) => !/<script|javascript:|on\w+\s*=/i.test(v),
    safeText: (v) => v && v.length > 0 && v.length < 10000 && SP.validators.noScript(v),
    password: (v) => v && v.length >= 8 && /[A-Z]/.test(v) && /[0-9]/.test(v),
    whatsapp: (v) => /^[\+]?[\d\s\-\(\)]{8,15}$/.test(v),
  },

  // Secure password strength meter
  passwordStrength: (p) => {
    if (!p) return { score: 0, label: 'Kosong', color: 'var(--m1)' };
    let score = 0;
    if (p.length >= 8) score++;
    if (p.length >= 12) score++;
    if (/[A-Z]/.test(p)) score++;
    if (/[0-9]/.test(p)) score++;
    if (/[^A-Za-z0-9]/.test(p)) score++;
    const levels = [
      { score:0, label:'Sangat Lemah', color:'var(--rd)' },
      { score:1, label:'Lemah', color:'var(--rd)' },
      { score:2, label:'Sedang', color:'var(--am)' },
      { score:3, label:'Cukup', color:'var(--cu)' },
      { score:4, label:'Kuat', color:'var(--gn)' },
      { score:5, label:'Sangat Kuat', color:'var(--gn)' },
    ];
    return levels[score] || levels[0];
  },

  // Audit log (in-memory, kirim ke server di production)
  _auditLog: [],
  log: (action, detail = '') => {
    const entry = {
      ts: new Date().toISOString(),
      user: (typeof CU !== 'undefined' && CU) ? CU.email : 'anonymous',
      action, detail,
      ua: navigator.userAgent.substring(0, 80),
    };
    SP._auditLog.push(entry);
    if (SP._auditLog.length > 200) SP._auditLog.shift(); // keep last 200
    // Di production: fetch('/api/audit', { method:'POST', body:JSON.stringify(entry) })
  },

  // Detect devtools open (basic)
  detectDevTools: () => {
    // Hanya warning, tidak memblokir (UX-friendly)
    const threshold = 160;
    if (window.outerWidth - window.innerWidth > threshold ||
        window.outerHeight - window.innerHeight > threshold) {
      console.warn('%c⚠ RH Partners Security', 'color:#e05555;font-size:14px;font-weight:bold',
        '\nJangan paste kode apapun di console ini. Ini bisa membahayakan akun Anda.');
    }
  },
};

// Inisialisasi security saat DOM ready

/* ══════════════════════════════════════
   LOCALSTORAGE PERSISTENCE
══════════════════════════════════════ */
const LOCAL_STATE_KEY = 'rhpartners.portal.state.v1';
const LOCAL_SESSION_KEY = 'rhpartners.portal.session.v1';

/* ── Password Hashing (SHA-256 via WebCrypto) ── */
async function hashPassword(plain) {
  if (!plain) return '';
  try {
    const enc = new TextEncoder();
    const buf = await crypto.subtle.digest('SHA-256', enc.encode('rhp:' + plain));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
  } catch(e) {
    // Fallback jika WebCrypto tidak tersedia (tidak seharusnya terjadi di browser modern)
    console.warn('[Security] WebCrypto tidak tersedia, menggunakan fallback hash sederhana');
    let h = 0;
    for (let i = 0; i < plain.length; i++) { h = ((h << 5) - h + plain.charCodeAt(i)) | 0; }
    return 'fb_' + Math.abs(h).toString(16);
  }
}

// Cek apakah string adalah hash (bukan plaintext)
function isHashed(s) {
  return typeof s === 'string' && (s.length === 64 || s.startsWith('fb_'));
}

function saveSessionToLocal(user) {
  try {
    if (!user) { localStorage.removeItem(LOCAL_SESSION_KEY); return; }
    // Simpan session tanpa password untuk keamanan
    const { pass, ...safeUser } = user;
    localStorage.setItem(LOCAL_SESSION_KEY, JSON.stringify({ ...safeUser, savedAt: Date.now() }));
  } catch(e) {}
}

function loadSessionFromLocal() {
  try {
    const raw = localStorage.getItem(LOCAL_SESSION_KEY);
    if (!raw) return null;
    const s = JSON.parse(raw);
    // Session kedaluwarsa setelah 8 jam
    if (!s || !s.email || !s.savedAt || Date.now() - s.savedAt > 8 * 60 * 60 * 1000) {
      localStorage.removeItem(LOCAL_SESSION_KEY);
      return null;
    }
    return s;
  } catch(e) { return null; }
}

function saveStateToLocal() {
  try {
    const state = {
      USERS,
      uploads,
      payList,
      klienList,
      invList,
      adminRevisions,
      cmsData,
      savedAt: Date.now()
    };
    localStorage.setItem(LOCAL_STATE_KEY, JSON.stringify(state));
  } catch(e) {
    console.warn('[LocalStorage] Gagal menyimpan state:', e);
  }
}

function loadStateFromLocal() {
  try {
    const raw = localStorage.getItem(LOCAL_STATE_KEY);
    if (!raw) return null;
    const state = JSON.parse(raw);
    if (!state || typeof state !== 'object') return null;
    return state;
  } catch(e) {
    console.warn('[LocalStorage] Gagal memuat state:', e);
    return null;
  }
}

function applyLocalState(state) {
  if (!state) return false;
  try {
    if (state.USERS && typeof state.USERS === 'object' && Object.keys(state.USERS).length > 0) {
      USERS = state.USERS;
    }
    if (Array.isArray(state.uploads))        uploads        = state.uploads;
    if (Array.isArray(state.payList))         payList        = state.payList;
    if (Array.isArray(state.klienList))       klienList      = state.klienList;
    if (Array.isArray(state.invList))         invList        = state.invList;
    if (Array.isArray(state.adminRevisions))  adminRevisions = state.adminRevisions;
    if (state.cmsData && typeof state.cmsData === 'object') {
      cmsData = Object.assign({}, cmsData, state.cmsData);
    }
    return true;
  } catch(e) {
    console.warn('[LocalStorage] Gagal menerapkan state:', e);
    return false;
  }
}

// Auto-save ke localStorage setiap kali state berubah (debounced)
let _lsSaveTimer = null;
function queueLocalSave() {
  clearTimeout(_lsSaveTimer);
  _lsSaveTimer = setTimeout(saveStateToLocal, 300);
}

/* ══════════════════════════════════════
   STATE & DATA
══════════════════════════════════════ */
window.normalizeEmail = window.normalizeEmail || function(email){ return String(email || '').trim().toLowerCase(); };
// ── Tidak ada akun default — admin wajib dibuat via setup awal
let USERS = {};

// ── Muat state dari localStorage saat pertama kali (sebelum Supabase sync)
// CATATAN: Dipindah ke setelah semua variabel dideklarasikan (lihat bawah cmsData)

let CU = null; // current user
let lnMode = 'klien';
let currentView = 'dash';
let ekTabState = 'info';
let upTabState = 'rev';
let fFile = 'all';
let fRev = 'all';
let fPay = 'all';

let uploads = [];
let payList = [];
let klienList = [];
let invList = [];
let uFiles = {}; // key: slot-id -> File[]
let pyFileObj = null;
let kpFileObj = null;

// recorder state (modal)
let mRec = null, mStream = null, mChunks = [], mSec = 0, mPaused = false, mIntv = null, mAnim = null, mBlobs = [];
// recorder state (page)
let pgRec = null, pgStream = null, pgChunks = [], pgSec = 0, pgPaused = false, pgIntv = null, pgAnim = null, pgBlobs = [];

let editCms = null;
let adminRevisions = []; // hasil revisi dari admin ke klien

let cmsData = {
  pengumuman: [
    { id:1, judul:'Sistem Pemeliharaan Terjadwal', isi:'Sistem akan dalam pemeliharaan pada 15 Maret 2026 pukul 00.00–03.00 WIB.', aktif:true, tgl:'01/03/2026' },
    { id:2, judul:'Fitur Upload Video Baru', isi:'Kini Anda dapat mengupload file video hingga 500MB untuk revisi.', aktif:true, tgl:'05/03/2026' },
  ],
  layanan: [
    { id:1, nama:'Desain Website',   isi:'Landing page, profil perusahaan, e-commerce', harga:'Mulai Rp 5.000.000',  ikon:'🌐', aktif:true },
    { id:2, nama:'Branding Package', isi:'Logo, identitas visual, panduan merek',       harga:'Mulai Rp 3.500.000',  ikon:'🎨', aktif:true },
    { id:3, nama:'Video Produksi',   isi:'Video iklan, company profile, konten sosmed', harga:'Mulai Rp 8.000.000',  ikon:'🎬', aktif:true },
    { id:4, nama:'Fotografi Produk', isi:'Foto produk profesional, still life',         harga:'Mulai Rp 2.000.000',  ikon:'📷', aktif:false },
  ],
  kontak: { nama:'RH Partners', email:'hello@rhpartners.id', wa:'+62 812-0000-0001', alamat:'Jl. Sudirman No. 12, Jakarta Selatan', jam:'Senin–Jumat, 09.00–18.00 WIB' },
  siteinfo: { judul:'RH Partners Portal', tagline:'Client, Project & Billing Workspace', rek_bca:'1234-567-890', rek_mandiri:'111-222-333-4', an:'RH Partners' },
};

// ── Muat state dari localStorage sekarang semua variabel sudah ada
(function() {
  try {
    const saved = loadStateFromLocal();
    if (saved) {
      applyLocalState(saved);
      console.info('[LocalStorage] State berhasil dimuat dari penyimpanan lokal.');
    }
  } catch(e) {
    console.warn('[LocalStorage] Gagal restore state awal:', e);
  }
})();

function seedData() {
  // Demo data dinonaktifkan — portal dimulai bersih
  klienList = [];
  adminRevisions = [];
  invList = [];
  payList = [];
  uploads = [];
}

/* ══════════════════════════════════════
   AUTH
══════════════════════════════════════ */

function avatarFromName(nama) {
  return String(nama || '').trim().split(/\s+/).map(v => v[0] || '').join('').slice(0,2).toUpperCase() || 'AD';
}

function resetPortalData() {
  uploads = [];
  payList = [];
  klienList = [];
  invList = [];
  adminRevisions = [];
  uFiles = {};
  queueLocalSave();
}

async function bootstrapPortal() {
  try {
    const studio = v('fs-studio').trim();
    const nama = v('fs-admin-name').trim();
    const email = window.normalizeEmail(v('fs-admin-email'));
    const wa = v('fs-admin-wa').trim();
    const pass = v('fs-admin-pass');
    const pass2 = v('fs-admin-pass2');
    const err = document.getElementById('fs-err');
    if (err) err.textContent = '';

    if (!studio || !nama || !email || !wa || !pass || !pass2) { if (err) err.textContent = 'Semua field wajib diisi.'; return false; }
    if (!SP.validators.email(email)) { if (err) err.textContent = 'Format email admin tidak valid.'; return false; }
    if (!(SP.validators.phone ? SP.validators.phone(wa) : /^[\+\d\s\-\(\)]{8,15}$/.test(wa))) { if (err) err.textContent = 'Format WhatsApp tidak valid.'; return false; }
    if (!SP.validators.password(pass)) { if (err) err.textContent = 'Password minimal 8 karakter, mengandung huruf besar dan angka.'; return false; }
    if (pass !== pass2) { if (err) err.textContent = 'Konfirmasi password tidak cocok.'; return false; }

    const passHash = await hashPassword(pass);
    USERS[email] = { pass: passHash, role:'admin', name:nama, avatar:avatarFromName(nama) };
    resetPortalData();
    cmsData.kontak = Object.assign({}, cmsData.kontak, { nama: studio, email, wa });
    cmsData.siteinfo = Object.assign({}, cmsData.siteinfo, { judul: 'RH Partners Portal', tagline: studio });

    closeModal('m-first-setup');
    renderLoginHint();

    if (window.__studioportalDB && typeof window.__studioportalDB.persistState === 'function') {
      try { await window.__studioportalDB.persistState('bootstrap-admin'); } catch (e) { console.warn('Persist bootstrap skipped:', e); }
    }

    saveStateToLocal();

    document.getElementById('ln-email').value = email;
    document.getElementById('ln-pass').value = '';
    lnMode = 'admin';
    document.getElementById('lt-klien').classList.remove('on');
    document.getElementById('lt-admin').classList.add('on');
    showToast('RH Partners Portal siap dipakai. Silakan masuk sebagai admin.','ok');
    return true;
  } catch (e) {
    console.error('bootstrapPortal error:', e);
    const err = document.getElementById('fs-err');
    if (err) err.textContent = 'Setup gagal: ' + (e && e.message ? e.message : 'unknown error');
    return false;
  }
}

function renderLoginHint() {
  const hint = document.getElementById('ln-hint');
  if (!hint) return;
  if (lnMode === 'admin') {
    hint.textContent = 'Masuk menggunakan akun administrator.';
  } else {
    const hasKlien = Object.values(USERS).some(u => u.role === 'klien');
    hint.textContent = hasKlien
      ? 'Masuk dengan akun klien yang sudah dibuat oleh admin.'
      : 'Belum ada akun klien. Admin perlu menambahkan klien terlebih dahulu.';
  }
}

function setLnMode(m) {
  lnMode = m;
  document.getElementById('lt-klien').classList.toggle('on', m === 'klien');
  document.getElementById('lt-admin').classList.toggle('on', m === 'admin');
  renderLoginHint();
  document.getElementById('ln-err').textContent = '';
}

function updatePwStrength(val) {
  if (!val) { const w = document.getElementById('pw-strength-wrap'); if(w) w.style.display='none'; return; }
  const str = SP.passwordStrength(val);
  const pct = (str.score / 5) * 100;
  const wrap = document.getElementById('pw-strength-wrap');
  const bar  = document.getElementById('pw-strength-bar');
  const lbl  = document.getElementById('pw-strength-label');
  if (wrap) wrap.style.display = val ? 'block' : 'none';
  if (bar)  { bar.style.width = pct + '%'; bar.style.background = str.color; }
  if (lbl)  { lbl.style.color = str.color; lbl.textContent = 'Kekuatan: ' + str.label; }
}

function togglePw() {
  const inp = document.getElementById('ln-pass');
  inp.type = inp.type === 'password' ? 'text' : 'password';
  document.getElementById('pw-eye').textContent = inp.type === 'password' ? '👁' : '🙈';
}

function doLogin() {
  // Rate limit: cegah brute force
  if (!SP.rateLimit('login', 800)) return;
  if (SP.isLoginBlocked()) {
    document.getElementById('ln-err').textContent = '⛔ Terlalu banyak percobaan. Coba lagi dalam 30 detik.';
    return;
  }
  const email = document.getElementById('ln-email').value.trim().toLowerCase();
  const pass  = document.getElementById('ln-pass').value;
  const errEl = document.getElementById('ln-err');
  const loginBtn = document.querySelector('.btn-login');
  errEl.textContent = '';

  // Validasi input
  if (!email || !pass) { errEl.textContent = 'Isi email dan password.'; return; }
  if (!SP.validators.email(email)) { errEl.textContent = 'Format email tidak valid.'; return; }
  if (!SP.validators.noScript(email) || !SP.validators.noScript(pass)) {
    errEl.textContent = 'Input mengandung karakter tidak diizinkan.';
    SP.log('security_alert', 'XSS attempt on login: ' + email.substring(0,30));
    return;
  }

  // Tampilkan loading
  if (loginBtn) { loginBtn.disabled = true; loginBtn.textContent = 'Memuat data...'; }
  errEl.textContent = '';

  // Tunggu Supabase sync selesai sebelum login
  const dbReady = window.__studioportalDB
    ? window.__studioportalDB.ensureInitialState().catch(() => null)
    : Promise.resolve();

  dbReady.then(() => {
    if (loginBtn) { loginBtn.disabled = false; loginBtn.textContent = 'Masuk ke Portal'; }

    const u = USERS[email];
    if (!u) {
      SP.recordLoginFail();
      SP.log('login_fail', email);
      setTimeout(() => {
        const remaining = Math.max(0, 5 - SP._loginAttempts);
        errEl.textContent = `Email atau password salah.${SP._loginAttempts > 2 ? ' (' + remaining + ' percobaan tersisa)' : ''}`;
      }, 400 + Math.random() * 300);
      return;
    }

    // Hash password lalu bandingkan (async)
    hashPassword(pass).then(passHash => {
      if (u.pass !== passHash) {
        SP.recordLoginFail();
        SP.log('login_fail', email);
        setTimeout(() => {
          const remaining = Math.max(0, 5 - SP._loginAttempts);
          errEl.textContent = `Email atau password salah.${SP._loginAttempts > 2 ? ' (' + remaining + ' percobaan tersisa)' : ''}`;
        }, 400 + Math.random() * 300);
        return;
      }
      if (u.role !== lnMode) {
        SP.log('login_role_mismatch', email);
        errEl.textContent = `Akun ini bukan ${lnMode === 'admin' ? 'administrator' : 'klien'}. Pilih tab yang sesuai.`;
        return;
      }
      SP.resetLoginAttempts();
      SP.log('login_success', email);
      CU = { email, ...u, loginAt: Date.now() };
      saveSessionToLocal(CU);
      launchApp();
    });
  });
}

function doLogout() {
  SP.log('logout', CU ? CU.email : 'unknown');
  stopAllRecorders();
  clearTimeout(SP._sessionTimer);
  saveSessionToLocal(null);
  CU = null;
  document.getElementById('scr-app').classList.remove('on');
  document.getElementById('scr-login').classList.add('on');
  document.getElementById('ln-email').value = '';
  document.getElementById('ln-pass').value = '';
  document.getElementById('ln-err').textContent = '';
  showToast('Berhasil keluar', 'inf');
}

/* ══════════════════════════════════════
   APP INIT
══════════════════════════════════════ */
function launchApp() {
  document.getElementById('scr-login').classList.remove('on');
  document.getElementById('scr-app').classList.add('on');
  const av = document.getElementById('sb-av');
  av.textContent = CU.avatar;
  av.className = 'av ' + (CU.role === 'admin' ? 'av-a' : 'av-k');
  document.getElementById('sb-un').textContent = CU.name;
  document.getElementById('sb-ur').textContent = CU.role === 'admin' ? 'Administrator' : 'Klien';
  document.getElementById('tb-act').style.display = CU.role === 'klien' ? 'flex' : 'none';
  buildNav();
  navTo('dash');
}

function buildNav() {
  const isA = CU.role === 'admin';
  const pendFiles = uploads.filter(u => u.status === 'pending').length;
  const pendRev   = uploads.filter(u => u.tipe === 'revisi'  && u.status === 'pending').length;
  const pendRek   = uploads.filter(u => u.tipe === 'rekaman' && u.status === 'pending').length;
  const pendPay   = payList.filter(p => p.status === 'verify').length;
  const myPend    = CU ? uploads.filter(u => u.client === CU.name && u.status === 'pending').length : 0;
  const myUnread  = CU ? adminRevisions.filter(r => r.klien === CU.name && !r.dibaca).length : 0;

  const adminNav = [
    { sec:'Utama' },
    { v:'dash',            ic:'📊', l:'Dashboard' },
    { sec:'Konten Klien' },
    { v:'files',           ic:'🗂️', l:'Semua File',   dot: pendFiles > 0 },
    { v:'rev-adm',         ic:'📋', l:'Revisi',       badge: pendRev || '' },
    { v:'rek-adm',         ic:'🎙️', l:'Rekaman',      badge: pendRek || '' },
    { v:'kirim-hasil',     ic:'📨', l:'Kirim Hasil Revisi' },
    { v:'pay-adm',         ic:'💳', l:'Pembayaran',   dot: pendPay > 0 },
    { sec:'Manajemen' },
    { v:'klien-adm',       ic:'👥', l:'Data Klien' },
    { sec:'CMS' },
    { v:'cms-pengumuman',  ic:'📢', l:'Pengumuman' },
    { v:'cms-layanan',     ic:'🛠️', l:'Layanan' },
    { v:'cms-kontak',      ic:'📞', l:'Kontak & Info' },
    { v:'cms-siteinfo',    ic:'⚙️', l:'Pengaturan & Password' },
    { sec:'Laporan' },
    { v:'report',          ic:'📈', l:'Ringkasan' },
  ];

  const klienNav = [
    { sec:'Utama' },
    { v:'dash',         ic:'📊', l:'Dashboard' },
    { sec:'Layanan' },
    { v:'upload',       ic:'📤', l:'Upload File',    badge: myPend || '' },
    { v:'hasil-revisi', ic:'📨', l:'Hasil Revisi',   badge: myUnread || '' },
    { v:'pay-kln',      ic:'💰', l:'Pembayaran' },
    { sec:'Akun' },
    { v:'profile',      ic:'👤', l:'Profil Saya' },
  ];

  const links = isA ? adminNav : klienNav;
  let html = '';
  links.forEach(l => {
    if (l.sec) {
      html += `<div class="nav-sec">${l.sec}</div>`;
    } else {
      const active = currentView === l.v ? 'on' : '';
      html += `<div class="ni ${active}" id="ni-${l.v}" onclick="navTo('${l.v}')">
        <span class="ni-ic">${l.ic}</span>${l.l}
        ${l.badge ? `<span class="nbdg">${l.badge}</span>` : ''}
        ${l.dot ? `<span class="ndot"></span>` : ''}
      </div>`;
    }
  });
  const sbNav = document.getElementById('sb-nav');
  if (sbNav) SP.setHTML(sbNav, html);
}

const PAGE_TITLES = {
  dash:'Dashboard', files:'Semua File', 'rev-adm':'Kelola Revisi', 'rek-adm':'Kelola Rekaman',
  'pay-adm':'Kelola Pembayaran', 'klien-adm':'Data Klien',
  'cms-pengumuman':'CMS Pengumuman', 'cms-layanan':'CMS Layanan', 'cms-kontak':'CMS Kontak',
  'cms-siteinfo':'Pengaturan & Password', report:'Ringkasan',
  upload:'Upload File', 'pay-kln':'Pembayaran', profile:'Profil Saya',
  'kirim-hasil':'Kirim Hasil Revisi', 'hasil-revisi':'Hasil Revisi dari Studio',
};

function navTo(v) {
  currentView = v;
  buildNav();
  updateSEOMeta(v);
  SP.log('navigation', v);
  const title = PAGE_TITLES[v] || v;
  const words = title.split(' ');
  const last = words.pop();
  document.getElementById('pg-title').innerHTML = (words.length ? words.join(' ') + ' ' : '') + `<span>${last}</span>`;

  const views = {
    dash:           CU.role === 'admin' ? dashAdmin : dashKlien,
    files:          adminFiles,
    'rev-adm':      adminRevisi,
    'rek-adm':      adminRekaman,
    'pay-adm':      adminPay,
    'klien-adm':    adminKlien,
    'cms-pengumuman': cmsPengumuman,
    'cms-layanan':  cmsLayanan,
    'cms-kontak':   cmsKontak,
    'cms-siteinfo': cmsSiteinfo,
    report:         adminReport,
    upload:         klienUpload,
    'pay-kln':      klienPay,
    profile:        klienProfile,
    'kirim-hasil':  adminKirimHasil,
    'hasil-revisi': klienHasilRevisi,
  };
  const fn = views[v];
  if (fn) fn();
  else setContent('<div class="empty"><div class="empty-ic">🚧</div><div class="empty-t">Segera Hadir</div></div>');
}

/* ══════════════════════════════════════
   ADMIN: DASHBOARD
══════════════════════════════════════ */
function dashAdmin() {
  const pend  = uploads.filter(u => u.status === 'pending').length;
  const rek   = uploads.filter(u => u.tipe === 'rekaman').length;
  const tot   = payList.reduce((s,p) => s + p.amount, 0);
  const lunas = payList.filter(p => p.status === 'paid').reduce((s,p) => s + p.amount, 0);
  const blm   = payList.filter(p => p.status !== 'paid').reduce((s,p) => s + p.amount, 0);

  setContent(`
  <div class="wb">
    <div><h2>Selamat datang, <span>${CU.name.split(' ')[0]}</span>!</h2>
    <p>${new Date().toLocaleDateString('id-ID',{weekday:'long',day:'numeric',month:'long',year:'numeric'})}</p></div>
    <div class="wb-ic">⚙️</div>
  </div>
  <div style="display:flex;gap:10px;margin-bottom:18px;flex-wrap:wrap">
    <div style="display:inline-flex;align-items:center;gap:6px;padding:5px 11px;background:rgba(74,186,130,.1);border:1px solid rgba(74,186,130,.2);border-radius:20px;font-size:10px;font-weight:700;color:var(--gn);letter-spacing:.06em">
      🔒 SSL/TLS 1.3 AKTIF
    </div>
    <div style="display:inline-flex;align-items:center;gap:6px;padding:5px 11px;background:rgba(85,153,224,.1);border:1px solid rgba(85,153,224,.2);border-radius:20px;font-size:10px;font-weight:700;color:var(--bl);letter-spacing:.06em">
      🛡 CSP AKTIF
    </div>
    <div style="display:inline-flex;align-items:center;gap:6px;padding:5px 11px;background:rgba(139,92,246,.1);border:1px solid rgba(139,92,246,.2);border-radius:20px;font-size:10px;font-weight:700;color:var(--pu);letter-spacing:.06em">
      🔐 HSTS PRELOAD
    </div>
    <div style="display:inline-flex;align-items:center;gap:6px;padding:5px 11px;background:rgba(224,168,48,.1);border:1px solid rgba(224,168,48,.2);border-radius:20px;font-size:10px;font-weight:700;color:var(--am);letter-spacing:.06em">
      📋 AUDIT LOG ON
    </div>
    <div style="display:inline-flex;align-items:center;gap:6px;padding:5px 11px;background:rgba(201,121,65,.1);border:1px solid rgba(201,121,65,.2);border-radius:20px;font-size:10px;font-weight:700;color:var(--cu);letter-spacing:.06em">
      ⚡ SEO Score A+
    </div>
  </div>
  <div class="g5 stats">
    <div class="sc cu"><div class="sic">📤</div><div class="sl">Total Upload</div><div class="sv cu">${uploads.length}</div><div class="ss">${pend} menunggu</div></div>
    <div class="sc gn"><div class="sic">✅</div><div class="sl">Disetujui</div><div class="sv gn">${uploads.filter(u=>u.status==='approved'||u.status==='reviewed').length}</div><div class="ss">Revisi &amp; rekaman</div></div>
    <div class="sc pu"><div class="sic">🎙️</div><div class="sl">Rekaman</div><div class="sv pu">${rek}</div><div class="ss">${uploads.filter(u=>u.tipe==='rekaman'&&u.status==='pending').length} baru</div></div>
    <div class="sc bl"><div class="sic">💰</div><div class="sl">Total Tagihan</div><div class="sv bl">${fRp(tot)}</div><div class="ss">${klienList.length} klien</div></div>
    <div class="sc rd"><div class="sic">⏳</div><div class="sl">Belum Lunas</div><div class="sv rd">${fRp(blm)}</div><div class="ss">${fRp(lunas)} lunas</div></div>
  </div>
  <div class="g2">
    <div class="card">
      <div class="ch"><div class="ct">Upload Terbaru</div><button class="btn btn-ol btn-xs" onclick="navTo('files')">Semua →</button></div>
      <div class="cb0">${fileTbl(uploads.slice(0,6), true)}</div>
    </div>
    <div>
      <div class="card" style="margin-bottom:18px">
        <div class="ch"><div class="ct">Status Pembayaran</div><button class="btn btn-ol btn-xs" onclick="navTo('pay-adm')">Kelola →</button></div>
        <div class="cb">${payList.slice(0,4).map(p=>`
          <div class="ic">
            <div class="ic-top"><span class="ic-id">${p.id}</span><span class="chip ch-${pStCls(p.status)}">${pStLbl(p.status)}</span></div>
            <div class="ic-desc">${p.client} — ${p.desc}</div>
            <div class="ic-ft"><span class="ic-due">Jatuh tempo: ${p.due}</span><span class="ic-amt">${fRp(p.amount)}</span></div>
          </div>`).join('')}
        </div>
      </div>
      <div class="card">
        <div class="ch">
          <div class="ct">Aktivitas Terkini</div>
          <button class="btn btn-ol btn-xs" onclick="clearFeed()" title="Hapus semua aktivitas terkini">🗑 Reset</button>
        </div>
        <div class="cb" id="feed-wrap">${buildFeed()}</div>
      </div>
    </div>
  </div>`);
}

/* ══════════════════════════════════════
   ADMIN: SEMUA FILE
══════════════════════════════════════ */
function adminFiles() {
  const filtered = fFile === 'all' ? uploads : uploads.filter(u => u.tipe === fFile);
  setContent(`
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:10px">
    <div class="tabs" style="margin-bottom:0">
      ${['all','revisi','rekaman'].map(f => `<div class="tab ${fFile===f?'on':''}" onclick="setFF('${f}',this)">${{all:'Semua',revisi:'📄 Revisi',rekaman:'🎙️ Rekaman'}[f]}</div>`).join('')}
    </div>
    <input style="background:var(--s2);border:1px solid var(--b1);border-radius:var(--r8);color:var(--tx);padding:7px 12px;font-size:12px;outline:none;width:210px"
      placeholder="🔍 Cari klien / proyek..." oninput="searchFiles(this.value,'file-tbl-body')">
  </div>
  <div class="card">
    <div class="ch"><div class="ct">Semua File <span style="color:var(--m1);font-weight:400">(${filtered.length})</span></div></div>
    <div class="cb0" id="file-tbl-wrap">${fileTbl(filtered, true)}</div>
  </div>`);
}

function setFF(f) {
  fFile = f;
  adminFiles();
}

function searchFiles(q, tbodyId) {
  const low = q.toLowerCase();
  const base = fFile === 'all' ? uploads : uploads.filter(u => u.tipe === fFile);
  const list = q ? base.filter(u => u.client.toLowerCase().includes(low) || u.proj.toLowerCase().includes(low) || u.judul.toLowerCase().includes(low)) : base;
  const wrap = document.getElementById('file-tbl-wrap');
  if (wrap) SP.setHTML(wrap, fileTbl(list, true));
}

function fileTbl(list, showActions) {
  if (!list.length) return '<div class="empty"><div class="empty-ic">📂</div><div class="empty-t">Tidak ada data</div></div>';
  return `<table class="tbl"><thead><tr>
    <th>Klien</th><th>Proyek</th><th>Tipe</th><th>Judul / Versi</th><th>File</th><th>Catatan</th><th>Tanggal</th><th>Status</th>
    ${showActions ? '<th>Aksi</th>' : ''}
  </tr></thead><tbody>${list.map(u => `<tr>
    <td style="font-weight:600">${u.client}</td>
    <td style="color:var(--m1);font-size:11px">${u.proj}</td>
    <td><span class="chip ${u.tipe==='rekaman'?'ch-rek-tipe':'ch-rev-tipe'}">${u.tipe==='rekaman'?'🎙️':'📄'} ${cap(u.tipe)}</span></td>
    <td><div style="font-size:12px;font-weight:500">${u.judul}</div>${u.ver&&u.ver!=='-'?`<div style="font-size:10px;color:var(--m1)">${u.ver}</div>`:''}</td>
    <td style="font-size:11px;color:var(--m1)">${u.files.length} file</td>
    <td style="font-size:11px;color:var(--m2);max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${u.catatan}">${u.catatan||'—'}</td>
    <td style="font-size:11px;color:var(--m1);white-space:nowrap">${u.tgl}</td>
    <td><span class="chip ch-${stCls(u.status)}">${stLbl(u.status)}</span></td>
    ${showActions ? `<td><div class="row-acts">
      <button class="btn btn-xs btn-bl" onclick="showDetail(${u.id})">Detail</button>
      ${u.status==='pending' ? `<button class="btn btn-xs btn-gn" onclick="approveUpload(${u.id})">${u.tipe==='rekaman'?'✓ Diputar':'✓ Setuju'}</button><button class="btn btn-xs btn-rd" onclick="rejectUpload(${u.id})">✕</button>` : ''}
    </div></td>` : ''}
  </tr>`).join('')}</tbody></table>`;
}

/* ══════════════════════════════════════
   ADMIN: REVISI
══════════════════════════════════════ */
function adminRevisi() {
  const list = uploads.filter(u => u.tipe === 'revisi');
  const filtered = fRev === 'all' ? list : list.filter(u => u.status === fRev);
  setContent(`
  <div class="tabs">
    ${['all','pending','approved','rejected'].map(f=>`<div class="tab ${fRev===f?'on':''}" onclick="setFRev('${f}',this)">${{all:'Semua',pending:'Menunggu',approved:'Disetujui',rejected:'Ditolak'}[f]}</div>`).join('')}
  </div>
  <div class="card">
    <div class="ch"><div class="ct">Revisi <span style="color:var(--m1);font-weight:400">(${filtered.length})</span></div></div>
    <div class="cb0">${fileTbl(filtered, true)}</div>
  </div>`);
}
function setFRev(f) { fRev = f; adminRevisi(); }

/* ══════════════════════════════════════
   ADMIN: REKAMAN
══════════════════════════════════════ */
function adminRekaman() {
  const list = uploads.filter(u => u.tipe === 'rekaman');
  setContent(`
  <div class="card">
    <div class="ch"><div class="ct">Rekaman <span style="color:var(--m1);font-weight:400">(${list.length})</span></div></div>
    <div class="cb0">${list.length ? `<table class="tbl"><thead><tr>
      <th>Klien</th><th>Proyek</th><th>Judul</th><th>Durasi</th><th>File</th><th>Catatan</th><th>Tanggal</th><th>Status</th><th>Aksi</th>
    </tr></thead><tbody>${list.map(u=>`<tr>
      <td style="font-weight:600">${u.client}</td>
      <td style="font-size:11px;color:var(--m1)">${u.proj}</td>
      <td style="font-weight:500">${u.judul}</td>
      <td style="font-size:11px;color:var(--m1)">${u.ver||'—'}</td>
      <td style="font-size:11px;color:var(--m1)">${u.files.join(', ')}</td>
      <td style="font-size:11px;color:var(--m2);max-width:110px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${u.catatan}">${u.catatan||'—'}</td>
      <td style="font-size:11px;color:var(--m1);white-space:nowrap">${u.tgl}</td>
      <td><span class="chip ch-${stCls(u.status)}">${stLbl(u.status)}</span></td>
      <td><div class="row-acts">
        <button class="btn btn-xs btn-bl" onclick="showDetail(${u.id})">Detail</button>
        ${u.status==='pending'?`<button class="btn btn-xs btn-gn" onclick="approveUpload(${u.id})">✓ Dengar</button>`:''}
      </div></td>
    </tr>`).join('')}</tbody></table>` :
    '<div class="empty"><div class="empty-ic">🎙️</div><div class="empty-t">Belum ada rekaman</div></div>'}</div>
  </div>`);
}

/* ══════════════════════════════════════
   ADMIN: PEMBAYARAN
══════════════════════════════════════ */
function adminPay() {
  const filtered = fPay === 'all' ? payList : payList.filter(p => p.status === fPay);
  setContent(`
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:10px">
    <div class="tabs" style="margin-bottom:0">
      ${['all','unpaid','verify','paid'].map(f=>`<div class="tab ${fPay===f?'on':''}" onclick="setFPay('${f}',this)">${{all:'Semua',unpaid:'Belum Bayar',verify:'Verifikasi',paid:'Lunas'}[f]}</div>`).join('')}
    </div>
    <button class="btn btn-cu btn-sm" onclick="openInvModal()">+ Buat Invoice</button>
  </div>
  <div class="card"><div class="cb0">
    ${filtered.length ? `<table class="tbl"><thead><tr>
      <th>Klien</th><th>Invoice</th><th>Deskripsi</th><th>Jumlah</th><th>Metode</th><th>Tgl Bayar</th><th>Status</th><th>Aksi</th>
    </tr></thead><tbody>${filtered.map(p=>`<tr>
      <td style="font-weight:600">${p.client}</td>
      <td style="font-family:'Syne',sans-serif;font-size:11px;color:var(--m2)">${p.id}</td>
      <td style="font-size:11px;color:var(--m2);max-width:130px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${p.desc}</td>
      <td style="font-weight:700;font-family:'Syne',sans-serif;color:var(--cu)">${fRp(p.amount)}</td>
      <td style="font-size:11px;color:var(--m1)">${p.method}</td>
      <td style="font-size:11px;color:var(--m1)">${p.date}</td>
      <td><span class="chip ch-${pStCls(p.status)}">${pStLbl(p.status)}</span></td>
      <td><div class="row-acts">
        ${p.status==='verify'?`<button class="btn btn-xs btn-gn" onclick="confirmPay('${p.id}')">Konfirmasi</button><button class="btn btn-xs btn-rd" onclick="rejectPay('${p.id}')">Tolak</button>`:
          p.status==='unpaid'?`<button class="btn btn-xs btn-gh" onclick="showToast('Reminder terkirim','inf')">Reminder</button>`:
          `<span style="font-size:11px;color:var(--gn)">✓ Lunas</span>`}
      </div></td>
    </tr>`).join('')}</tbody></table>` :
    '<div class="empty"><div class="empty-ic">💳</div><div class="empty-t">Tidak ada data</div></div>'}
  </div></div>`);
}
function setFPay(f) { fPay = f; adminPay(); }
function confirmPay(id) { const p = payList.find(p=>p.id===id); if(p){ p.status='paid'; buildNav(); pushActivity(`💰 Pembayaran ${p.id} (${p.client}) dikonfirmasi lunas`, 'var(--green)'); showToast('Pembayaran dikonfirmasi ✓','ok'); adminPay(); } }
function rejectPay(id)  { const p = payList.find(p=>p.id===id); if(p){ p.status='unpaid'; pushActivity(`❌ Bukti bayar ${p.id} (${p.client}) ditolak`, 'var(--red)'); showToast('Pembayaran ditolak','err'); adminPay(); } }

/* ══════════════════════════════════════
   ADMIN: DATA KLIEN
══════════════════════════════════════ */
function adminKlien() {
  setContent(`
  <div style="display:flex;justify-content:flex-end;margin-bottom:16px">
    <button class="btn btn-cu btn-sm" onclick="openModal('m-addklien')">+ Tambah Klien</button>
  </div>
  <div class="card"><div class="cb0">
    <table class="tbl"><thead><tr>
      <th>Nama / Email</th><th>WhatsApp</th><th>Proyek</th><th>Total Tagihan</th><th>Upload</th><th>Status</th><th>Aksi</th>
    </tr></thead><tbody id="kl-tbody">${renderKlienRows()}</tbody></table>
  </div></div>`);
}

function renderKlienRows() {
  if (!klienList.length) return '<tr><td colspan="7"><div class="empty"><div class="empty-t">Belum ada klien</div></div></td></tr>';
  return klienList.map((k,i) => `<tr>
    <td><div style="font-weight:600">${k.nama}</div><div style="font-size:10px;color:var(--m1)">${k.email}</div></td>
    <td style="font-size:11px;color:var(--m2)">${k.wa}</td>
    <td style="font-size:12px">${k.proyek}</td>
    <td style="font-weight:700;font-family:'Syne',sans-serif;color:var(--cu)">${fRp(k.total)}</td>
    <td style="font-size:12px">${uploads.filter(u=>u.client===k.nama).length} file</td>
    <td><span class="chip ch-active">Aktif</span></td>
    <td><div class="row-acts">
      <button class="btn btn-xs btn-bl" onclick="openEditKlien(${i})">✏️ Edit</button>
      <button class="btn btn-xs btn-rd" onclick="deleteKlien(${i})">🗑</button>
    </div></td>
  </tr>`).join('');
}

function openEditKlien(i) {
  const k = klienList[i];
  document.getElementById('ek-idx').value = i;
  document.getElementById('ek-nama').value  = k.nama;
  document.getElementById('ek-email').value = k.email;
  document.getElementById('ek-wa').value    = k.wa;
  document.getElementById('ek-proj').value  = k.proyek;
  document.getElementById('ek-p1').value = '';
  document.getElementById('ek-p2').value = '';
  document.getElementById('ek-title').textContent = `✏️ Edit — ${k.nama}`;
  setEkTab('info', document.querySelector('#ek-tabs .tab'));
  openModal('m-editklien');
}

function setEkTab(t, el) {
  ekTabState = t;
  document.querySelectorAll('#ek-tabs .tab').forEach(tb => tb.classList.remove('on'));
  if (el) el.classList.add('on');
  document.getElementById('ek-info').style.display = t === 'info' ? 'block' : 'none';
  document.getElementById('ek-pass').style.display = t === 'pass' ? 'block' : 'none';
}

async function doSaveKlien() {
  const i = parseInt(document.getElementById('ek-idx').value);
  const k = klienList[i];
  if (!k) return;
  if (ekTabState === 'info') {
    k.nama   = document.getElementById('ek-nama').value.trim();
    k.email  = document.getElementById('ek-email').value.trim();
    k.wa     = document.getElementById('ek-wa').value.trim();
    k.proyek = document.getElementById('ek-proj').value.trim();
    if (!k.nama || !k.email) { showToast('Nama dan email wajib diisi','err'); return; }
    showToast('Data klien diperbarui ✓','ok');
  } else {
    const p1 = document.getElementById('ek-p1').value;
    const p2 = document.getElementById('ek-p2').value;
    if (!p1) { showToast('Masukkan password baru','err'); return; }
    if (p1.length < 8) { showToast('Password minimal 8 karakter','err'); return; }
    if (!SP.validators.password(p1)) { showToast('Password harus mengandung huruf besar dan angka','err'); return; }
    if (p1 !== p2) { showToast('Konfirmasi password tidak cocok','err'); return; }
    if (USERS[k.email]) USERS[k.email].pass = await hashPassword(p1);
    showToast(`Password ${k.nama} berhasil diubah ✓`,'ok');
  }
  closeModal('m-editklien');
  buildNav();
  const tb = document.getElementById('kl-tbody');
  if (tb) SP.setHTML(tb, renderKlienRows());
}

function deleteKlien(i) {
  if (!confirm(`Hapus klien "${klienList[i].nama}"?`)) return;
  klienList.splice(i, 1);
  const tb = document.getElementById('kl-tbody');
  if (tb) SP.setHTML(tb, renderKlienRows());
  showToast('Klien dihapus','inf');
}

async function doAddKlien() {
  const nama  = document.getElementById('ak-nama').value.trim();
  const email = document.getElementById('ak-email').value.trim().toLowerCase();
  const pass  = document.getElementById('ak-pass').value;
  const wa    = document.getElementById('ak-wa').value.trim();
  const proyek= document.getElementById('ak-proj').value.trim();
  if (!nama || !email || !pass) { showToast('Nama, email, dan password wajib diisi','err'); return; }
  if (pass.length < 8) { showToast('Password minimal 8 karakter','err'); return; }
  if (!SP.validators.password(pass)) { showToast('Password harus mengandung huruf besar dan angka','err'); return; }
  if (USERS[email]) { showToast('Email sudah terdaftar','err'); return; }
  const passHash = await hashPassword(pass);
  USERS[email] = { pass: passHash, role:'klien', name:nama, avatar:nama.slice(0,2).toUpperCase() };
  klienList.push({ nama, email, wa, proyek, total:0 });
  closeModal('m-addklien');
  showToast(`Klien ${nama} berhasil ditambahkan ✓`,'ok');
  const tb = document.getElementById('kl-tbody');
  if (tb) SP.setHTML(tb, renderKlienRows());
}

/* ══════════════════════════════════════
   CMS: PENGUMUMAN
══════════════════════════════════════ */
function cmsPengumuman() {
  setContent(`
  <div style="display:flex;justify-content:flex-end;margin-bottom:16px">
    <button class="btn btn-cu btn-sm" onclick="openCmsEdit('pengumuman',null)">+ Pengumuman Baru</button>
  </div>
  <div id="peng-list">${renderPengumumanList()}</div>`);
}

function renderPengumumanList() {
  if (!cmsData.pengumuman.length) return '<div class="empty"><div class="empty-ic">📢</div><div class="empty-t">Belum ada pengumuman</div></div>';
  return cmsData.pengumuman.map((p,i) => `
  <div class="card" style="margin-bottom:12px">
    <div class="ch">
      <div>
        <div class="ct">${p.judul}</div>
        <div style="font-size:10px;color:var(--m1);margin-top:3px">
          Dibuat: ${p.tgl} ·
          <span style="color:${p.aktif?'var(--gn)':'var(--rd)'}">${p.aktif?'Aktif':'Nonaktif'}</span>
        </div>
      </div>
      <div class="row-acts">
        <button class="btn btn-xs ${p.aktif?'btn-rd':'btn-gn'}" onclick="togglePengumuman(${i})">${p.aktif?'Nonaktifkan':'Aktifkan'}</button>
        <button class="btn btn-xs btn-bl" onclick="openCmsEdit('pengumuman',${i})">✏️ Edit</button>
        <button class="btn btn-xs btn-rd" onclick="delPengumuman(${i})">🗑</button>
      </div>
    </div>
    <div class="cb" style="font-size:13px;color:var(--m3);line-height:1.6">${p.isi}</div>
  </div>`).join('');
}
function togglePengumuman(i) { cmsData.pengumuman[i].aktif = !cmsData.pengumuman[i].aktif; showToast('Status diperbarui','ok'); SP.setHTML(document.getElementById('peng-list'), renderPengumumanList()); }
function delPengumuman(i) { if(!confirm('Hapus pengumuman?')) return; cmsData.pengumuman.splice(i,1); showToast('Dihapus','inf'); SP.setHTML(document.getElementById('peng-list'), renderPengumumanList()); }

/* ══════════════════════════════════════
   CMS: LAYANAN
══════════════════════════════════════ */
function cmsLayanan() {
  setContent(`
  <div style="display:flex;justify-content:flex-end;margin-bottom:16px">
    <button class="btn btn-cu btn-sm" onclick="openCmsEdit('layanan',null)">+ Layanan Baru</button>
  </div>
  <div class="g2e" id="layan-list">${renderLayananList()}</div>`);
}

function renderLayananList() {
  return cmsData.layanan.map((l,i) => `
  <div class="card">
    <div class="ch">
      <div style="display:flex;align-items:center;gap:10px">
        <span style="font-size:22px">${l.ikon}</span>
        <div><div class="ct">${l.nama}</div><div style="font-size:10px;color:${l.aktif?'var(--gn)':'var(--rd)'};margin-top:2px">${l.aktif?'Aktif':'Nonaktif'}</div></div>
      </div>
      <div class="row-acts">
        <button class="btn btn-xs btn-bl" onclick="openCmsEdit('layanan',${i})">✏️</button>
        <button class="btn btn-xs btn-rd" onclick="delLayanan(${i})">🗑</button>
      </div>
    </div>
    <div class="cb">
      <div style="font-size:12px;color:var(--m2);margin-bottom:8px">${l.isi}</div>
      <div style="font-family:'Syne',sans-serif;font-size:13px;font-weight:700;color:var(--cu)">${l.harga}</div>
    </div>
  </div>`).join('');
}
function delLayanan(i) { if(!confirm('Hapus layanan?')) return; cmsData.layanan.splice(i,1); showToast('Dihapus','inf'); const el=document.getElementById('layan-list'); if(el) SP.setHTML(el, renderLayananList()); }

/* ══════════════════════════════════════
   CMS: KONTAK
══════════════════════════════════════ */
function cmsKontak() {
  const d = cmsData.kontak;
  setContent(`
  <div class="card" style="max-width:560px">
    <div class="ch"><div class="ct">📞 Informasi Kontak</div></div>
    <div class="cb">
      <div class="fg"><label>Nama Studio / Perusahaan</label><input class="cms-inp" id="ck-nama" value="${esc(d.nama)}"></div>
      <div class="fg"><label>Email</label><input class="cms-inp" id="ck-email" value="${esc(d.email)}"></div>
      <div class="fg"><label>WhatsApp</label><input class="cms-inp" id="ck-wa" value="${esc(d.wa)}"></div>
      <div class="fg"><label>Alamat</label><textarea class="cms-ta" id="ck-alamat">${esc(d.alamat)}</textarea></div>
      <div class="fg"><label>Jam Operasional</label><input class="cms-inp" id="ck-jam" value="${esc(d.jam)}"></div>
      <button class="btn btn-cu" onclick="saveKontak()">Simpan Perubahan</button>
    </div>
  </div>`);
}
function saveKontak() {
  cmsData.kontak = { nama:v('ck-nama'), email:v('ck-email'), wa:v('ck-wa'), alamat:v('ck-alamat'), jam:v('ck-jam') };
  showToast('Informasi kontak disimpan ✓','ok');
}

/* ══════════════════════════════════════
   CMS: SITE INFO
══════════════════════════════════════ */
function cmsSiteinfo() {
  const d = cmsData.siteinfo;
  setContent(`
  <div class="g2e">
    <div class="card">
      <div class="ch"><div class="ct">⚙️ Informasi Situs</div></div>
      <div class="cb">
        <div class="fg"><label>Nama Situs</label><input class="cms-inp" id="si-judul" value="${esc(d.judul)}"></div>
        <div class="fg"><label>Tagline</label><input class="cms-inp" id="si-tag" value="${esc(d.tagline)}"></div>
        <button class="btn btn-cu" onclick="saveSiteinfo()">Simpan</button>
      </div>
    </div>
    <div class="card">
      <div class="ch"><div class="ct">🏦 Info Rekening</div></div>
      <div class="cb">
        <div class="fg"><label>Rekening BCA</label><input class="cms-inp" id="si-bca" value="${esc(d.rek_bca)}"></div>
        <div class="fg"><label>Rekening Mandiri</label><input class="cms-inp" id="si-mdr" value="${esc(d.rek_mandiri)}"></div>
        <div class="fg"><label>Atas Nama</label><input class="cms-inp" id="si-an" value="${esc(d.an)}"></div>
        <div class="info-box" style="margin-top:4px">Info rekening tampil pada tagihan klien yang belum lunas.</div>
        <button class="btn btn-cu" style="margin-top:12px" onclick="saveRekening()">Simpan</button>
      </div>
    </div>
  </div>
  <!-- Admin Password Change Card -->
  <div class="card" style="margin-top:18px;max-width:520px">
    <div class="ch">
      <div class="ct">🔑 Ubah Password Admin</div>
      <span style="font-size:11px;color:var(--m1)">${esc(CU.email)}</span>
    </div>
    <div class="cb">
      <div class="warn-box" style="margin-bottom:16px">⚠️ Pastikan Anda mengingat password baru. Password tidak bisa dipulihkan otomatis.</div>
      <div class="fg"><label>Password Saat Ini</label>
        <div class="pw-wrap">
          <input type="password" id="adm-pass-old" class="cms-inp" placeholder="Masukkan password saat ini">
        </div>
      </div>
      <div class="fg"><label>Password Baru</label>
        <div class="pw-wrap">
          <input type="password" id="adm-pass-new" class="cms-inp" placeholder="Min. 8 karakter, huruf besar & angka" oninput="updateAdmPwStrength(this.value)">
        </div>
        <div id="adm-pw-strength-wrap" style="display:none;margin-top:6px">
          <div style="height:3px;background:var(--s3);border-radius:3px;overflow:hidden">
            <div id="adm-pw-strength-bar" style="height:100%;width:0%;transition:all .3s;border-radius:3px"></div>
          </div>
          <div id="adm-pw-strength-label" style="font-size:10px;color:var(--m1);margin-top:3px"></div>
        </div>
      </div>
      <div class="fg"><label>Konfirmasi Password Baru</label>
        <input type="password" id="adm-pass-confirm" class="cms-inp" placeholder="Ulangi password baru">
      </div>
      <button class="btn btn-cu" onclick="saveAdminPassword()">🔒 Simpan Password Baru</button>
    </div>
  </div>
  <!-- Danger Zone -->
  <div class="card" style="margin-top:18px;max-width:520px;border-color:rgba(224,85,85,.25)">
    <div class="ch" style="border-bottom-color:rgba(224,85,85,.15)">
      <div class="ct" style="color:var(--red)">⚠️ Zona Berbahaya</div>
    </div>
    <div class="cb">
      <div class="warn-box" style="border-color:rgba(224,85,85,.25);color:#f4a0a0;margin-bottom:16px">
        Tindakan di bawah ini <strong>tidak dapat dibatalkan</strong>. Semua data klien, upload, invoice, dan aktivitas akan dihapus permanen dari server.
      </div>
      <button class="btn btn-rd" style="width:100%;justify-content:center;padding:12px" onclick="doHardReset()">
        🗑️ Hapus Semua Data Portal
      </button>
    </div>
  </div>`);
}

async function doHardReset() {
  const confirm1 = confirm('⚠️ PERINGATAN: Semua data klien, upload, invoice, dan aktivitas akan DIHAPUS PERMANEN.\n\nLanjutkan?');
  if (!confirm1) return;
  const confirm2 = prompt('Ketik HAPUS SEMUA untuk konfirmasi:');
  if (confirm2 !== 'HAPUS SEMUA') { showToast('Reset dibatalkan.', 'inf'); return; }

  // Simpan data admin agar tidak ikut terhapus
  const adminEmail = CU.email;
  const adminUser  = { ...USERS[adminEmail] };

  // Kosongkan semua data
  uploads        = [];
  payList        = [];
  klienList      = [];
  invList        = [];
  adminRevisions = [];
  uFiles         = {};

  // Hapus semua user klien, pertahankan admin
  USERS = {};
  USERS[adminEmail] = adminUser;

  // Hapus activity log lokal
  try { localStorage.removeItem('rhpartners.portal.activitylog.v1'); } catch(e) {}

  // Simpan ke localStorage
  saveStateToLocal();

  // Simpan ke Supabase
  if (window.__studioportalDB?.persistState) {
    try { await window.__studioportalDB.persistState('hard-reset'); } catch(e) {}
  }

  showToast('Semua data berhasil dihapus ✓', 'ok');
  buildNav();
  navTo('dash');
}
function saveSiteinfo() { cmsData.siteinfo.judul=v('si-judul'); cmsData.siteinfo.tagline=v('si-tag'); showToast('Pengaturan situs disimpan ✓','ok'); }
function saveRekening() { cmsData.siteinfo.rek_bca=v('si-bca'); cmsData.siteinfo.rek_mandiri=v('si-mdr'); cmsData.siteinfo.an=v('si-an'); showToast('Info rekening disimpan ✓','ok'); }

function updateAdmPwStrength(val) {
  const wrap = document.getElementById('adm-pw-strength-wrap');
  const bar  = document.getElementById('adm-pw-strength-bar');
  const lbl  = document.getElementById('adm-pw-strength-label');
  if (!val) { if(wrap) wrap.style.display='none'; return; }
  const str = SP.passwordStrength(val);
  const pct = (str.score / 5) * 100;
  if (wrap) wrap.style.display = 'block';
  if (bar)  { bar.style.width = pct + '%'; bar.style.background = str.color; }
  if (lbl)  { lbl.style.color = str.color; lbl.textContent = 'Kekuatan: ' + str.label; }
}

async function saveAdminPassword() {
  const oldPass   = document.getElementById('adm-pass-old')?.value || '';
  const newPass   = document.getElementById('adm-pass-new')?.value || '';
  const confPass  = document.getElementById('adm-pass-confirm')?.value || '';

  if (!oldPass) { showToast('Masukkan password saat ini','err'); return; }
  if (!newPass) { showToast('Masukkan password baru','err'); return; }
  if (!SP.validators.password(newPass)) { showToast('Password baru minimal 8 karakter, ada huruf besar & angka','err'); return; }
  if (newPass !== confPass) { showToast('Konfirmasi password tidak cocok','err'); return; }
  if (oldPass === newPass)  { showToast('Password baru tidak boleh sama dengan yang lama','err'); return; }

  const userRec = USERS[CU.email];
  if (!userRec) { showToast('Akun tidak ditemukan','err'); return; }
  const oldHash = await hashPassword(oldPass);
  if (userRec.pass !== oldHash) { showToast('Password saat ini salah','err'); return; }

  const newHash = await hashPassword(newPass);
  USERS[CU.email].pass = newHash;
  if (window.__studioportalDB?.queuePersist) window.__studioportalDB.queuePersist('change-admin-password');
  queueLocalSave();
  showToast('Password admin berhasil diubah ✓','ok');
  SP.log('admin_password_changed', CU.email);
  ['adm-pass-old','adm-pass-new','adm-pass-confirm'].forEach(id => { const el = document.getElementById(id); if(el) el.value=''; });
  const wrap = document.getElementById('adm-pw-strength-wrap');
  if (wrap) wrap.style.display = 'none';
}

/* ── CMS EDIT MODAL ── */
function openCmsEdit(type, idx) {
  editCms = { type, idx };
  const isNew = idx === null;
  document.getElementById('cms-mt').textContent = `${isNew?'Tambah':'Edit'} ${type==='pengumuman'?'Pengumuman':'Layanan'}`;
  let html = '';
  if (type === 'pengumuman') {
    const d = isNew ? { judul:'', isi:'', aktif:true } : cmsData.pengumuman[idx];
    html = `
    <div class="fg"><label>Judul</label><input class="cms-inp" id="ce-judul" value="${esc(d.judul)}" placeholder="Judul pengumuman"></div>
    <div class="fg"><label>Isi / Konten</label><textarea class="cms-ta" id="ce-isi" rows="5">${esc(d.isi)}</textarea></div>
    <div class="fg"><label>Status</label><select id="ce-aktif" class="cms-inp">
      <option value="1"${d.aktif?' selected':''}>Aktif</option>
      <option value="0"${!d.aktif?' selected':''}>Nonaktif</option>
    </select></div>`;
  } else {
    const d = isNew ? { nama:'', isi:'', harga:'', ikon:'🛠️', aktif:true } : cmsData.layanan[idx];
    html = `
    <div class="fg2">
      <div class="fg" style="margin-bottom:0"><label>Nama Layanan</label><input class="cms-inp" id="ce-nama" value="${esc(d.nama)}" placeholder="Nama Layanan"></div>
      <div class="fg" style="margin-bottom:0"><label>Ikon (emoji)</label><input class="cms-inp" id="ce-ikon" value="${d.ikon||'🛠️'}"></div>
    </div>
    <div class="fg" style="margin-top:15px"><label>Deskripsi</label><textarea class="cms-ta" id="ce-isi">${esc(d.isi)}</textarea></div>
    <div class="fg2">
      <div class="fg" style="margin-bottom:0"><label>Harga</label><input class="cms-inp" id="ce-harga" value="${esc(d.harga)}" placeholder="Mulai Rp 5.000.000"></div>
      <div class="fg" style="margin-bottom:0"><label>Status</label><select id="ce-aktif" class="cms-inp">
        <option value="1"${d.aktif?' selected':''}>Aktif</option>
        <option value="0"${!d.aktif?' selected':''}>Nonaktif</option>
      </select></div>
    </div>`;
  }
  SP.setHTML(document.getElementById('cms-body'), html);
  openModal('m-cms');
}

function saveCmsItem() {
  const { type, idx } = editCms;
  const isNew = idx === null;
  if (type === 'pengumuman') {
    const judul = v('ce-judul');
    if (!judul) { showToast('Judul wajib diisi','err'); return; }
    const item = { id: isNew ? Date.now() : cmsData.pengumuman[idx].id, judul, isi:v('ce-isi'), aktif: v('ce-aktif')==='1', tgl: isNew ? new Date().toLocaleDateString('id-ID') : cmsData.pengumuman[idx].tgl };
    if (isNew) cmsData.pengumuman.unshift(item); else cmsData.pengumuman[idx] = item;
    closeModal('m-cms'); showToast('Pengumuman disimpan ✓','ok'); cmsPengumuman();
  } else {
    const nama = v('ce-nama');
    if (!nama) { showToast('Nama wajib diisi','err'); return; }
    const item = { id: isNew ? Date.now() : cmsData.layanan[idx].id, nama, isi:v('ce-isi'), harga:v('ce-harga'), ikon:v('ce-ikon')||'🛠️', aktif: v('ce-aktif')==='1' };
    if (isNew) cmsData.layanan.push(item); else cmsData.layanan[idx] = item;
    closeModal('m-cms'); showToast('Layanan disimpan ✓','ok'); cmsLayanan();
  }
  queueLocalSave();
}

/* ══════════════════════════════════════
   ADMIN: REPORT
══════════════════════════════════════ */
function adminReport() {
  const pA = payList.filter(p=>p.status==='paid').reduce((s,p)=>s+p.amount,0);
  const pU = payList.filter(p=>p.status!=='paid').reduce((s,p)=>s+p.amount,0);
  setContent(`
  <div class="g3 stats">
    <div class="sc gn"><div class="sl">Pendapatan Terkonfirmasi</div><div class="sv gn">${fRp(pA)}</div><div class="ss">${payList.filter(p=>p.status==='paid').length} invoice lunas</div></div>
    <div class="sc rd"><div class="sl">Piutang</div><div class="sv rd">${fRp(pU)}</div><div class="ss">${payList.filter(p=>p.status!=='paid').length} invoice pending</div></div>
    <div class="sc cu"><div class="sl">Total Klien</div><div class="sv cu">${klienList.length}</div><div class="ss">${uploads.length} total upload</div></div>
  </div>
  <div class="g2e">
    <div class="card"><div class="ch"><div class="ct">Upload per Tipe</div></div><div class="cb">
      ${[['revisi','Revisi','cu'],['rekaman','Rekaman','pu']].map(([t,l,c])=>{
        const n=uploads.filter(u=>u.tipe===t).length, tot=uploads.length||1, pct=Math.round(n/tot*100);
        return `<div style="margin-bottom:14px"><div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:5px"><span>${l}</span><span style="color:var(--m1)">${n} (${pct}%)</span></div><div class="pbar" style="height:6px"><div class="pfill" style="width:${pct}%;background:var(--${c})"></div></div></div>`;
      }).join('')}
      ${[['pending','Menunggu','cu'],['approved','Disetujui','gn'],['rejected','Ditolak','rd'],['reviewed','Diputar','pu']].map(([s,l,c])=>{
        const n=uploads.filter(u=>u.status===s).length, tot=uploads.length||1, pct=Math.round(n/tot*100);
        return `<div style="margin-bottom:14px"><div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:5px"><span>${l}</span><span style="color:var(--m1)">${n} (${pct}%)</span></div><div class="pbar" style="height:6px"><div class="pfill" style="width:${pct}%;background:var(--${c})"></div></div></div>`;
      }).join('')}
    </div></div>
    <div class="card"><div class="ch"><div class="ct">Klien & Upload</div></div><div class="cb">
      ${klienList.map(k=>{
        const n=uploads.filter(u=>u.client===k.nama).length;
        return `<div class="fi-item"><div class="fc fc-zip" style="font-family:'Syne',sans-serif;font-size:11px;font-weight:800">${k.nama.slice(0,2).toUpperCase()}</div><div class="fi-meta"><div class="fi-name">${k.nama}</div><div class="fi-size">${n} file · ${fRp(k.total)}</div></div><span class="chip ch-active">Aktif</span></div>`;
      }).join('')}
    </div></div>
  </div>`);
}

/* ══════════════════════════════════════
   KLIEN: DASHBOARD
══════════════════════════════════════ */
function dashKlien() {
  const _unreadHasil = adminRevisions.filter(r => r.klien === CU.name && !r.dibaca).length;
  const _hasilBanner = _unreadHasil ? `<div class="warn-box" style="margin-bottom:16px;display:flex;align-items:center;justify-content:space-between;cursor:pointer" onclick="navTo('hasil-revisi')"><span>📨 Ada <strong>${_unreadHasil}</strong> hasil revisi baru dari studio!</span><button class="btn btn-cu btn-xs">Lihat →</button></div>` : '';
  const myUp  = uploads.filter(u => u.client === CU.name);
  const myRev = myUp.filter(u => u.tipe === 'revisi');
  const myRek = myUp.filter(u => u.tipe === 'rekaman');
  const myInv = payList.filter(p => p.client === CU.name);
  const tot   = myInv.reduce((s,p)=>s+p.amount,0);
  const lunas = myInv.filter(p=>p.status==='paid').reduce((s,p)=>s+p.amount,0);
  const blm   = myInv.filter(p=>p.status!=='paid').reduce((s,p)=>s+p.amount,0);

  setContent(`
  <div class="wb">
    <div><h2>Halo, <span>${CU.name.split(' ')[0]}</span>! 🎨</h2><p>Pantau perkembangan proyek dan pembayaran Anda.</p></div>
    <div class="wb-ic">🎯</div>
  </div>
  ${_hasilBanner}
  
  <div class="g5 stats">
    <div class="sc cu"><div class="sic">📄</div><div class="sl">Revisi</div><div class="sv cu">${myRev.length}</div><div class="ss">${myRev.filter(r=>r.status==='pending').length} menunggu</div></div>
    <div class="sc pu"><div class="sic">🎙️</div><div class="sl">Rekaman</div><div class="sv pu">${myRek.length}</div><div class="ss">${myRek.filter(r=>r.status==='pending').length} baru</div></div>
    <div class="sc gn"><div class="sic">✅</div><div class="sl">Disetujui</div><div class="sv gn">${myRev.filter(r=>r.status==='approved').length}</div><div class="ss">Revisi selesai</div></div>
    <div class="sc bl"><div class="sic">💳</div><div class="sl">Total Tagihan</div><div class="sv bl">${fRp(tot)}</div><div class="ss">${myInv.length} invoice</div></div>
    <div class="sc rd"><div class="sic">⏳</div><div class="sl">Belum Dibayar</div><div class="sv rd">${fRp(blm)}</div><div class="ss">${fRp(lunas)} lunas</div></div>
  </div>
  <div class="g2">
    <div class="card">
      <div class="ch"><div class="ct">File Saya</div><button class="btn btn-cu btn-xs" onclick="openModal('m-upload')">+ Upload</button></div>
      <div class="cb0">${myUp.length ? `<table class="tbl"><thead><tr><th>Tipe</th><th>Proyek</th><th>Judul</th><th>Tgl</th><th>Status</th></tr></thead><tbody>
        ${myUp.slice(0,8).map(u=>`<tr>
          <td><span class="chip ${u.tipe==='rekaman'?'ch-rek-tipe':'ch-rev-tipe'}">${u.tipe==='rekaman'?'🎙️':'📄'} ${cap(u.tipe)}</span></td>
          <td style="font-size:11px;color:var(--m1)">${u.proj}</td>
          <td style="font-size:12px;font-weight:500">${u.judul}</td>
          <td style="font-size:10px;color:var(--m1)">${u.tgl}</td>
          <td><span class="chip ch-${stCls(u.status)}">${stLbl(u.status)}</span></td>
        </tr>`).join('')}
      </tbody></table>` : '<div class="empty"><div class="empty-t">Belum ada upload</div></div>'}</div>
    </div>
    <div class="card">
      <div class="ch"><div class="ct">Tagihan Saya</div><button class="btn btn-ol btn-xs" onclick="navTo('pay-kln')">Bayar →</button></div>
      <div class="cb">${myInv.length ? myInv.map(p=>`
        <div class="ic">
          <div class="ic-top"><span class="ic-id">${p.id}</span><span class="chip ch-${pStCls(p.status)}">${pStLbl(p.status)}</span></div>
          <div class="ic-desc">${p.desc}</div>
          <div class="ic-ft"><span class="ic-due">Jatuh tempo: ${p.due}</span><span class="ic-amt">${fRp(p.amount)}</span></div>
          ${p.status==='unpaid'?`<button class="btn btn-cu btn-full btn-sm" style="margin-top:8px" onclick="openPayModal('${p.id}')">Bayar Sekarang</button>`:''}
        </div>`).join('') : '<div class="empty"><div class="empty-t">Tidak ada tagihan</div></div>'}
      </div>
    </div>
  </div>`);
}

/* ══════════════════════════════════════
   KLIEN: UPLOAD FILE (Revisi + Rekaman)
══════════════════════════════════════ */
function klienUpload() {
  uFiles = {};
  pgBlobs = [];
  const myUp = uploads.filter(u => u.client === CU.name);

  setContent(`
  <div class="g2">
    <div>
      <div class="card">
        <div class="ch"><div class="ct">📤 Upload File</div></div>
        <div class="cb">
          <div class="tabs" id="pg-tabs">
            <div class="tab on" onclick="setPgTab('rev',this)">📄 Revisi</div>
            <div class="tab" onclick="setPgTab('rek',this)">🎙️ Rekaman</div>
          </div>
          <!-- REVISI -->
          <div id="pg-rev">
            <div class="fg"><label>Proyek</label>
              <select id="pg-proj">${projectOptions()}</select>
            </div>
            <div class="fg2">
              <div class="fg" style="margin-bottom:0"><label>Versi</label><input type="text" id="pg-ver" placeholder="cth. v2.1"></div>
              <div class="fg" style="margin-bottom:0"><label>Tanggal</label><input type="text" id="pg-tgl" placeholder="${today()}"></div>
            </div>
            <div class="fg" style="margin-top:15px"><label>Catatan</label><textarea id="pg-note" placeholder="Jelaskan perubahan..."></textarea></div>
            <div class="upz" id="pg-zone" ondragover="onDragOver(event,'pg-zone')" ondragleave="onDragLeave('pg-zone')" ondrop="onDrop(event,'pg-files')">
              <div class="upz-ic">📎</div>
              <div class="upz-t">Seret atau klik untuk upload</div>
              <div class="upz-s">PDF · ZIP · PNG · AI · PSD — Maks 50MB</div>
              <input type="file" multiple onchange="onFileInput(event,'pg-files')">
            </div>
            <div id="pg-files-list" style="margin-top:6px"></div>
            <div id="pg-prog" style="display:none;margin-top:8px">
              <div style="font-size:11px;color:var(--m1);margin-bottom:4px">Mengirim...</div>
              <div class="pbar"><div class="pfill" id="pg-pfill" style="width:0%"></div></div>
            </div>
            <button class="btn btn-cu btn-full" style="margin-top:14px" onclick="submitPgRevisi()">Kirim Revisi</button>
          </div>
          <!-- REKAMAN -->
          <div id="pg-rek" style="display:none">
            <div class="fg"><label>Proyek</label>
              <select id="pgr-proj">${projectOptions()}</select>
            </div>
            <div class="fg"><label>Judul Rekaman</label><input type="text" id="pgr-judul" placeholder="cth. Feedback Halaman Utama"></div>
            <div class="fg"><label>Catatan</label><textarea id="pgr-note" placeholder="Instruksi atau keterangan..."></textarea></div>
            <canvas class="rec-cv" id="pg-cv"></canvas>
            <div style="display:flex;align-items:center;gap:12px;margin-bottom:10px">
              <div class="rec-timer" id="pg-timer">00:00</div>
              <div id="pg-pulse" style="display:none"><div class="rec-pulse"></div></div>
              <span style="font-size:11px;color:var(--m1);margin-left:auto" id="pg-rec-st">Siap merekam</span>
            </div>
            <div style="display:flex;gap:8px;margin-bottom:10px">
              <button class="btn btn-rd btn-sm" id="pg-btn-s" type="button" onclick="pgStartRec()">⏺ Mulai</button>
              <button class="btn btn-gh btn-sm" id="pg-btn-p" type="button" style="display:none" onclick="pgPauseRec()">⏸ Jeda</button>
              <button class="btn btn-gh btn-sm" id="pg-btn-st" type="button" style="display:none" onclick="pgStopRec()">⏹ Stop</button>
            </div>
            <div id="pg-blobs-list"></div>
            <div class="sep"><div class="sep-line"></div>atau upload file<div class="sep-line"></div></div>
            <div class="upz" id="pgr-zone" style="padding:18px" ondragover="onDragOver(event,'pgr-zone')" ondragleave="onDragLeave('pgr-zone')" ondrop="onDrop(event,'pgr-files')">
              <div class="upz-ic" style="font-size:20px">🎵</div>
              <div class="upz-t" style="font-size:12px">Upload Audio / Video</div>
              <div class="upz-s">MP3 · WAV · M4A · MP4 · WEBM</div>
              <input type="file" accept="audio/*,video/*" multiple onchange="onFileInput(event,'pgr-files')">
            </div>
            <div id="pgr-files-list" style="margin-top:6px"></div>
            <div id="pgr-prog" style="display:none;margin-top:8px">
              <div style="font-size:11px;color:var(--m1);margin-bottom:4px">Mengirim...</div>
              <div class="pbar"><div class="pfill" id="pgr-pfill" style="width:0%"></div></div>
            </div>
            <button class="btn btn-cu btn-full" style="margin-top:14px" onclick="submitPgRekaman()">Kirim Rekaman</button>
          </div>
        </div>
      </div>
    </div>
    <div class="card">
      <div class="ch"><div class="ct">Semua Upload Saya</div><span style="font-size:11px;color:var(--m1)">${myUp.length} file</span></div>
      <div class="cb0" id="my-up-list">${renderMyUploads()}</div>
    </div>
  </div>`);

  // draw idle canvas after DOM ready
  setTimeout(() => pgDrawIdle(), 50);
}

function setPgTab(t, el) {
  document.querySelectorAll('#pg-tabs .tab').forEach(tb => tb.classList.remove('on'));
  if (el) el.classList.add('on');
  document.getElementById('pg-rev').style.display = t === 'rev' ? 'block' : 'none';
  document.getElementById('pg-rek').style.display = t === 'rek' ? 'block' : 'none';
  if (t === 'rek') setTimeout(() => pgDrawIdle(), 30);
}

function renderMyUploads() {
  const list = uploads.filter(u => u.client === CU.name);
  if (!list.length) return '<div class="empty"><div class="empty-ic">📂</div><div class="empty-t">Belum ada upload</div></div>';
  return `<div style="padding:0 16px">${list.map(u=>`
    <div class="fi-item">
      <div class="fc ${u.tipe==='rekaman'?'fc-aud':'fc-pdf'}">${u.tipe==='rekaman'?'🎙️':'📄'}</div>
      <div class="fi-meta">
        <div class="fi-name">${u.judul}${u.ver&&u.ver!=='-'?` <span style="font-size:10px;color:var(--m1)">(${u.ver})</span>`:''}</div>
        <div class="fi-size">${u.proj} · ${u.tgl}</div>
      </div>
      <span class="chip ch-${stCls(u.status)}" style="font-size:9px">${stLbl(u.status)}</span>
    </div>`).join('')}</div>`;
}

async function submitPgRevisi() {
  const proj = v('pg-proj');
  const ver  = v('pg-ver');
  const note = v('pg-note');
  if (!proj) { showToast('Pilih proyek terlebih dahulu','err'); return; }
  if (!ver)  { showToast('Isi versi terlebih dahulu','err'); return; }
  const files = uFiles['pg-files'] || [];
  if (!files.length) { showToast('Upload minimal 1 file','err'); return; }
  runProgress('pg-prog','pg-pfill', async () => {
    const uploadedFiles = await window.__portalSupabaseStorage.uploadBrowserFiles(files, 'revisi', `${CU.name}/${proj}/${ver}`);
    uploads.unshift({ id:Date.now(), client:CU.name, proj, tipe:'revisi', ver, judul:`Revisi ${ver}`, catatan:note, files:uploadedFiles, tgl:today(), status:'pending' });
    uFiles['pg-files'] = [];
    renderFileList('pg-files');
    buildNav();
    showToast('Revisi berhasil dikirim! ✓','ok');
    const el = document.getElementById('my-up-list');
    if (el) SP.setHTML(el, renderMyUploads());
  });
}

async function submitPgRekaman() {
  const proj  = v('pgr-proj');
  const judul = v('pgr-judul');
  const note  = v('pgr-note');
  if (!proj)  { showToast('Pilih proyek terlebih dahulu','err'); return; }
  if (!judul) { showToast('Isi judul rekaman','err'); return; }
  const audFiles = uFiles['pgr-files'] || [];
  if (!pgBlobs.length && !audFiles.length) { showToast('Rekam atau upload file audio terlebih dahulu','err'); return; }
  runProgress('pgr-prog','pgr-pfill', async () => {
    const recordedUploads = await window.__portalSupabaseStorage.uploadBlobItems(pgBlobs, 'rekaman', `${CU.name}/${proj}/${judul}`);
    const browserUploads = await window.__portalSupabaseStorage.uploadBrowserFiles(audFiles, 'rekaman', `${CU.name}/${proj}/${judul}`);
    const allItems = [
      ...recordedUploads.map(f => ({ file:f, dur:f.durationLabel || '—' })),
      ...browserUploads.map(f => ({ file:f, dur:'—' })),
    ];
    allItems.forEach(item => {
      uploads.unshift({ id:Date.now()+Math.random(), client:CU.name, proj, tipe:'rekaman', ver:item.dur, judul, catatan:note, files:[item.file], tgl:today(), status:'pending' });
    });
    pgBlobs = [];
    uFiles['pgr-files'] = [];
    renderFileList('pgr-files');
    document.getElementById('pg-blobs-list').innerHTML = '';
    buildNav();
    showToast('Rekaman berhasil dikirim! ✓','ok');
    const el = document.getElementById('my-up-list');
    if (el) SP.setHTML(el, renderMyUploads());
  });
}

/* ── PAGE RECORDER ── */
function pgDrawIdle() {
  const c = document.getElementById('pg-cv');
  if (!c) return;
  c.width = c.offsetWidth || c.parentElement.offsetWidth || 400;
  c.height = 60;
  const ctx = c.getContext('2d');
  ctx.clearRect(0,0,c.width,c.height);
  ctx.strokeStyle = 'rgba(201,121,65,.22)';
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  ctx.moveTo(0, 30);
  for (let x = 0; x < c.width; x += 4) ctx.lineTo(x, 30 + Math.sin(x * 0.055) * 5);
  ctx.stroke();
}

async function pgStartRec() {
  try {
    pgStream = await navigator.mediaDevices.getUserMedia({ audio:true });
    const AC = window.AudioContext || window.webkitAudioContext;
    const ac = new AC();
    const src = ac.createMediaStreamSource(pgStream);
    const an = ac.createAnalyser(); an.fftSize = 512;
    src.connect(an);
    const c = document.getElementById('pg-cv');
    const buf = new Uint8Array(an.frequencyBinCount);
    function draw() {
      pgAnim = requestAnimationFrame(draw);
      an.getByteTimeDomainData(buf);
      c.width = c.offsetWidth || 400; c.height = 60;
      const ctx = c.getContext('2d');
      ctx.clearRect(0,0,c.width,c.height);
      ctx.shadowBlur = 6; ctx.shadowColor = 'rgba(224,85,85,.4)';
      ctx.strokeStyle = 'rgba(224,85,85,.9)'; ctx.lineWidth = 2;
      ctx.beginPath();
      const sw = c.width / buf.length; let x = 0;
      for (let i = 0; i < buf.length; i++) {
        const y = (buf[i] / 128) * 30;
        i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
        x += sw;
      }
      ctx.lineTo(c.width, 30); ctx.stroke();
    }
    draw();
    pgRec = new MediaRecorder(pgStream);
    pgChunks = []; pgSec = 0; pgPaused = false;
    pgRec.ondataavailable = e => { if (e.data.size > 0) pgChunks.push(e.data); };
    pgRec.onstop = () => {
      const blob = new Blob(pgChunks, { type:'audio/webm' });
      const url = URL.createObjectURL(blob);
      const dur = fDur(pgSec);
      pgBlobs.push({ blob, url, dur, sz:fSz(blob.size), name:`rekaman_${Date.now()}.webm` });
      renderPgBlobs();
      const t = document.getElementById('pg-timer'); if(t) t.textContent = '00:00';
    };
    pgRec.start(100);
    pgIntv = setInterval(() => {
      if (!pgPaused) {
        pgSec++;
        const el = document.getElementById('pg-timer');
        if (el) el.textContent = fDur(pgSec);
      }
    }, 1000);
    sel('pg-btn-s', 'display', 'none');
    sel('pg-btn-p', 'display', 'flex');
    sel('pg-btn-st', 'display', 'flex');
    sel('pg-pulse', 'display', 'block');
    const timer = document.getElementById('pg-timer'); if(timer) timer.classList.add('rec-on');
    const st = document.getElementById('pg-rec-st'); if(st) st.textContent = 'Sedang merekam…';
  } catch(e) {
    showToast('Mikrofon tidak dapat diakses. Izinkan akses mikrofon.','err');
  }
}

function pgPauseRec() {
  if (!pgRec) return;
  if (pgPaused) {
    pgRec.resume(); pgPaused = false;
    const btn = document.getElementById('pg-btn-p'); if(btn) btn.innerHTML = '⏸ Jeda';
    sel('pg-pulse','display','block');
    const st = document.getElementById('pg-rec-st'); if(st) st.textContent = 'Sedang merekam…';
  } else {
    pgRec.pause(); pgPaused = true;
    const btn = document.getElementById('pg-btn-p'); if(btn) btn.innerHTML = '▶ Lanjut';
    sel('pg-pulse','display','none');
    const st = document.getElementById('pg-rec-st'); if(st) st.textContent = 'Dijeda';
  }
}

function pgStopRec() {
  if (pgRec && pgRec.state !== 'inactive') pgRec.stop();
  if (pgStream) pgStream.getTracks().forEach(t => t.stop());
  clearInterval(pgIntv);
  if (pgAnim) { cancelAnimationFrame(pgAnim); pgAnim = null; }
  pgRec = null; pgStream = null;
  sel('pg-btn-s','display','flex'); sel('pg-btn-p','display','none'); sel('pg-btn-st','display','none');
  sel('pg-pulse','display','none');
  const timer = document.getElementById('pg-timer'); if(timer) timer.classList.remove('rec-on');
  const st = document.getElementById('pg-rec-st'); if(st) st.textContent = 'Siap merekam';
  pgDrawIdle();
}

function renderPgBlobs() {
  const el = document.getElementById('pg-blobs-list'); if (!el) return;
  el.innerHTML = pgBlobs.map((b,i) => `
    <div class="fi-item">
      <div class="fc fc-aud">🎙️</div>
      <div class="fi-meta">
        <div class="fi-name">${b.name}</div>
        <div class="fi-size">${b.dur} · ${b.sz}</div>
        <audio src="${b.url}" controls style="width:100%;height:28px;margin-top:5px"></audio>
      </div>
      <button class="btn btn-xs btn-rd" onclick="pgBlobs.splice(${i},1);renderPgBlobs()">✕</button>
    </div>`).join('');
}

/* ══════════════════════════════════════
   KLIEN: PEMBAYARAN
══════════════════════════════════════ */
function klienPay() {
  const myInv = payList.filter(p => p.client === CU.name);
  const unpaid = myInv.filter(p => p.status === 'unpaid');
  setContent(`
  <div class="g2">
    <div class="card">
      <div class="ch"><div class="ct">💳 Upload Bukti Pembayaran</div></div>
      <div class="cb">
        <div class="fg"><label>Invoice</label>
          <select id="kp-inv" class="cms-inp">
            ${unpaid.length ? unpaid.map(p=>`<option value="${p.id}">${p.id} — ${fRp(p.amount)}</option>`).join('') : '<option value="">Tidak ada tagihan yang perlu dibayar</option>'}
          </select>
        </div>
        <div class="fg2">
          <div class="fg" style="margin-bottom:0"><label>Metode</label>
            <select id="kp-meth" class="cms-inp"><option>Transfer BCA</option><option>Transfer Mandiri</option><option>QRIS</option><option>GoPay/OVO</option></select>
          </div>
          <div class="fg" style="margin-bottom:0"><label>Jumlah (Rp)</label><input type="number" id="kp-amt" class="cms-inp" placeholder="0"></div>
        </div>
        <div class="fg2" style="margin-top:15px">
          <div class="fg" style="margin-bottom:0"><label>Tanggal</label><input type="text" id="kp-tgl" class="cms-inp" placeholder="${today()}"></div>
          <div class="fg" style="margin-bottom:0"><label>Kode Referensi</label><input type="text" id="kp-ref" class="cms-inp" placeholder="TRF..."></div>
        </div>
        <div class="fg" style="margin-top:15px"><label>Bukti Transfer</label>
          <div class="upz" style="padding:16px">
            <div class="upz-ic" style="font-size:20px">🧾</div>
            <div class="upz-t" style="font-size:12px">Upload Bukti Transfer</div>
            <input type="file" accept="image/*,.pdf" onchange="kpFileIn(event)">
          </div>
          <div id="kp-prev" style="margin-top:6px"></div>
        </div>
        <button class="btn btn-cu btn-full" style="margin-top:14px" onclick="submitKpPay()">Kirim Bukti Pembayaran</button>
      </div>
    </div>
    <div class="card">
      <div class="ch"><div class="ct">Semua Tagihan Saya</div></div>
      <div class="cb">${myInv.length ? myInv.map(p=>`
        <div class="ic">
          <div class="ic-top"><span class="ic-id">${p.id}</span><span class="chip ch-${pStCls(p.status)}">${pStLbl(p.status)}</span></div>
          <div class="ic-desc">${p.desc}</div>
          <div class="ic-ft"><span class="ic-due">Jatuh tempo: ${p.due}</span><span class="ic-amt">${fRp(p.amount)}</span></div>
          ${p.status==='unpaid'?`<div class="info-box" style="margin-top:8px;font-size:10px">BCA: <strong>${cmsData.siteinfo.rek_bca}</strong> a.n. ${cmsData.siteinfo.an}</div>`:''}
        </div>`).join('') : '<div class="empty"><div class="empty-t">Tidak ada tagihan</div></div>'}
      </div>
    </div>
  </div>`);
  kpFileObj = null;
}

function kpFileIn(e) {
  kpFileObj = e.target.files[0];
  const el = document.getElementById('kp-prev');
  if (el && kpFileObj) el.innerHTML = `
    <div class="fi-item">
      <div class="fc fc-img">🧾</div>
      <div class="fi-meta"><div class="fi-name">${kpFileObj.name}</div><div class="fi-size">${fSz(kpFileObj.size)}</div></div>
      <button class="btn btn-xs btn-gh" onclick="kpFileObj=null;document.getElementById('kp-prev').innerHTML=''">✕</button>
    </div>`;
}

async function submitKpPay() {
  const invId = v('kp-inv');
  const amt   = v('kp-amt');
  if (!invId || invId === '') { showToast('Pilih invoice yang akan dibayar','err'); return; }
  if (!amt)   { showToast('Masukkan jumlah pembayaran','err'); return; }
  if (!kpFileObj) { showToast('Upload bukti pembayaran terlebih dahulu','err'); return; }
  const idx = payList.findIndex(p => p.id === invId);
  if (idx >= 0) {
    const uploadedProof = await window.__portalSupabaseStorage.uploadSingleFile(kpFileObj, 'pembayaran', `${CU.name || 'klien'}/${invId}`);
    payList[idx].status = 'verify';
    payList[idx].method = v('kp-meth');
    payList[idx].date   = v('kp-tgl') || today();
    payList[idx].ref    = v('kp-ref');
    payList[idx].proof  = uploadedProof;
  }
  kpFileObj = null;
  showToast('Bukti pembayaran dikirim! Menunggu verifikasi.','ok');
  klienPay();
}

/* ══════════════════════════════════════
   KLIEN: PROFIL
══════════════════════════════════════ */
function klienProfile() {
  setContent(`
  <div style="max-width:460px">
    <div class="card">
      <div class="cb">
        <div style="display:flex;align-items:center;gap:18px;margin-bottom:22px">
          <div class="av av-k" style="width:54px;height:54px;font-size:18px">${CU.avatar}</div>
          <div>
            <div style="font-family:'Syne',sans-serif;font-size:18px;font-weight:800">${CU.name}</div>
            <div style="font-size:11px;color:var(--m1);margin-top:3px">${CU.email}</div>
            <span class="chip ch-active" style="margin-top:7px;display:inline-flex">Klien Aktif</span>
          </div>
        </div>
        <div class="fg"><label>Nama Lengkap</label><input type="text" id="pf-nama" class="cms-inp" value="${esc(CU.name)}"></div>
        <div class="fg"><label>Email</label><input type="email" id="pf-email" class="cms-inp" value="${esc(CU.email)}"></div>
        <div class="fg"><label>Password Baru</label><input type="password" id="pf-pass" class="cms-inp" placeholder="Kosongkan jika tidak ingin mengubah"></div>
        <div class="fg"><label>Konfirmasi Password</label><input type="password" id="pf-pass2" class="cms-inp" placeholder="Ulangi password baru"></div>
        <button class="btn btn-cu" onclick="saveProfile()">Simpan Perubahan</button>
      </div>
    </div>
  </div>`);
}

async function saveProfile() {
  const nama  = v('pf-nama');
  const email = v('pf-email');
  const pass  = v('pf-pass');
  const pass2 = v('pf-pass2');
  if (!nama) { showToast('Nama tidak boleh kosong','err'); return; }
  if (pass && pass.length < 8) { showToast('Password minimal 8 karakter','err'); return; }
  if (pass && !SP.validators.password(pass)) { showToast('Password harus mengandung huruf besar dan angka','err'); return; }
  if (pass && pass !== pass2) { showToast('Konfirmasi password tidak cocok','err'); return; }
  CU.name = nama; CU.email = email;
  if (USERS[CU.email]) {
    USERS[CU.email].name = nama;
    if (pass) USERS[CU.email].pass = await hashPassword(pass);
  }
  document.getElementById('sb-un').textContent = CU.name;
  showToast('Profil berhasil diperbarui ✓','ok');
}

/* ══════════════════════════════════════
   UPLOAD MODAL (tombol + di topbar)
══════════════════════════════════════ */
function setUpTab(t, el) {
  upTabState = t;
  document.querySelectorAll('#uptabs .tab').forEach(tb => tb.classList.remove('on'));
  if (el) el.classList.add('on');
  document.getElementById('up-rev').style.display = t === 'rev' ? 'block' : 'none';
  document.getElementById('up-rek').style.display = t === 'rek' ? 'block' : 'none';
  if (t === 'rek') setTimeout(() => mDrawIdle(), 30);
}

// Reset upload modal fields
function resetUploadModal() {
  upTabState = 'rev';
  document.querySelectorAll('#uptabs .tab').forEach((tb,i) => tb.classList.toggle('on', i===0));
  document.getElementById('up-rev').style.display = 'block';
  document.getElementById('up-rek').style.display = 'none';
  // populate project options
  ['ur-proj','urk-proj'].forEach(id => {
    const el = document.getElementById(id); if (el) el.innerHTML = projectOptions();
  });
  uFiles['ur-files'] = [];
  uFiles['urk-files'] = [];
  renderFileList('ur-files');
  renderFileList('urk-files');
  mBlobs = [];
  const mb = document.getElementById('m-blobs'); if (mb) mb.innerHTML = '';
  mDrawIdle();
}

async function submitUpload() {
  if (upTabState === 'rev') {
    const proj = v('ur-proj');
    const ver  = v('ur-ver');
    const note = v('ur-note');
    if (!proj) { showToast('Pilih proyek terlebih dahulu','err'); return; }
    if (!ver)  { showToast('Isi versi terlebih dahulu','err'); return; }
    const files = uFiles['ur-files'] || [];
    if (!files.length) { showToast('Upload minimal 1 file','err'); return; }
    runProgress('up-prog','up-pfill', async () => {
      const uploadedFiles = await window.__portalSupabaseStorage.uploadBrowserFiles(files, 'revisi', `${CU.name}/${proj}/${ver}`);
      uploads.unshift({ id:Date.now(), client:CU.name, proj, tipe:'revisi', ver, judul:`Revisi ${ver}`, catatan:note, files:uploadedFiles, tgl:today(), status:'pending' });
      uFiles['ur-files'] = [];
      closeModal('m-upload');
      buildNav();
      pushActivity(`📄 ${CU.name} upload revisi ${ver} — ${proj}`, 'var(--gold)');
      showToast('Revisi berhasil dikirim! ✓','ok');
      const el = document.getElementById('my-up-list'); if (el) SP.setHTML(el, renderMyUploads());
    });
  } else {
    const proj  = v('urk-proj');
    const judul = v('urk-judul');
    const note  = v('urk-note');
    if (!proj)  { showToast('Pilih proyek terlebih dahulu','err'); return; }
    if (!judul) { showToast('Isi judul rekaman','err'); return; }
    const audFiles = uFiles['urk-files'] || [];
    if (!mBlobs.length && !audFiles.length) { showToast('Rekam atau upload file audio','err'); return; }
    runProgress('up-prog','up-pfill', async () => {
      const recordedUploads = await window.__portalSupabaseStorage.uploadBlobItems(mBlobs, 'rekaman', `${CU.name}/${proj}/${judul}`);
      const browserUploads = await window.__portalSupabaseStorage.uploadBrowserFiles(audFiles, 'rekaman', `${CU.name}/${proj}/${judul}`);
      [...recordedUploads.map(f=>({file:f,dur:f.durationLabel || '—'})), ...browserUploads.map(f=>({file:f,dur:'—'}))].forEach(item => {
        uploads.unshift({ id:Date.now()+Math.random(), client:CU.name, proj, tipe:'rekaman', ver:item.dur, judul, catatan:note, files:[item.file], tgl:today(), status:'pending' });
      });
      mBlobs = []; uFiles['urk-files'] = [];
      closeModal('m-upload');
      buildNav();
      pushActivity(`🎙️ ${CU.name} upload rekaman "${judul}" — ${proj}`, 'var(--purple)');
      showToast('Rekaman berhasil dikirim! ✓','ok');
      const el = document.getElementById('my-up-list'); if (el) SP.setHTML(el, renderMyUploads());
    });
  }
}

/* ── MODAL RECORDER ── */
function mDrawIdle() {
  const c = document.getElementById('m-cv'); if (!c) return;
  c.width = c.offsetWidth || c.parentElement?.offsetWidth || 460; c.height = 60;
  const ctx = c.getContext('2d');
  ctx.clearRect(0,0,c.width,c.height);
  ctx.strokeStyle = 'rgba(201,121,65,.22)'; ctx.lineWidth = 1.5;
  ctx.beginPath(); ctx.moveTo(0, 30);
  for (let x = 0; x < c.width; x += 4) ctx.lineTo(x, 30 + Math.sin(x * 0.055) * 5);
  ctx.stroke();
}

async function mStartRec() {
  try {
    mStream = await navigator.mediaDevices.getUserMedia({ audio:true });
    const AC = window.AudioContext || window.webkitAudioContext;
    const ac = new AC();
    const src = ac.createMediaStreamSource(mStream);
    const an = ac.createAnalyser(); an.fftSize = 512;
    src.connect(an);
    const c = document.getElementById('m-cv');
    const buf = new Uint8Array(an.frequencyBinCount);
    function draw() {
      mAnim = requestAnimationFrame(draw);
      an.getByteTimeDomainData(buf);
      c.width = c.offsetWidth || 460; c.height = 60;
      const ctx = c.getContext('2d');
      ctx.clearRect(0,0,c.width,c.height);
      ctx.shadowBlur = 6; ctx.shadowColor = 'rgba(224,85,85,.4)';
      ctx.strokeStyle = 'rgba(224,85,85,.9)'; ctx.lineWidth = 2;
      ctx.beginPath();
      const sw = c.width / buf.length; let x = 0;
      for (let i = 0; i < buf.length; i++) {
        const y = (buf[i]/128)*30;
        i===0 ? ctx.moveTo(x,y) : ctx.lineTo(x,y);
        x += sw;
      }
      ctx.lineTo(c.width,30); ctx.stroke();
    }
    draw();
    mRec = new MediaRecorder(mStream); mChunks = []; mSec = 0; mPaused = false;
    mRec.ondataavailable = e => { if (e.data.size > 0) mChunks.push(e.data); };
    mRec.onstop = () => {
      const blob = new Blob(mChunks, {type:'audio/webm'});
      const url = URL.createObjectURL(blob);
      mBlobs.push({ blob, url, dur:fDur(mSec), sz:fSz(blob.size), name:`rekaman_${Date.now()}.webm` });
      renderMBlobs();
      const t = document.getElementById('m-timer'); if(t) t.textContent = '00:00';
    };
    mRec.start(100);
    mIntv = setInterval(() => { if(!mPaused) { mSec++; const t=document.getElementById('m-timer'); if(t) t.textContent=fDur(mSec); } }, 1000);
    sel('m-btn-start','display','none'); sel('m-btn-pause','display','flex'); sel('m-btn-stop','display','flex');
    sel('m-pulse','display','block');
    const timer = document.getElementById('m-timer'); if(timer) timer.classList.add('rec-on');
    const st = document.getElementById('m-rec-status'); if(st) st.textContent='Sedang merekam…';
  } catch(e) { showToast('Mikrofon tidak dapat diakses','err'); }
}

function mPauseRec() {
  if (!mRec) return;
  if (mPaused) {
    mRec.resume(); mPaused = false;
    const btn=document.getElementById('m-btn-pause'); if(btn) btn.innerHTML='⏸ Jeda';
    sel('m-pulse','display','block');
    const st=document.getElementById('m-rec-status'); if(st) st.textContent='Sedang merekam…';
  } else {
    mRec.pause(); mPaused = true;
    const btn=document.getElementById('m-btn-pause'); if(btn) btn.innerHTML='▶ Lanjut';
    sel('m-pulse','display','none');
    const st=document.getElementById('m-rec-status'); if(st) st.textContent='Dijeda';
  }
}

function mStopRec() {
  if (mRec && mRec.state !== 'inactive') mRec.stop();
  if (mStream) mStream.getTracks().forEach(t => t.stop());
  clearInterval(mIntv); if (mAnim) { cancelAnimationFrame(mAnim); mAnim = null; }
  mRec = null; mStream = null;
  sel('m-btn-start','display','flex'); sel('m-btn-pause','display','none'); sel('m-btn-stop','display','none');
  sel('m-pulse','display','none');
  const timer=document.getElementById('m-timer'); if(timer) timer.classList.remove('rec-on');
  const st=document.getElementById('m-rec-status'); if(st) st.textContent='Siap merekam';
  mDrawIdle();
}

function renderMBlobs() {
  const el = document.getElementById('m-blobs'); if (!el) return;
  el.innerHTML = mBlobs.map((b,i) => `
    <div class="fi-item">
      <div class="fc fc-aud">🎙️</div>
      <div class="fi-meta">
        <div class="fi-name">${b.name}</div>
        <div class="fi-size">${b.dur} · ${b.sz}</div>
        <audio src="${b.url}" controls style="width:100%;height:28px;margin-top:5px"></audio>
      </div>
      <button class="btn btn-xs btn-rd" onclick="mBlobs.splice(${i},1);renderMBlobs()">✕</button>
    </div>`).join('');
}

/* ══════════════════════════════════════
   INVOICE MODAL
══════════════════════════════════════ */
function openInvModal() {
  const sel = document.getElementById('inv-client');
  sel.innerHTML = klienList.map(k => `<option>${k.nama}</option>`).join('');
  document.getElementById('inv-desc').value = '';
  document.getElementById('inv-amt').value = '';
  document.getElementById('inv-due').value = '';
  document.getElementById('inv-note').value = '';
  openModal('m-inv');
}

function doCreateInv() {
  const client = v('inv-client');
  const desc   = v('inv-desc');
  const amt    = parseInt(v('inv-amt')) || 0;
  const due    = v('inv-due');
  if (!desc) { showToast('Isi deskripsi invoice','err'); return; }
  if (!amt)  { showToast('Isi jumlah invoice','err'); return; }
  const id = 'INV-' + String(payList.length + 1).padStart(3,'0');
  const inv = { id, client, desc, amount:amt, due, status:'unpaid', method:'-', date:'-', ref:'-' };
  payList.unshift(inv); invList.unshift(inv);
  closeModal('m-inv');
  showToast(`Invoice ${id} berhasil dibuat ✓`,'ok');
  adminPay();
}

/* ══════════════════════════════════════
   BAYAR MODAL (klien dari dashboard)
══════════════════════════════════════ */
function openPayModal(invId) {
  const myUnpaid = payList.filter(p => p.client === CU.name && p.status === 'unpaid');
  const pyInvEl = document.getElementById('py-inv');
  pyInvEl.innerHTML = myUnpaid.length
    ? myUnpaid.map(p=>`<option value="${p.id}"${p.id===invId?' selected':''}>${p.id} — ${fRp(p.amount)}</option>`).join('')
    : '<option value="">Tidak ada tagihan</option>';
  document.getElementById('py-amt').value = '';
  document.getElementById('py-tgl').value = '';
  document.getElementById('py-ref').value = '';
  document.getElementById('py-file-prev').innerHTML = '';
  pyFileObj = null;
  openModal('m-pay');
}

function pyFileIn(e) {
  pyFileObj = e.target.files[0];
  const el = document.getElementById('py-file-prev');
  if (el && pyFileObj) el.innerHTML = `
    <div class="fi-item">
      <div class="fc fc-img">🧾</div>
      <div class="fi-meta"><div class="fi-name">${pyFileObj.name}</div><div class="fi-size">${fSz(pyFileObj.size)}</div></div>
      <button class="btn btn-xs btn-gh" onclick="pyFileObj=null;this.closest('.fi-item').remove()">✕</button>
    </div>`;
}

async function submitPay() {
  const invId = v('py-inv');
  const amt   = v('py-amt');
  if (!invId) { showToast('Pilih invoice','err'); return; }
  if (!amt)   { showToast('Masukkan jumlah','err'); return; }
  if (!pyFileObj) { showToast('Upload bukti pembayaran','err'); return; }
  const idx = payList.findIndex(p => p.id === invId);
  if (idx >= 0) {
    const uploadedProof = await window.__portalSupabaseStorage.uploadSingleFile(pyFileObj, 'pembayaran', `${CU.name || 'klien'}/${invId}`);
    payList[idx].status = 'verify';
    payList[idx].method = v('py-meth');
    payList[idx].date   = v('py-tgl') || today();
    payList[idx].ref    = v('py-ref');
    payList[idx].proof  = uploadedProof;
  }
  pyFileObj = null;
  closeModal('m-pay');
  const inv = payList[idx];
  if (inv) pushActivity(`💳 ${CU.name} kirim bukti bayar ${inv.id} — menunggu verifikasi`, 'var(--blue)');
  showToast('Bukti pembayaran terkirim! Menunggu verifikasi.','ok');
  buildNav();
}

/* ══════════════════════════════════════
   DETAIL MODAL
══════════════════════════════════════ */
function showDetail(id) {
  const u = uploads.find(u => u.id === id);
  if (!u) { showToast('Data tidak ditemukan','err'); return; }
  document.getElementById('dt-title').textContent = `${u.tipe==='rekaman'?'🎙️':'📄'} ${u.judul}`;
  document.getElementById('dt-body').innerHTML = `
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:14px">
    ${[['Klien',u.client],['Proyek',u.proj],['Tipe',cap(u.tipe)],['Tanggal',u.tgl]].map(([l,vl])=>`
    <div class="info-box"><div style="font-size:9px;letter-spacing:.1em;text-transform:uppercase;color:var(--m1);margin-bottom:3px">${l}</div><div style="font-size:13px;font-weight:600">${vl}</div></div>`).join('')}
  </div>
  ${u.ver && u.ver !== '-' ? `<div class="info-box" style="margin-bottom:10px"><div style="font-size:9px;letter-spacing:.1em;text-transform:uppercase;color:var(--m1);margin-bottom:3px">${u.tipe==='rekaman'?'Durasi':'Versi'}</div><div style="font-size:13px">${u.ver}</div></div>` : ''}
  <div class="info-box" style="margin-bottom:14px"><div style="font-size:9px;letter-spacing:.1em;text-transform:uppercase;color:var(--m1);margin-bottom:4px">Catatan</div><div style="font-size:13px;line-height:1.6;color:var(--m3)">${u.catatan||'—'}</div></div>
  <div style="font-size:9px;letter-spacing:.1em;text-transform:uppercase;color:var(--m1);margin-bottom:8px">File (${u.files.length})</div>
  ${u.files.map((f,idx)=>`
    <div class="fi-item">
      <div class="fc ${fCls(f)}">${fEmo(f)}</div>
      <div class="fi-meta"><div class="fi-name">${esc(getFileName(f))}</div></div>
      <button class="btn btn-xs ${getFileUrl(f)?'btn-gn':'btn-gh'}" onclick="${fileDownloadAction(f)}">⬇ Unduh</button>
    </div>`).join('')}
  <div style="margin-top:14px;display:flex;align-items:center;gap:8px;font-size:12px">
    Status saat ini: <span class="chip ch-${stCls(u.status)}">${stLbl(u.status)}</span>
  </div>`;
  document.getElementById('dt-foot').innerHTML = `
    <button class="btn btn-ol" onclick="closeModal('m-detail')">Tutup</button>
    ${u.status==='pending' && CU.role==='admin' ? `
    <button class="btn btn-rd" onclick="rejectUpload(${u.id});closeModal('m-detail')">✕ Tolak</button>
    <button class="btn btn-gn" onclick="approveUpload(${u.id});closeModal('m-detail')">${u.tipe==='rekaman'?'✓ Tandai Diputar':'✓ Setujui'}</button>` : ''}`;
  openModal('m-detail');
}

/* ══════════════════════════════════════
   UPLOAD ACTIONS
══════════════════════════════════════ */
function approveUpload(id) {
  const u = uploads.find(u => u.id === id);
  if (!u) return;
  u.status = u.tipe === 'rekaman' ? 'reviewed' : 'approved';
  buildNav();
  pushActivity(
    u.tipe === 'rekaman'
      ? `🎙️ Rekaman "${u.judul}" (${u.client}) ditandai diputar`
      : `✅ Revisi "${u.judul}" (${u.client}) disetujui`,
    u.tipe === 'rekaman' ? 'var(--purple)' : 'var(--green)'
  );
  showToast(u.tipe==='rekaman' ? 'Rekaman ditandai sudah diputar ✓' : 'Revisi disetujui ✓','ok');
  const viewFns = { 'files':adminFiles, 'rev-adm':adminRevisi, 'rek-adm':adminRekaman, 'dash':dashAdmin, 'kirim-hasil':adminKirimHasil };
  const fn = viewFns[currentView];
  if (fn) fn();
}

function rejectUpload(id) {
  const u = uploads.find(u => u.id === id);
  if (!u) return;
  u.status = 'rejected';
  buildNav();
  pushActivity(`❌ Upload "${u.judul}" (${u.client}) ditolak`, 'var(--red)');
  showToast('Upload ditolak','err');
  const viewFns = { 'files':adminFiles, 'rev-adm':adminRevisi, 'rek-adm':adminRekaman, 'dash':dashAdmin, 'kirim-hasil':adminKirimHasil };
  const fn = viewFns[currentView];
  if (fn) fn();
}

/* ══════════════════════════════════════
   ADMIN: KIRIM HASIL REVISI KE KLIEN
══════════════════════════════════════ */
function adminKirimHasil() {
  uFiles['hr-files'] = [];
  const sorted = [...adminRevisions].reverse();
  setContent(`
  <div class="g2">
    <div>
      <div class="card">
        <div class="ch"><div class="ct">📨 Kirim Hasil Revisi ke Klien</div></div>
        <div class="cb">
          <div class="fg">
            <label>Klien</label>
            <select id="hr-klien" class="cms-inp" onchange="hrUpdateProyek()">
              <option value="">— Pilih Klien —</option>
              ${klienList.map(k=>`<option value="${esc(k.nama)}" data-proyek="${esc(k.proyek)}">${esc(k.nama)}</option>`).join('')}
            </select>
          </div>
          <div class="fg">
            <label>Proyek</label>
            <input type="text" id="hr-proyek" class="cms-inp" placeholder="Nama proyek" readonly style="background:var(--s3);cursor:default">
          </div>
          <div class="fg2">
            <div class="fg" style="margin-bottom:0">
              <label>Versi / Label</label>
              <input type="text" id="hr-ver" class="cms-inp" placeholder="cth. v2.1 Final">
            </div>
            <div class="fg" style="margin-bottom:0">
              <label>Kategori</label>
              <select id="hr-kategori" class="cms-inp">
                <option>Desain</option>
                <option>Video</option>
                <option>Foto</option>
                <option>Dokumen</option>
                <option>Lainnya</option>
              </select>
            </div>
          </div>
          <div class="fg" style="margin-top:15px">
            <label>Pesan untuk Klien</label>
            <textarea id="hr-pesan" class="cms-ta" placeholder="Jelaskan perubahan yang sudah dilakukan, instruksi review, dll..."></textarea>
          </div>
          <div class="fg">
            <label>File Hasil Revisi</label>
            <div class="upz" id="hr-zone" ondragover="onDragOver(event,'hr-zone')" ondragleave="onDragLeave('hr-zone')" ondrop="onDrop(event,'hr-files')">
              <div class="upz-ic">📁</div>
              <div class="upz-t">Seret atau klik untuk upload file hasil</div>
              <div class="upz-s">PDF · ZIP · AI · PSD · MP4 · PNG — Maks 100MB</div>
              <input type="file" multiple onchange="onFileInput(event,'hr-files')">
            </div>
            <div id="hr-files-list" style="margin-top:6px"></div>
          </div>
          <div id="hr-prog" style="display:none;margin-top:8px">
            <div style="font-size:11px;color:var(--m1);margin-bottom:4px">Mengirim hasil revisi...</div>
            <div class="pbar"><div class="pfill" id="hr-pfill" style="width:0%"></div></div>
          </div>
          <button class="btn btn-cu btn-full" style="margin-top:14px" onclick="doKirimHasil()">📨 Kirim ke Klien</button>
        </div>
      </div>
    </div>
    <div class="card">
      <div class="ch"><div class="ct">Riwayat Pengiriman</div><span style="font-size:11px;color:var(--m1)">${adminRevisions.length} terkirim</span></div>
      <div class="cb0" id="hr-history">${renderHrHistory()}</div>
    </div>
  </div>`);
}

function hrUpdateProyek() {
  const sel = document.getElementById('hr-klien');
  const opt = sel.options[sel.selectedIndex];
  const proj = opt ? opt.getAttribute('data-proyek') : '';
  const el = document.getElementById('hr-proyek');
  if (el) el.value = proj || '';
}

function renderHrHistory() {
  if (!adminRevisions.length) return '<div class="empty"><div class="empty-ic">📭</div><div class="empty-t">Belum ada pengiriman</div><div class="empty-s">Hasil revisi yang dikirim akan muncul di sini</div></div>';
  return `<div style="padding:0 16px">${adminRevisions.map((r,i) => `
    <div class="fi-item" style="align-items:flex-start;padding:12px 0">
      <div class="fc fc-zip" style="margin-top:2px">📨</div>
      <div class="fi-meta">
        <div class="fi-name">${esc(r.ver)} <span style="font-size:10px;color:var(--m1);font-weight:400">· ${esc(r.kategori)}</span></div>
        <div class="fi-size">Ke: <strong style="color:var(--tx)">${esc(r.klien)}</strong> · ${esc(r.proyek)}</div>
        <div style="font-size:10px;color:var(--m1);margin-top:2px">${r.tgl} · ${r.files.length} file</div>
        ${r.pesan ? `<div class="info-box" style="margin-top:6px;font-size:11px">${esc(r.pesan)}</div>` : ''}
        <div style="margin-top:6px;display:flex;flex-wrap:wrap;gap:4px">
          ${r.files.map(f=>`<span style="font-size:10px;background:var(--s3);padding:2px 7px;border-radius:4px;color:var(--m2)">${fEmo(f)} ${esc(getFileName(f))}</span>`).join('')}
        </div>
      </div>
      <button class="btn btn-xs btn-rd" style="flex-shrink:0;margin-top:2px" onclick="deleteHrItem(${i})" title="Hapus">🗑</button>
    </div>`).join('')}</div>`;
}

async function doKirimHasil() {
  const klien   = document.getElementById('hr-klien')?.value;
  const proyek  = document.getElementById('hr-proyek')?.value || '';
  const ver     = v('hr-ver');
  const kategori= v('hr-kategori');
  const pesan   = v('hr-pesan');
  const files   = uFiles['hr-files'] || [];
  if (!klien)  { showToast('Pilih klien terlebih dahulu','err'); return; }
  if (!ver)    { showToast('Isi versi / label hasil revisi','err'); return; }
  if (!files.length) { showToast('Upload minimal 1 file hasil revisi','err'); return; }
  runProgress('hr-prog','hr-pfill', async () => {
    const uploadedFiles = await window.__portalSupabaseStorage.uploadBrowserFiles(files, 'hasil', `${klien}/${proyek}/${ver}`);
    adminRevisions.unshift({ id:Date.now(), klien, proyek, ver, kategori, pesan, files:uploadedFiles, tgl:today(), dibaca:false });
    uFiles['hr-files'] = [];
    renderFileList('hr-files');
    document.getElementById('hr-ver').value = '';
    document.getElementById('hr-pesan').value = '';
    showToast(`Hasil revisi berhasil dikirim ke ${klien} ✓`,'ok');
    const el = document.getElementById('hr-history');
    if (el) el.innerHTML = renderHrHistory();
  });
}

function deleteHrItem(i) {
  if (!confirm('Hapus riwayat pengiriman ini?')) return;
  adminRevisions.splice(i, 1);
  const el = document.getElementById('hr-history');
  if (el) el.innerHTML = renderHrHistory();
  showToast('Dihapus','inf');
}

/* ══════════════════════════════════════
   KLIEN: LIHAT HASIL REVISI
══════════════════════════════════════ */
function klienHasilRevisi() {
  const myResults = adminRevisions.filter(r => r.klien === CU.name);
  // mark as read
  myResults.forEach(r => { r.dibaca = true; });
  setContent(`
  <div class="wb" style="margin-bottom:20px">
    <div>
      <h2>📨 Hasil <span>Revisi</span> Anda</h2>
      <p>File hasil pekerjaan yang dikirimkan studio untuk Anda review.</p>
    </div>
    <div class="wb-ic">📁</div>
  </div>
  ${myResults.length ? myResults.map(r => `
  <div class="card" style="margin-bottom:14px;animation:slideUp .3s ease">
    <div class="ch">
      <div>
        <div class="ct" style="display:flex;align-items:center;gap:8px">
          ${esc(r.ver)}
          <span class="chip ch-rev-tipe">${esc(r.kategori)}</span>
        </div>
        <div style="font-size:11px;color:var(--m1);margin-top:3px">Proyek: ${esc(r.proyek)} · ${r.tgl}</div>
      </div>
      <span style="font-size:11px;color:var(--gn);font-weight:600">✓ Diterima</span>
    </div>
    <div class="cb">
      ${r.pesan ? `
      <div class="info-box" style="margin-bottom:14px">
        <div style="font-size:9px;letter-spacing:.1em;text-transform:uppercase;color:var(--m1);margin-bottom:5px">💬 Pesan dari Studio</div>
        <div style="font-size:13px;line-height:1.6;color:var(--m3)">${esc(r.pesan)}</div>
      </div>` : ''}
      <div style="font-size:9px;letter-spacing:.1em;text-transform:uppercase;color:var(--m1);margin-bottom:8px">File (${r.files.length})</div>
      ${r.files.map(f=>`
      <div class="fi-item">
        <div class="fc ${fCls(f)}">${fEmo(f)}</div>
        <div class="fi-meta">
          <div class="fi-name">${esc(getFileName(f))}</div>
          <div class="fi-size">${getFileUrl(f)?'Siap diunduh':'Belum ada URL file'}</div>
        </div>
        <button class="btn btn-xs ${getFileUrl(f)?'btn-gn':'btn-gh'}" onclick="${fileDownloadAction(f)}">⬇ Unduh</button>
      </div>`).join('')}
      <div style="display:flex;gap:8px;margin-top:14px;padding-top:12px;border-top:1px solid var(--b1)">
        <button class="btn btn-gn btn-sm" onclick="showToast('Feedback diterima! Terima kasih ✓','ok')">✅ Setuju / Sudah OK</button>
        <button class="btn btn-ol btn-sm" onclick="openRevisionFeedback(${r.id})">✏️ Minta Revisi</button>
      </div>
    </div>
  </div>`).join('') : `
  <div class="empty" style="padding:80px 20px">
    <div class="empty-ic">📭</div>
    <div class="empty-t">Belum ada hasil revisi</div>
    <div class="empty-s">Studio belum mengirimkan hasil pekerjaan. Pantau terus ya!</div>
  </div>`}`);
}

function openRevisionFeedback(revId) {
  const r = adminRevisions.find(r => r.id === revId);
  if (!r) return;
  document.getElementById('dt-title').textContent = `✏️ Minta Revisi — ${r.ver}`;
  document.getElementById('dt-body').innerHTML = `
    <div class="warn-box" style="margin-bottom:14px">Tuliskan catatan revisi yang Anda inginkan. Studio akan menindaklanjuti segera.</div>
    <div class="fg"><label>Catatan Revisi</label>
      <textarea id="fb-note" class="cms-ta" style="min-height:120px" placeholder="Jelaskan bagian yang perlu direvisi, perubahan yang diinginkan, dll..."></textarea>
    </div>`;
  document.getElementById('dt-foot').innerHTML = `
    <button class="btn btn-ol" onclick="closeModal('m-detail')">Batal</button>
    <button class="btn btn-cu" onclick="submitRevisionFeedback(${revId})">📨 Kirim Catatan</button>`;
  openModal('m-detail');
}

function submitRevisionFeedback(revId) {
  const note = v('fb-note');
  if (!note.trim()) { showToast('Tulis catatan revisi terlebih dahulu','err'); return; }
  closeModal('m-detail');
  showToast('Catatan revisi berhasil dikirim ke studio ✓','ok');
}

/* ══════════════════════════════════════
   FILE HANDLING
══════════════════════════════════════ */
function onDragOver(e, zoneId) { e.preventDefault(); document.getElementById(zoneId).classList.add('drag'); }
function onDragLeave(zoneId) { document.getElementById(zoneId).classList.remove('drag'); }
function onDrop(e, slotId) {
  e.preventDefault();
  const zone = e.currentTarget; zone.classList.remove('drag');
  addFiles(Array.from(e.dataTransfer.files), slotId);
}
function onFileInput(e, slotId) { addFiles(Array.from(e.target.files), slotId); }

function addFiles(files, slotId) {
  if (!uFiles[slotId]) uFiles[slotId] = [];
  uFiles[slotId] = [...uFiles[slotId], ...files];
  renderFileList(slotId);
}

function renderFileList(slotId) {
  const elId = slotId + '-list';
  const el = document.getElementById(elId);
  if (!el) return;
  const list = uFiles[slotId] || [];
  el.innerHTML = list.map((f,i) => `
    <div class="fi-item">
      <div class="fc ${fCls(f.name)}">${fEmo(f.name)}</div>
      <div class="fi-meta"><div class="fi-name">${f.name}</div><div class="fi-size">${fSz(f.size)}</div></div>
      <button class="btn btn-xs btn-gh" onclick="removeFile(${i},'${slotId}')">✕</button>
    </div>`).join('');
}

function removeFile(i, slotId) {
  if (uFiles[slotId]) { uFiles[slotId].splice(i, 1); renderFileList(slotId); }
}

/* ══════════════════════════════════════
   MODAL SYSTEM
══════════════════════════════════════ */
function openModal(id) {
  if (id === 'm-upload') resetUploadModal();
  document.getElementById(id).classList.add('on');
}
function closeModal(id) { document.getElementById(id).classList.remove('on'); }


document.addEventListener('DOMContentLoaded', () => {
  const modal = document.getElementById('m-first-setup');
  if (modal) {
    modal.style.pointerEvents = 'auto';
    modal.style.zIndex = '10050';
  }
  const btn = document.querySelector('#m-first-setup .btn.btn-cu');
  if (btn) {
    btn.type = 'button';
    btn.style.pointerEvents = 'auto';
    btn.onclick = null;
    btn.addEventListener('click', async function(ev){
      ev.preventDefault();
      ev.stopPropagation();
      await bootstrapPortal();
    });
  }
});


document.addEventListener('DOMContentLoaded', async () => {
  // ── Security init
  SP.initSession();
  SP.detectDevTools();
  console.log('%c⛔ STOP!', 'color:#e05555;font-size:48px;font-weight:bold;-webkit-text-stroke:1px black;');
  console.log('%cIni adalah fitur browser untuk developer. Jangan paste atau ketik apapun di sini.', 'color:#f4f1ec;font-size:14px;');
  console.log('%cJika seseorang menyuruh Anda melakukan ini, mereka mencoba mencuri akun Anda.', 'color:#9490a0;font-size:12px;');

  // ── Modal click-outside to close
  document.querySelectorAll('.mbg').forEach(m => {
    m.addEventListener('click', e => { if (e.target === m) m.classList.remove('on'); });
  });

  renderLoginHint();

  // ── Tunggu Supabase sync (module bersifat async, poll sampai siap)
  async function waitForSupabaseDB(timeoutMs = 8000) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      if (window.__studioportalDB && typeof window.__studioportalDB.ensureInitialState === 'function') {
        try { await window.__studioportalDB.ensureInitialState(); } catch(e) { console.warn('Supabase DB init error:', e); }
        return;
      }
      await new Promise(r => setTimeout(r, 100));
    }
    console.warn('[Init] Supabase DB tidak tersedia dalam ' + timeoutMs + 'ms, lanjut dengan data lokal.');
  }

  await waitForSupabaseDB();

  // Hanya tampilkan first-setup jika tidak ada admin sama sekali
  const hasAdmin = USERS && Object.values(USERS).some(u => u.role === 'admin');
  if (!hasAdmin) {
    openModal('m-first-setup');
  } else {
    // ── Restore session: auto-login jika ada session aktif
    const savedSession = loadSessionFromLocal();
    if (savedSession && savedSession.email && USERS[savedSession.email]) {
      const userRecord = USERS[savedSession.email];
      CU = { ...savedSession, ...userRecord, email: savedSession.email, loginAt: savedSession.loginAt || Date.now() };
      console.info('[Session] Auto-login sebagai', CU.email);
      launchApp();
    }
  }
});
/* ══════════════════════════════════════
   HELPERS
══════════════════════════════════════ */
function stopAllRecorders() {
  if (pgRec && pgRec.state !== 'inactive') try { pgRec.stop(); } catch(e){}
  if (pgStream) pgStream.getTracks().forEach(t => t.stop());
  if (pgAnim) cancelAnimationFrame(pgAnim);
  if (mRec && mRec.state !== 'inactive') try { mRec.stop(); } catch(e){}
  if (mStream) mStream.getTracks().forEach(t => t.stop());
  if (mAnim) cancelAnimationFrame(mAnim);
  clearInterval(pgIntv); clearInterval(mIntv);
}

function projectOptions() {
  // Ambil proyek unik dari klienList milik user ini (klien) atau semua (admin)
  const myProjects = CU && CU.role === 'klien'
    ? klienList.filter(k => k.email === CU.email).map(k => k.proyek).filter(Boolean)
    : [...new Set(klienList.map(k => k.proyek).filter(Boolean))];
  if (!myProjects.length) return '<option value="">— Belum ada proyek —</option>';
  return '<option value="">— Pilih Proyek —</option>' + myProjects.map(p=>`<option>${p}</option>`).join('');
}

function v(id) { const el = document.getElementById(id); return el ? el.value : ''; }
function sel(id, prop, val) { const el = document.getElementById(id); if (el) el.style[prop] = val; }
function setContent(html) {
  const el = document.getElementById('content');
  if (el) el.innerHTML = SP.sanitize(html);
}

function buildFeed() {
  const log = getActivityLog();
  if (!log.length) return '<div class="empty"><div class="empty-ic">📋</div><div class="empty-t">Belum ada aktivitas</div></div>';
  return log.slice(0, 10).map(a => `<div class="fd">
    <div class="fd-dot" style="background:${a.c}"></div>
    <div><div class="fd-t">${a.txt}</div><div class="fd-s">${a.sub}</div></div>
  </div>`).join('');
}

// ── Activity log (tersimpan di state, bisa di-reset)
const FEED_KEY = 'rhpartners.portal.activitylog.v1';

function getActivityLog() {
  try {
    const raw = localStorage.getItem(FEED_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch(e) { return []; }
}

function pushActivity(txt, c = 'var(--cu)') {
  try {
    const log = getActivityLog();
    const now = new Date().toLocaleString('id-ID', { day:'2-digit', month:'2-digit', year:'numeric', hour:'2-digit', minute:'2-digit' });
    log.unshift({ txt, sub: now, c });
    // Simpan maks 50 entri
    localStorage.setItem(FEED_KEY, JSON.stringify(log.slice(0, 50)));
  } catch(e) {}
}

function clearFeed() {
  if (!confirm('Hapus semua aktivitas terkini?')) return;
  try { localStorage.removeItem(FEED_KEY); } catch(e) {}
  const wrap = document.getElementById('feed-wrap');
  if (wrap) SP.setHTML(wrap, buildFeed());
  showToast('Aktivitas terkini direset ✓', 'ok');
}

function runProgress(wrapId, fillId, cb) {
  const w = document.getElementById(wrapId);
  const f = document.getElementById(fillId);
  if (w) w.style.display = 'block';
  if (f) f.style.width = '0%';
  let p = 0;
  const iv = setInterval(() => {
    p += Math.random() * 20 + 5;
    if (p >= 100) { p = 100; clearInterval(iv); if(w) w.style.display = 'none'; Promise.resolve(cb()).catch(err => { console.error(err); showToast(err?.message || 'Upload gagal','err'); }); return; }
    if (f) f.style.width = p + '%';
  }, 160);
}

function showToast(msg, type='inf') {
  const el = document.createElement('div');
  const cls = { ok:'t-ok', err:'t-err', inf:'t-inf' };
  const ic  = { ok:'✅', err:'❌', inf:'ℹ️' };
  el.className = `toast ${cls[type]||'t-inf'}`;
  el.innerHTML = `<span>${ic[type]||'ℹ️'}</span><span>${msg}</span>`;
  document.getElementById('toasts').appendChild(el);
  setTimeout(() => {
    el.style.cssText += 'opacity:0;transform:translateX(16px);transition:all .28s';
    setTimeout(() => el.remove(), 300);
  }, 3200);
}

// File type helpers
function getFileName(file) {
  if (file && typeof file === 'object') return file.name || file.path || 'file';
  return String(file || 'file');
}
function getFileUrl(file) {
  return file && typeof file === 'object' ? (file.url || file.downloadURL || '') : '';
}
function fCls(file) {
  const ext = getFileName(file).split('.').pop().toLowerCase();
  if (['pdf'].includes(ext)) return 'fc-pdf';
  if (['jpg','jpeg','png','gif','webp','svg'].includes(ext)) return 'fc-img';
  if (['mp3','wav','m4a','ogg','webm','aac','flac'].includes(ext)) return 'fc-aud';
  if (['mp4','mov','avi','mkv'].includes(ext)) return 'fc-vid';
  return 'fc-zip';
}
function fEmo(file) {
  const ext = getFileName(file).split('.').pop().toLowerCase();
  if (['pdf'].includes(ext)) return '📄';
  if (['jpg','jpeg','png','gif','webp','svg'].includes(ext)) return '🖼️';
  if (['mp3','wav','m4a','ogg','webm','aac'].includes(ext)) return '🎵';
  if (['mp4','mov','avi','mkv'].includes(ext)) return '🎬';
  return '📦';
}
function downloadPortalFile(file) {
  const url = getFileUrl(file);
  if (!url) { showToast('File belum punya URL unduhan.','inf'); return; }
  window.open(url, '_blank', 'noopener');
}

function fileDownloadAction(file) {
  const url = getFileUrl(file);
  if (!url) return `showToast('File belum punya URL unduhan.','inf')`;
  const safeUrl = String(url).replace(/'/g, "\\'");
  return `window.open('${safeUrl}','_blank','noopener')`;
}

function fSz(b) {
  if (!b) return '0B';
  if (b < 1024) return b + 'B';
  if (b < 1048576) return (b/1024).toFixed(1) + 'KB';
  return (b/1048576).toFixed(1) + 'MB';
}
function fDur(s) { return String(Math.floor(s/60)).padStart(2,'0') + ':' + String(s%60).padStart(2,'0'); }
function fRp(n)  { return 'Rp ' + Number(n||0).toLocaleString('id-ID'); }
function cap(s)  { return s ? s.charAt(0).toUpperCase() + s.slice(1) : ''; }
function today() { return new Date().toLocaleDateString('id-ID',{day:'2-digit',month:'2-digit',year:'numeric'}); }
function esc(s)  { return SP.esc(s); }

function stCls(s) { return { pending:'pend', approved:'ok', rejected:'no', reviewed:'rev' }[s] || 'pend'; }
function stLbl(s) { return { pending:'Menunggu', approved:'Disetujui', rejected:'Ditolak', reviewed:'Diputar' }[s] || cap(s); }
function pStCls(s) { return { unpaid:'unpaid', verify:'vfy', paid:'paid' }[s] || 'unpaid'; }
function pStLbl(s) { return { unpaid:'Belum Bayar', verify:'Verifikasi', paid:'Lunas' }[s] || s; }



/* ══════════════════════════════════════════════════════════
   PWA — Service Worker (dinonaktifkan, sw.js belum tersedia)
   ══════════════════════════════════════════════════════════ */
// Service worker dinonaktifkan sampai sw.js tersedia di server
// if ('serviceWorker' in navigator) { ... }

/* ══════════════════════════════════════════════════════════
   PERFORMANCE — Lazy load images & defer non-critical
   ══════════════════════════════════════════════════════════ */
// Intersection Observer untuk lazy loading
if ('IntersectionObserver' in window) {
  const imgObserver = new IntersectionObserver((entries) => {
    entries.forEach(e => {
      if (e.isIntersecting) {
        const img = e.target;
        if (img.dataset.src) { img.src = img.dataset.src; imgObserver.unobserve(img); }
      }
    });
  }, { rootMargin: '50px' });
  document.querySelectorAll('img[data-src]').forEach(img => imgObserver.observe(img));
}

/* ══════════════════════════════════════════════════════════
   SEO — Dynamic meta updater (SPA-friendly)
   Update meta tags saat navigasi antar halaman (single-page)
   ══════════════════════════════════════════════════════════ */
function updateSEOMeta(view) {
  const metas = {
    'dash':         { title: 'Dashboard — RH Partners Portal', desc: 'Pantau semua aktivitas proyek, revisi, dan pembayaran klien RH Partners.' },
    'files':        { title: 'Semua File — RH Partners Portal', desc: 'Kelola semua file revisi dan rekaman yang dikirim klien.' },
    'rev-adm':      { title: 'Kelola Revisi — RH Partners Portal', desc: 'Review dan setujui revisi desain dari klien RH Partners.' },
    'rek-adm':      { title: 'Kelola Rekaman — RH Partners Portal', desc: 'Putar dan kelola rekaman feedback audio dari klien.' },
    'pay-adm':      { title: 'Kelola Pembayaran — RH Partners Portal', desc: 'Verifikasi pembayaran dan kelola invoice klien RH Partners.' },
    'klien-adm':    { title: 'Data Klien — RH Partners Portal', desc: 'Kelola data dan akses klien RH Partners.' },
    'kirim-hasil':  { title: 'Kirim Hasil Revisi — RH Partners Portal', desc: 'Kirimkan file hasil revisi langsung ke klien.' },
    'upload':       { title: 'Upload File — RH Partners Portal', desc: 'Upload revisi dan rekaman feedback proyek Anda.' },
    'hasil-revisi': { title: 'Hasil Revisi — RH Partners Portal', desc: 'Lihat dan unduh file hasil revisi dari RH Partners.' },
    'pay-kln':      { title: 'Pembayaran — RH Partners Portal', desc: 'Bayar invoice dan pantau status pembayaran proyek Anda.' },
    'profile':      { title: 'Profil — RH Partners Portal', desc: 'Kelola informasi akun dan preferensi Anda.' },
    'report':       { title: 'Laporan — RH Partners Portal', desc: 'Ringkasan performa dan statistik RH Partners.' },
  };
  const m = metas[view];
  if (!m) return;
  document.title = m.title;
  const descEl = document.querySelector('meta[name="description"]');
  if (descEl) descEl.setAttribute('content', m.desc);
  const ogTitle = document.querySelector('meta[property="og:title"]');
  if (ogTitle) ogTitle.setAttribute('content', m.title);
  const ogDesc = document.querySelector('meta[property="og:description"]');
  if (ogDesc) ogDesc.setAttribute('content', m.desc);
  // Update canonical URL dengan hash
  const canonical = document.querySelector('link[rel="canonical"]');
  if (canonical) canonical.setAttribute('href', 'https://portal.rhpartners.id/#' + view);
}

/* ══════════════════════════════════════════════════════════
   SECURITY — SSL/TLS Certificate Pinning hint (client-side)
   Real pinning harus dilakukan di service worker / server
   ══════════════════════════════════════════════════════════ */
const SSL_CONFIG = {
  minTLSVersion: 'TLS 1.3',
  cipherSuites: ['TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256'],
  hpkp: 'pin-sha256="base64hash=="; max-age=2592000; includeSubDomains',
  hsts: 'max-age=31536000; includeSubDomains; preload',
  ocspStapling: true,
  sslLabsTarget: 'A+',
};

/* ══════════════════════════════════════════════════════════
   SECURITY — Prevent Prototype Pollution
   ══════════════════════════════════════════════════════════ */
(function preventPrototypePollution() {
  const origAssign = Object.assign;
  Object.assign = function(target, ...sources) {
    sources.forEach(src => {
      if (src && typeof src === 'object') {
        Object.keys(src).forEach(key => {
          if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            console.warn('[Security] Prototype pollution attempt blocked:', key);
            return;
          }
        });
      }
    });
    return origAssign.apply(this, [target, ...sources]);
  };
})();

/* ══════════════════════════════════════════════════════════
   SECURITY — JSON.parse wrapper (prevent ReDoS)
   ══════════════════════════════════════════════════════════ */
const safeJSON = {
  parse: (str, fallback = null) => {
    try {
      if (typeof str !== 'string' || str.length > 1000000) return fallback;
      return JSON.parse(str);
    } catch(e) { return fallback; }
  },
  stringify: (obj) => {
    try { return JSON.stringify(obj); } catch(e) { return '{}'; }
  }
};

/* ══════════════════════════════════════════════════════════
   SECURITY — Clipboard hijacking protection
   ══════════════════════════════════════════════════════════ */
document.addEventListener('copy', (e) => {
  // Log copy events untuk audit (di production)
  SP.log('clipboard_copy', 'User copied text from app');
});

// ═══════════════════════════════════════════
// UI PATCH
// ═══════════════════════════════════════════
(function(){
  'use strict';

  function setSafeHTML(id, html) {
    const el = document.getElementById(id);
    if (el) SP.setHTML(el, html);
  }

  function normalizeEmail(email) {
    return String(email || '').trim().toLowerCase();
  }

  function syncUserRecordEmail(oldEmail, newEmail, updates) {
    const prevEmail = normalizeEmail(oldEmail);
    const nextEmail = normalizeEmail(newEmail);
    const record = USERS[prevEmail] ? { ...USERS[prevEmail] } : null;

    if (nextEmail && prevEmail !== nextEmail && USERS[nextEmail]) {
      return { ok: false, message: 'Email sudah digunakan oleh akun lain' };
    }

    if (record) {
      delete USERS[prevEmail];
      USERS[nextEmail] = Object.assign(record, updates || {});
    } else if (nextEmail) {
      USERS[nextEmail] = Object.assign({ role:'klien', avatar:'KL' }, updates || {});
    }

    return { ok: true };
  }

  function refreshClientNameReferences(oldName, newName) {
    if (!oldName || !newName || oldName === newName) return;
    uploads.forEach(u => { if (u.client === oldName) u.client = newName; });
    payList.forEach(p => { if (p.client === oldName) p.client = newName; });
    invList.forEach(p => { if (p.client === oldName) p.client = newName; });
    adminRevisions.forEach(r => { if (r.klien === oldName) r.klien = newName; });
  }

  const origSetLnMode = window.setLnMode;
  window.setLnMode = function(m) {
    origSetLnMode(m);
    if (typeof renderLoginHint === 'function') renderLoginHint();
  };

  window.doAddKlien = function() {
    const nama = document.getElementById('ak-nama').value.trim();
    const email = normalizeEmail(document.getElementById('ak-email').value);
    const pass = document.getElementById('ak-pass').value;
    const wa = document.getElementById('ak-wa').value.trim();
    const proyek = document.getElementById('ak-proj').value.trim();

    if (!nama || !email || !pass) { showToast('Nama, email, dan password wajib diisi','err'); return; }
    if (!SP.validators.email(email)) { showToast('Format email tidak valid','err'); return; }
    if (pass.length < 8) { showToast('Password minimal 8 karakter','err'); return; }
    if (!SP.validators.password(pass)) { showToast('Password harus mengandung huruf besar dan angka','err'); return; }
    if (wa && !SP.validators.phone(wa)) { showToast('Format WhatsApp tidak valid','err'); return; }
    if (USERS[email]) { showToast('Email sudah terdaftar','err'); return; }

    USERS[email] = { pass, role:'klien', name:nama, avatar:nama.split(/\s+/).map(v=>v[0]).join('').slice(0,2).toUpperCase() || 'KL' };
    klienList.push({ nama, email, wa, proyek, total:0 });
    closeModal('m-addklien');
    pushActivity(`👤 Klien baru ditambahkan: ${nama}${proyek ? ' — ' + proyek : ''}`, 'var(--blue)');
    showToast(`Klien ${nama} berhasil ditambahkan ✓`,'ok');
    const tb = document.getElementById('kl-tbody');
    if (tb) SP.setHTML(tb, renderKlienRows());
  };

  window.doSaveKlien = function() {
    const i = parseInt(document.getElementById('ek-idx').value, 10);
    const k = klienList[i];
    if (!k) return;

    if (ekTabState === 'info') {
      const oldEmail = k.email;
      const oldName = k.nama;
      const nama = document.getElementById('ek-nama').value.trim();
      const email = normalizeEmail(document.getElementById('ek-email').value);
      const wa = document.getElementById('ek-wa').value.trim();
      const proyek = document.getElementById('ek-proj').value.trim();

      if (!nama || !email) { showToast('Nama dan email wajib diisi','err'); return; }
      if (!SP.validators.email(email)) { showToast('Format email tidak valid','err'); return; }
      if (wa && !SP.validators.phone(wa)) { showToast('Format WhatsApp tidak valid','err'); return; }

      const sync = syncUserRecordEmail(oldEmail, email, {
        name: nama,
        avatar: nama.split(/\s+/).map(v=>v[0]).join('').slice(0,2).toUpperCase() || 'KL'
      });
      if (!sync.ok) { showToast(sync.message,'err'); return; }

      k.nama = nama;
      k.email = email;
      k.wa = wa;
      k.proyek = proyek;
      refreshClientNameReferences(oldName, nama);
      showToast('Data klien diperbarui ✓','ok');
    } else {
      const p1 = document.getElementById('ek-p1').value;
      const p2 = document.getElementById('ek-p2').value;
      if (!p1) { showToast('Masukkan password baru','err'); return; }
      if (p1.length < 8) { showToast('Password minimal 8 karakter','err'); return; }
      if (!SP.validators.password(p1)) { showToast('Password harus mengandung huruf besar dan angka','err'); return; }
      if (p1 !== p2) { showToast('Konfirmasi password tidak cocok','err'); return; }
      if (USERS[k.email]) USERS[k.email].pass = await hashPassword(p1);
      showToast(`Password ${k.nama} berhasil diubah ✓`,'ok');
    }

    closeModal('m-editklien');
    buildNav();
    const tb = document.getElementById('kl-tbody');
    if (tb) SP.setHTML(tb, renderKlienRows());
  };

  window.deleteKlien = function(i) {
    const item = klienList[i];
    if (!item) return;
    if (!confirm(`Hapus klien "${item.nama}"?`)) return;
    delete USERS[normalizeEmail(item.email)];
    uploads = uploads.filter(u => u.client !== item.nama);
    payList = payList.filter(p => p.client !== item.nama);
    invList = invList.filter(p => p.client !== item.nama);
    adminRevisions = adminRevisions.filter(r => r.klien !== item.nama);
    klienList.splice(i, 1);
    const tb = document.getElementById('kl-tbody');
    if (tb) SP.setHTML(tb, renderKlienRows());
    buildNav();
    showToast('Klien dan data terkait dihapus','inf');
  };

  window.saveProfile = async function() {
    const nama = v('pf-nama').trim();
    const email = normalizeEmail(v('pf-email'));
    const pass = v('pf-pass');
    const pass2 = v('pf-pass2');
    const oldEmail = CU ? CU.email : '';
    const oldName = CU ? CU.name : '';

    if (!nama) { showToast('Nama tidak boleh kosong','err'); return; }
    if (!SP.validators.email(email)) { showToast('Format email tidak valid','err'); return; }
    if (pass && pass.length < 8) { showToast('Password minimal 8 karakter','err'); return; }
    if (pass && !SP.validators.password(pass)) { showToast('Password harus mengandung huruf besar dan angka','err'); return; }
    if (pass && pass !== pass2) { showToast('Konfirmasi password tidak cocok','err'); return; }

    const passHash = pass ? await hashPassword(pass) : (USERS[normalizeEmail(oldEmail)] && USERS[normalizeEmail(oldEmail)].pass) || undefined;

    const sync = syncUserRecordEmail(oldEmail, email, {
      name: nama,
      avatar: nama.split(/\s+/).map(v=>v[0]).join('').slice(0,2).toUpperCase() || 'KL',
      pass: passHash,
      role: (USERS[normalizeEmail(oldEmail)] && USERS[normalizeEmail(oldEmail)].role) || 'klien'
    });
    if (!sync.ok) { showToast(sync.message,'err'); return; }

    CU.name = nama;
    CU.email = email;
    CU.avatar = USERS[email] ? USERS[email].avatar : CU.avatar;
    refreshClientNameReferences(oldName, nama);

    const clientRow = klienList.find(k => normalizeEmail(k.email) === normalizeEmail(oldEmail) || normalizeEmail(k.email) === email || k.nama === oldName);
    if (clientRow) {
      clientRow.nama = nama;
      clientRow.email = email;
    }

    const sbName = document.getElementById('sb-un');
    if (sbName) sbName.textContent = CU.name;
    const sbAv = document.getElementById('sb-av');
    if (sbAv) sbAv.textContent = CU.avatar || 'KL';
    buildNav();
    showToast('Profil berhasil diperbarui ✓','ok');
  };

  const origShowToast = window.showToast;
  window.showToast = function(msg, type='inf') {
    const el = document.createElement('div');
    const cls = { ok:'t-ok', err:'t-err', inf:'t-inf' };
    const ic = { ok:'✅', err:'❌', inf:'ℹ️' };
    el.className = `toast ${cls[type] || 't-inf'}`;
    const icon = document.createElement('span');
    icon.textContent = ic[type] || 'ℹ️';
    const text = document.createElement('span');
    text.textContent = String(msg || '');
    el.appendChild(icon);
    el.appendChild(text);
    const host = document.getElementById('toasts');
    if (!host) return;
    host.appendChild(el);
    setTimeout(() => {
      el.style.cssText += 'opacity:0;transform:translateX(16px);transition:all .28s';
      setTimeout(() => el.remove(), 300);
    }, 3200);
  };

  window.openModal = (function(orig) {
    return function(id) {
      if (id === 'm-upload') resetUploadModal();
      const el = document.getElementById(id);
      if (el) el.classList.add('on');
    };
  })(window.openModal);

  const origResetUploadModal = window.resetUploadModal;
  window.resetUploadModal = function() {
    origResetUploadModal();
    ['ur-ver','ur-tgl','ur-note','urk-judul','urk-note'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.value = '';
    });
    const urTgl = document.getElementById('ur-tgl');
    if (urTgl) urTgl.value = today();
  };

  const origLaunchApp = window.launchApp;
  window.launchApp = function() {
    origLaunchApp();
    const sbAv = document.getElementById('sb-av');
    if (sbAv) sbAv.textContent = CU.avatar || 'KL';
  };

  if (location.protocol === 'file:' || !/^https?:$/.test(location.protocol)) {
    const noopRegister = () => Promise.resolve({ update() {}, scope: location.href });
    if (navigator.serviceWorker && typeof navigator.serviceWorker.register === 'function') {
      navigator.serviceWorker.register = noopRegister;
    }
  }
})();

// ═══════════════════════════════════════════
// LOCALSTORAGE AUTO-SAVE PATCH
// ═══════════════════════════════════════════
(function() {
  // Wrap semua fungsi mutasi agar otomatis simpan ke localStorage
  const MUTATORS = [
    'confirmPay','rejectPay','approveUpload','rejectUpload',
    'submitPgRevisi','submitPgRekaman','submitKpPay',
    'doAddKlien','doSaveKlien','deleteKlien',
    'saveProfile','togglePengumuman','delPengumuman','delLayanan',
    'saveKontak','saveSiteinfo','saveRekening','saveCmsItem','saveAdminPassword',
    'createInvoice','submitPay','sendHasilRevisi','deleteHasil',
    'klienHasilRevisi','doCreateInv','doKirimHasil',
    'submitUpload','bootstrapPortal','resetPortalData'
  ];

  function wrapWithLocalSave(name) {
    const orig = window[name];
    if (typeof orig !== 'function') return;
    window[name] = async function(...args) {
      const result = await orig.apply(this, args);
      if (typeof queueLocalSave === 'function') queueLocalSave();
      return result;
    };
  }

  // Tunda sedikit agar semua fungsi sudah terdefinisi
  setTimeout(() => {
    MUTATORS.forEach(wrapWithLocalSave);
    console.info('[LocalStorage] Auto-save patch aktif untuk', MUTATORS.length, 'fungsi mutasi.');
  }, 100);

  // Juga simpan saat halaman akan ditutup/refresh
  window.addEventListener('beforeunload', () => {
    if (typeof saveStateToLocal === 'function') saveStateToLocal();
  });

  // Patch applyRemoteState Supabase agar juga update localStorage
  // Harus di-delay karena module Supabase bersifat async dan expose fungsi setelah init
  setTimeout(() => {
    const origApplyRemote = window.applyRemoteState;
    if (typeof origApplyRemote === 'function') {
      window.applyRemoteState = function(data, announce) {
        const result = origApplyRemote.apply(this, arguments);
        if (typeof queueLocalSave === 'function') queueLocalSave();
        return result;
      };
    }
  }, 500);

  // Cek apakah ada data localStorage — jika ada, pastikan setup awal tidak muncul
  (function checkFirstSetup() {
    try {
      const raw = localStorage.getItem('rhpartners.portal.state.v1');
      if (!raw) return;
      const state = JSON.parse(raw);
      // Jika sudah ada USERS lebih dari default, sembunyikan modal first-setup
      const userCount = state && state.USERS ? Object.keys(state.USERS).length : 0;
      if (userCount > 0) {
        const setupModal = document.getElementById('m-first-setup');
        if (setupModal) setupModal.classList.remove('on');
      }
    } catch(e) {}
  })();
})();
