// ═══════════════════════════════════════════
// SUPABASE STORAGE MODULE
// ═══════════════════════════════════════════
(async function(){
  const cfg = window.STUDIOPORTAL_SUPABASE_CONFIG || {};
  const hasConfig = !!(cfg && cfg.url && cfg.anonKey);
  const defaultBuckets = { revisi:'revisi', rekaman:'rekaman', pembayaran:'pembayaran', hasil:'hasil' };
  const bucketMap = Object.assign({}, defaultBuckets, cfg.buckets || {});

  function localMeta(file, bucket, folder, extra = {}) {
    const name = extra.name || file?.name || 'file.bin';
    return {
      name,
      path: `${folder || 'local'}/${Date.now()}_${name.replace(/[^a-zA-Z0-9._-]+/g, '_')}`,
      url: '',
      type: file?.type || extra.type || 'application/octet-stream',
      size: file?.size || extra.size || 0,
      bucket,
      ...(extra.durationLabel ? { durationLabel: extra.durationLabel } : {})
    };
  }

  if (!hasConfig) {
    console.warn('[Supabase] Konfigurasi belum diisi. File tetap tercatat tanpa URL unduhan.');
    window.__portalSupabaseStorage = {
      ready: false,
      async uploadSingleFile(file, bucketType, folder, extra) { return localMeta(file, bucketMap[bucketType] || bucketType, folder, extra); },
      async uploadBrowserFiles(files, bucketType, folder) { return Promise.all((files || []).map(file => this.uploadSingleFile(file, bucketType, folder))); },
      async uploadBlobItems(items, bucketType, folder) {
        return Promise.all((items || []).map(item => this.uploadSingleFile(item.blob || item.file, bucketType, folder, { name:item.name, durationLabel:item.dur, type:(item.blob || item.file)?.type, size:(item.blob || item.file)?.size })));
      }
    };
    return;
  }

  const { createClient } = await import('https://esm.sh/@supabase/supabase-js@2');
  const supabase = createClient(cfg.url, cfg.anonKey);

  async function uploadSingleFile(file, bucketType, folder = 'general', extra = {}) {
    const bucket = bucketMap[bucketType] || bucketType;
    const originalName = extra.name || file?.name || 'file.bin';
    const safeName = originalName.replace(/[^a-zA-Z0-9._-]+/g, '_');
    const path = `${folder || 'general'}/${Date.now()}_${safeName}`;
    const { error } = await supabase.storage.from(bucket).upload(path, file, { upsert: false, cacheControl: '3600' });
    if (error) throw error;
    const { data } = supabase.storage.from(bucket).getPublicUrl(path);
    return {
      name: originalName,
      path,
      url: data?.publicUrl || '',
      type: file?.type || extra.type || 'application/octet-stream',
      size: file?.size || extra.size || 0,
      bucket,
      ...(extra.durationLabel ? { durationLabel: extra.durationLabel } : {})
    };
  }

  window.__portalSupabaseStorage = {
    ready: true,
    uploadSingleFile,
    async uploadBrowserFiles(files, bucketType, folder) {
      return Promise.all((files || []).map(file => uploadSingleFile(file, bucketType, folder)));
    },
    async uploadBlobItems(items, bucketType, folder) {
      return Promise.all((items || []).map(item => uploadSingleFile(item.blob || item.file, bucketType, folder, { name:item.name, durationLabel:item.dur, type:(item.blob || item.file)?.type, size:(item.blob || item.file)?.size })));
    }
  };
})();

// ═══════════════════════════════════════════
// SUPABASE DATABASE SYNC
// ═══════════════════════════════════════════
(async function(){
  const cfg = window.STUDIOPORTAL_SUPABASE_CONFIG || {};
  const hasConfig = !!(cfg && cfg.url && cfg.anonKey);

  if (!hasConfig) {
    document.documentElement.dataset.dbMode = 'off';
    console.warn('[SupabaseDB] Konfigurasi belum diisi. Portal berjalan dalam mode lokal.');
    return;
  }

  const { createClient } = await import('https://esm.sh/@supabase/supabase-js@2');
  const supabase = createClient(cfg.url, cfg.anonKey);

  // Nama tabel di Supabase (buat via SQL Editor):
  // CREATE TABLE IF NOT EXISTS portal_state (
  //   id TEXT PRIMARY KEY DEFAULT 'app-state',
  //   state JSONB NOT NULL DEFAULT '{}',
  //   updated_at TIMESTAMPTZ DEFAULT NOW()
  // );
  // ALTER TABLE portal_state ENABLE ROW LEVEL SECURITY;
  // CREATE POLICY "allow_all" ON portal_state FOR ALL USING (true) WITH CHECK (true);
  const TABLE = 'portal_state';
  const ROW_ID = 'app-state';

  let dbReady = false;
  let applyingRemote = false;
  let initialSyncDone = false;
  let initialSyncPromise = null;
  let realtimeChannel = null;
  let saveTimer = null;
  let lastSavedHash = '';
  let lastRemoteHash = '';

  const deepClone = (v) => JSON.parse(JSON.stringify(v));
  const safeArray = (v) => Array.isArray(v) ? deepClone(v) : [];
  const safeObject = (v, fb = {}) => v && typeof v === 'object' ? deepClone(v) : deepClone(fb);

  function normalizeState(state) {
    return {
      USERS: safeObject(state && state.USERS, {}),
      uploads: safeArray(state && state.uploads),
      payList: safeArray(state && state.payList),
      klienList: safeArray(state && state.klienList),
      invList: safeArray(state && state.invList),
      adminRevisions: safeArray(state && state.adminRevisions),
      cmsData: safeObject(state && state.cmsData, { pengumuman:[], layanan:[], kontak:{}, siteinfo:{} })
    };
  }

  function currentState() {
    return normalizeState({ USERS, uploads, payList, klienList, invList, adminRevisions, cmsData });
  }

  function serializedState() {
    return JSON.stringify(currentState());
  }

  function refreshVisibleUi() {
    try {
      if (typeof buildNav === 'function') buildNav();
      if (typeof navTo === 'function' && document.getElementById('scr-app')?.classList.contains('on')) {
        navTo(window.currentView || 'dash');
      }
      if (CU) {
        const normalizedEmail = String(CU.email || '').trim().toLowerCase();
        const user = USERS[normalizedEmail];
        if (!user) {
          showToast('Akun Anda tidak lagi tersedia. Silakan login ulang.','err');
          if (typeof doLogout === 'function') doLogout();
          return;
        }
        CU = Object.assign({}, CU, user, { email: normalizedEmail });
        const sbAv = document.getElementById('sb-av');
        const sbUn = document.getElementById('sb-un');
        const sbUr = document.getElementById('sb-ur');
        if (sbAv) sbAv.textContent = CU.avatar || 'RH';
        if (sbUn) sbUn.textContent = CU.name || '';
        if (sbUr) sbUr.textContent = CU.role === 'admin' ? 'Administrator' : 'Klien';
      }
    } catch (err) {
      console.error('[SupabaseDB] Gagal me-refresh UI:', err);
    }
  }

  function applyRemoteState(state, announce = false) {
    const normalized = normalizeState(state || {});
    const nextHash = JSON.stringify(normalized);
    if (nextHash === lastRemoteHash) return;

    applyingRemote = true;
    USERS = normalized.USERS;
    uploads = normalized.uploads;
    payList = normalized.payList;
    klienList = normalized.klienList;
    invList = normalized.invList;
    adminRevisions = normalized.adminRevisions;
    cmsData = normalized.cmsData;
    applyingRemote = false;

    lastRemoteHash = nextHash;
    lastSavedHash = nextHash;
    refreshVisibleUi();
    if (typeof saveStateToLocal === 'function') saveStateToLocal();

    if (announce && dbReady) {
      showToast('Data tersinkron dari perangkat lain.','inf');
    }
  }
  // Expose ke window agar patch localStorage bisa mengaksesnya
  window.applyRemoteState = applyRemoteState;

  async function persistState(reason = 'sync') {
    if (!dbReady || applyingRemote || !initialSyncDone) return;
    const hash = serializedState();
    if (hash === lastSavedHash) return;

    try {
      const state = currentState();
      const { error } = await supabase
        .from(TABLE)
        .upsert({ id: ROW_ID, state, updated_at: new Date().toISOString() }, { onConflict: 'id' });

      if (error) throw error;
      lastSavedHash = JSON.stringify(state);
    } catch (err) {
      console.error('[SupabaseDB] Gagal menyimpan state:', err);
      showToast('Sinkronisasi Supabase gagal. Periksa koneksi dan RLS policy.','err');
    }
  }

  function queuePersist(reason = 'sync', delay = 220) {
    if (!dbReady || applyingRemote || !initialSyncDone) return;
    clearTimeout(saveTimer);
    saveTimer = setTimeout(() => persistState(reason), delay);
  }

  async function ensureInitialState() {
    if (initialSyncPromise) return initialSyncPromise;

    initialSyncPromise = (async () => {
      // Ambil state dari Supabase
      const { data, error } = await supabase
        .from(TABLE)
        .select('state')
        .eq('id', ROW_ID)
        .single();

      if (error && error.code !== 'PGRST116') {
        // PGRST116 = row not found (normal untuk pertama kali)
        throw new Error('Supabase DB error: ' + error.message);
      }

      if (data && data.state) {
        applyRemoteState(data.state, false);
      } else {
        // Baris belum ada — simpan state awal
        const local = currentState();
        const { error: insertError } = await supabase
          .from(TABLE)
          .upsert({ id: ROW_ID, state: local, updated_at: new Date().toISOString() }, { onConflict: 'id' });
        if (insertError) throw new Error('Supabase insert error: ' + insertError.message);
        lastRemoteHash = JSON.stringify(normalizeState(local));
        lastSavedHash = lastRemoteHash;
      }

      // Subscribe Realtime untuk sinkronisasi multi-device
      realtimeChannel = supabase
        .channel('portal-state-changes')
        .on('postgres_changes', {
          event: 'UPDATE',
          schema: 'public',
          table: TABLE,
          filter: `id=eq.${ROW_ID}`
        }, (payload) => {
          if (!payload.new || !payload.new.state) return;
          const incomingHash = JSON.stringify(normalizeState(payload.new.state));
          if (incomingHash === lastRemoteHash) return;
          applyRemoteState(payload.new.state, true);
        })
        .subscribe((status) => {
          if (status === 'SUBSCRIBED') {
            console.info('[SupabaseDB] Realtime aktif.');
          } else if (status === 'CHANNEL_ERROR' || status === 'TIMED_OUT') {
            console.warn('[SupabaseDB] Realtime terputus, status:', status);
          }
        });

      dbReady = true;
      initialSyncDone = true;
      document.documentElement.dataset.dbMode = 'on';
      console.info('[SupabaseDB] RH Partners Portal sinkron dengan Supabase.');
      return true;
    })();

    return initialSyncPromise;
  }

  function wrapMutator(name, reason, delayMs = 0) {
    const original = window[name];
    if (typeof original !== 'function') return;
    window[name] = async function(...args) {
      const before = serializedState();
      const result = await original.apply(this, args);
      const after = serializedState();
      if (before !== after) {
        queuePersist(reason, delayMs || 220);
      }
      return result;
    };
  }

  // Tunda wrap agar semua fungsi sudah terdefinisi di window
  setTimeout(() => {
    [
      ['confirmPay','confirm-pay'],
      ['rejectPay','reject-pay'],
      ['approveUpload','approve-upload'],
      ['rejectUpload','reject-upload'],
      ['submitPgRevisi','submit-pg-revisi',300],
      ['submitPgRekaman','submit-pg-rekaman',300],
      ['submitKpPay','submit-kp-pay'],
      ['doAddKlien','add-client'],
      ['doSaveKlien','save-client'],
      ['deleteKlien','delete-client'],
      ['saveProfile','save-profile'],
      ['togglePengumuman','toggle-pengumuman'],
      ['delPengumuman','delete-pengumuman'],
      ['delLayanan','delete-layanan'],
      ['saveKontak','save-kontak'],
      ['saveSiteinfo','save-siteinfo'],
      ['saveRekening','save-rekening'],
      ['saveCmsItem','save-cms-item'],
      ['saveAdminPassword','change-password'],
      ['createInvoice','create-invoice'],
      ['submitPay','submit-pay'],
      ['sendHasilRevisi','send-hasil',300],
      ['deleteHasil','delete-hasil'],
      ['klienHasilRevisi','read-hasil'],
      ['doCreateInv','create-invoice-admin'],
      ['doKirimHasil','kirim-hasil-admin'],
      ['submitUpload','submit-upload',300],
      ['bootstrapPortal','bootstrap-portal'],
      ['resetPortalData','reset-data']
    ].forEach(([name, reason, delayMs]) => wrapMutator(name, reason, delayMs));
  }, 200);

  // Wrap doLogin dan launchApp setelah fungsi-fungsi tersebut terdefinisi
  setTimeout(() => {
    const originalDoLogin = window.doLogin;
    if (typeof originalDoLogin === 'function') {
      window.doLogin = async function(...args) {
        await ensureInitialState();
        return originalDoLogin.apply(this, args);
      };
    }

    const originalLaunchApp = window.launchApp;
    if (typeof originalLaunchApp === 'function') {
      window.launchApp = async function(...args) {
        await ensureInitialState();
        return originalLaunchApp.apply(this, args);
      };
    }
  }, 150);

  window.__studioportalDB = {
    ensureInitialState,
    queuePersist,
    persistState,
    teardown() {
      if (realtimeChannel) supabase.removeChannel(realtimeChannel);
      clearTimeout(saveTimer);
    }
  };

  window.addEventListener('online', () => {
    document.documentElement.dataset.dbMode = dbReady ? 'on' : 'off';
    if (dbReady) queuePersist('reconnect', 400);
  });

  window.addEventListener('offline', () => {
    document.documentElement.dataset.dbMode = 'off';
    showToast('Koneksi offline. Portal berjalan dari data lokal.','inf');
  });

  window.addEventListener('beforeunload', () => {
    if (dbReady) persistState('beforeunload');
  });

  try {
    await ensureInitialState();
  } catch (err) {
    document.documentElement.dataset.dbMode = 'error';
    console.error('[SupabaseDB] Inisialisasi gagal:', err);
    showToast('Supabase gagal terhubung. Cek URL, anon key, dan RLS policy tabel portal_state.','err');
  }
})();
