// オフライン用キャッシュは暗号化して保存する (v2)。v1 以前は平文だったので読み込み時に移行して消す。
const ACCOUNT_CACHE_KEY = "phos-mfa.accounts.v2";
const LEGACY_PLAINTEXT_CACHE_KEYS = ["phos-mfa.accounts.v1", "dreamy-mfa.accounts.v1"];
const CACHE_KEY_DB = "phos-mfa-keys";
const CACHE_KEY_STORE = "keys";
const CACHE_KEY_ID = "account-cache-key-v1";
const CACHE_AAD = new TextEncoder().encode("phos-mfa.accounts.v2");
const OTP_HASHES = { SHA1: "SHA-1", SHA256: "SHA-256", SHA512: "SHA-512" };
const OTP_DEFAULTS = { algorithm: "SHA1", digits: 6, period: 30 };
const SERVICE_WORKER_CACHE = "phos-mfa-v20";
// 開いたときのロックが有効な人のオフライン用キャッシュ (v3)。サーバーからもらう鍵 K で暗号化し、
// K はパスコードから PBKDF2 で作った鍵で包んで保存する。パスコードを知らないと開けない。
const OFFLINE_WRAP_KEY = "phos-mfa.offline-wrap.v1";
const OFFLINE_FAILURES_KEY = "phos-mfa.offline-failures";
const OFFLINE_CACHE_AAD = new TextEncoder().encode("phos-mfa.accounts.v3");
const PBKDF2_ITERATIONS = 600_000;
const MAX_ATTEMPTS = 5;
const UNLOCK_HEADER = "X-PhosMFA-Unlock";

const state = {
  accounts: [],
  selectedId: "",
  canAddSecrets: false,
  cameraStream: null,
  qrFrameId: 0,
  serverTimeOffsetMs: 0,
  offlineMode: false,
  offlineReady: false,
  syncConfirmed: false,
  accessRevoked: false,
  lastSyncAt: 0,
  syncing: false,
  me: null,
  isAdmin: false,
  // 開いたときのロックを解除した証明。メモリにだけ置くので、再読み込みやアプリの再起動で消える。
  unlockToken: "",
  // オフライン用の鍵をパスコードで包むために、確認直後だけ一時的に持つ
  pendingPasscode: "",
  pendingPasscodeTimer: 0,
  gatePromise: null,
  passkeyOfferDone: false,
  // 管理画面: サーバーにある並び順 (adminAccounts) と、編集中の並び順 (adminOrder)
  adminAccounts: [],
  adminOrder: [],
};

const els = {
  workspace: document.querySelector("#workspace"),
  lockButton: document.querySelector("#lockButton"),
  secretForm: document.querySelector("#secretForm"),
  searchInput: document.querySelector("#searchInput"),
  accountList: document.querySelector("#accountList"),
  accountCount: document.querySelector("#accountCount"),
  template: document.querySelector("#accountTemplate"),
  emptyState: document.querySelector("#emptyState"),
  tokenView: document.querySelector("#tokenView"),
  selectedRole: document.querySelector("#selectedRole"),
  selectedService: document.querySelector("#selectedService"),
  selectedAccount: document.querySelector("#selectedAccount"),
  tokenText: document.querySelector("#tokenText"),
  tokenPeriodHint: document.querySelector("#tokenPeriodHint"),
  selectedAlgorithm: document.querySelector("#selectedAlgorithm"),
  selectedDigits: document.querySelector("#selectedDigits"),
  selectedPeriod: document.querySelector("#selectedPeriod"),
  copyTokenButton: document.querySelector("#copyTokenButton"),
  deleteButton: document.querySelector("#deleteButton"),
  timeLeft: document.querySelector("#timeLeft"),
  currentTime: document.querySelector("#currentTime"),
  syncStatus: document.querySelector("#syncStatus"),
  progressBar: document.querySelector("#progressBar"),
  serviceInput: document.querySelector("#serviceInput"),
  accountInput: document.querySelector("#accountInput"),
  roleInput: document.querySelector("#roleInput"),
  secretInput: document.querySelector("#secretInput"),
  otpOptions: document.querySelector("#otpOptions"),
  algorithmInput: document.querySelector("#algorithmInput"),
  digitsInput: document.querySelector("#digitsInput"),
  periodInput: document.querySelector("#periodInput"),
  addPanel: document.querySelector("#addPanel"),
  qrFileInput: document.querySelector("#qrFileInput"),
  qrFileButton: document.querySelector("#qrFileButton"),
  qrCameraButton: document.querySelector("#qrCameraButton"),
  qrStopButton: document.querySelector("#qrStopButton"),
  qrVideo: document.querySelector("#qrVideo"),
  qrCanvas: document.querySelector("#qrCanvas"),
  qrStatus: document.querySelector("#qrStatus"),
  cameraPanel: document.querySelector("#cameraPanel"),
  discordUser: document.querySelector("#discordUser"),
  settingsButton: document.querySelector("#settingsButton"),
  adminButton: document.querySelector("#adminButton"),
  gate: document.querySelector("#securityGate"),
  gateTitle: document.querySelector("#gateTitle"),
  gateMessage: document.querySelector("#gateMessage"),
  gateBody: document.querySelector("#gateBody"),
  gateError: document.querySelector("#gateError"),
  gateUser: document.querySelector("#gateUser"),
  gateLogout: document.querySelector("#gateLogout"),
  settingsDialog: document.querySelector("#settingsDialog"),
  unlockOnOpenToggle: document.querySelector("#unlockOnOpenToggle"),
  unlockOnOpenStatus: document.querySelector("#unlockOnOpenStatus"),
  passkeyList: document.querySelector("#passkeyList"),
  addPasskeyButton: document.querySelector("#addPasskeyButton"),
  passkeyStatus: document.querySelector("#passkeyStatus"),
  passcodeChangeForm: document.querySelector("#passcodeChangeForm"),
  currentPasscodeInput: document.querySelector("#currentPasscodeInput"),
  newPasscodeInput: document.querySelector("#newPasscodeInput"),
  confirmPasscodeInput: document.querySelector("#confirmPasscodeInput"),
  passcodeChangeStatus: document.querySelector("#passcodeChangeStatus"),
  adminDialog: document.querySelector("#adminDialog"),
  adminReloadButton: document.querySelector("#adminReloadButton"),
  adminStatus: document.querySelector("#adminStatus"),
  adminUserList: document.querySelector("#adminUserList"),
  adminUsersTab: document.querySelector("#adminUsersTab"),
  adminOrderTab: document.querySelector("#adminOrderTab"),
  adminUsersPanel: document.querySelector("#adminUsersPanel"),
  adminOrderPanel: document.querySelector("#adminOrderPanel"),
  adminOrderStatus: document.querySelector("#adminOrderStatus"),
  adminOrderList: document.querySelector("#adminOrderList"),
  adminOrderSaveButton: document.querySelector("#adminOrderSaveButton"),
  adminOrderResetButton: document.querySelector("#adminOrderResetButton"),
};

registerServiceWorker();
syncGateScrollLock();
init();

els.lockButton.addEventListener("click", async () => {
  stopQrCamera();
  await clearAccountCache();
  location.href = "/logout";
});
els.gateLogout.addEventListener("click", async (event) => {
  event.preventDefault();
  await clearAccountCache();
  location.href = "/logout";
});
els.settingsButton.addEventListener("click", openSettings);
els.adminButton.addEventListener("click", openAdmin);
els.adminReloadButton.addEventListener("click", reloadAdmin);
els.adminUsersTab.addEventListener("click", () => selectAdminTab("users"));
els.adminOrderTab.addEventListener("click", () => selectAdminTab("order"));
for (const tab of [els.adminUsersTab, els.adminOrderTab]) {
  tab.addEventListener("keydown", (event) => {
    if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
    event.preventDefault();
    const next = tab === els.adminUsersTab ? "order" : "users";
    selectAdminTab(next);
    (next === "users" ? els.adminUsersTab : els.adminOrderTab).focus();
  });
}
els.adminOrderSaveButton.addEventListener("click", saveAccountOrder);
els.adminOrderResetButton.addEventListener("click", () => {
  state.adminOrder = [...state.adminAccounts];
  renderAccountOrder();
});
els.unlockOnOpenToggle.addEventListener("change", updateUnlockOnOpen);
els.addPasskeyButton.addEventListener("click", addPasskeyFromSettings);
els.passcodeChangeForm.addEventListener("submit", changePasscodeFromSettings);
for (const dialog of [els.settingsDialog, els.adminDialog]) {
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog || event.target.closest("[data-close]")) dialog.close();
  });
}

els.secretForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!state.canAddSecrets) {
    alert("このDiscordアカウントには、シードを追加する権限がありません。");
    return;
  }
  if (state.offlineMode) {
    alert("オフライン中は追加できません。オンラインに戻ってから保存してください。");
    return;
  }

  const payload = {
    service: els.serviceInput.value.trim(),
    account: els.accountInput.value.trim(),
    role: els.roleInput.value.trim(),
    secret: els.secretInput.value.trim(),
    algorithm: els.algorithmInput.value,
    digits: Number(els.digitsInput.value),
    period: Number(els.periodInput.value),
  };

  if (!payload.service || !payload.account || !payload.secret) {
    alert("サービス名、アカウント、シードを入力してください。");
    return;
  }

  const { response, data } = await api("/api/accounts", { method: "POST", body: payload });
  if (await handleAccessError(response, data)) return;

  if (!response.ok) {
    alert("保存できませんでした。入力内容または権限を確認してください。");
    return;
  }

  els.secretForm.reset();
  els.otpOptions.open = false;
  setQrStatus("保存しました。");
  await loadAccounts({ showError: true });
});

els.searchInput.addEventListener("input", renderAccounts);
els.secretInput.addEventListener("input", () => {
  const value = els.secretInput.value.trim();
  if (!value.startsWith("otpauth://")) return;
  try {
    applyOtpParamsToForm(parseOtpAuth(value));
  } catch (error) {
    setQrStatus(error.message);
  }
});
els.qrFileButton.addEventListener("click", () => els.qrFileInput.click());
els.qrFileInput.addEventListener("change", handleQrFile);
els.qrCameraButton.addEventListener("click", startQrCamera);
els.qrStopButton.addEventListener("click", stopQrCamera);

els.copyTokenButton.addEventListener("click", async () => {
  const token = currentAccount()?.token || "";
  if (!/^\d{6,8}$/.test(token)) return;
  await navigator.clipboard.writeText(token);
  els.copyTokenButton.querySelector("small").textContent = "コピーしました";
  window.setTimeout(() => {
    els.copyTokenButton.querySelector("small").textContent = "クリックしてコピー";
  }, 1400);
});

els.deleteButton.addEventListener("click", async () => {
  if (!state.canAddSecrets) {
    alert("このDiscordアカウントには、シードを削除する権限がありません。");
    return;
  }
  if (state.offlineMode) {
    alert("オフライン中は削除できません。オンラインに戻ってから削除してください。");
    return;
  }

  const selected = currentAccount();
  if (!selected) return;
  const ok = confirm(`${selected.service} / ${selected.account} を削除しますか？`);
  if (!ok) return;

  const { response, data } = await api(`/api/accounts/${selected.id}`, { method: "DELETE" });
  if (await handleAccessError(response, data)) return;
  if (!response.ok) {
    alert("削除できませんでした。");
    return;
  }

  state.selectedId = "";
  await loadAccounts({ showError: true });
});

window.addEventListener("online", () => loadAccounts({ showError: false }));
window.addEventListener("offline", () => {
  // すでに表示中なら、手元のデータでそのまま続ける (ロック解除をやり直させない)
  if (state.accounts.length && !state.offlineMode && state.me) {
    state.offlineMode = true;
    updatePermissionUi();
    updateSyncStatus();
    return;
  }
  enableOfflineFromCache();
});
window.setInterval(tick, 1000);

async function init() {
  await tick();

  const me = await loadCurrentUser();
  if (!me) {
    if (state.accessRevoked) return;
    if (shouldUseOfflineFallback()) {
      const restored = await enableOfflineFromCache();
      if (restored) return;
    }
    location.href = "/login";
    return;
  }

  // 2段階認証の登録・確認・開いたときのロック解除が終わるまで、ここで待つ
  await ensureSecurity(me);
  state.offlineMode = false;
  updatePermissionUi();
  els.workspace.classList.remove("hidden");

  await loadAccounts({ showError: true });
  await tick();
}

async function loadAccounts({ showError = false } = {}) {
  if (state.syncing) return;
  state.syncing = true;

  try {
    const { response, data } = await api("/api/accounts");
    // 確認画面を通ったら、次の tick ですぐ読み直す
    if (await handleAccessError(response, data, { retry: () => { state.lastSyncAt = 0; } })) return;
    if (!response.ok) throw new Error("accounts request failed");

    applyServerTime(data.serverTime);
    state.offlineMode = false;
    state.lastSyncAt = Date.now();
    state.accounts = await hydrateAccounts(data.accounts || []);
    await cacheAccounts(state.accounts, data.offlineKey || null);

    if (!state.accounts.some((account) => account.id === state.selectedId)) {
      state.selectedId = state.accounts[0]?.id || "";
    }

    updatePermissionUi();
    renderAccounts();
    // Service Worker が使えない環境では ready が解決しないので、表示を待たせない
    prepareOfflineApp();
  } catch (error) {
    const restored = shouldUseOfflineFallback() ? await enableOfflineFromCache() : false;
    if (!restored && showError) {
      alert("認証コード一覧を読み込めませんでした。");
      state.accounts = [];
      renderAccounts();
    }
  } finally {
    state.syncing = false;
  }
}

async function hydrateAccounts(accounts) {
  const now = syncedNow();
  return Promise.all(
    accounts.map(async (account) => {
      const otp = normalizeOtpParams(account);
      return {
        id: account.id,
        service: account.service,
        account: account.account,
        role: account.role || "未分類",
        secret: account.secret,
        ...otp,
        token: account.secret ? await generateTotp(account.secret, now, otp) : account.token,
      };
    }),
  );
}

function renderAccounts() {
  const query = els.searchInput.value.trim().toLowerCase();
  const accounts = state.accounts.filter((account) => {
    const text = `${account.service} ${account.account} ${account.role}`.toLowerCase();
    return text.includes(query);
  });

  els.accountList.replaceChildren();
  els.accountCount.textContent = `${accounts.length}件`;

  for (const account of accounts) {
    const item = els.template.content.firstElementChild.cloneNode(true);
    item.classList.toggle("active", account.id === state.selectedId);
    item.querySelector(".account-service").textContent = account.service;
    item.querySelector(".account-name").textContent = account.account;
    item.querySelector(".account-role").textContent = account.role;
    item.addEventListener("click", () => {
      state.selectedId = account.id;
      renderAccounts();
      renderSelection();
    });
    els.accountList.append(item);
  }

  renderSelection();
}

function renderSelection() {
  const account = currentAccount();
  els.emptyState.classList.toggle("hidden", Boolean(account));
  els.tokenView.classList.toggle("hidden", !account);
  if (!account) return;

  els.selectedRole.textContent = account.role;
  els.selectedService.textContent = account.service;
  els.selectedAccount.textContent = account.account;
  els.tokenText.textContent = formatTokenForDisplay(account.token);
  els.selectedAlgorithm.textContent = `OATH-TOTP / ${OTP_HASHES[account.algorithm] || "SHA-1"}`;
  els.selectedDigits.textContent = `${account.digits}桁`;
  els.selectedPeriod.textContent = `${account.period}秒`;
  els.tokenPeriodHint.textContent = String(account.period);
}

async function tick() {
  const now = syncedNow();
  const seconds = Math.floor(now / 1000);
  const period = currentAccount()?.period || OTP_DEFAULTS.period;
  const remaining = period - (seconds % period);

  els.timeLeft.textContent = String(remaining).padStart(2, "0");
  if (els.currentTime) els.currentTime.textContent = formatTime(now);
  els.progressBar.style.width = `${(remaining / period) * 100}%`;
  updateSyncStatus();

  await refreshTokens(now);
  renderSelection();

  if (state.me && !state.gatePromise && !state.offlineMode && navigator.onLine && Date.now() - state.lastSyncAt > 30_000) {
    await loadAccounts({ showError: false });
  }
}

async function refreshTokens(now) {
  for (const account of state.accounts) {
    if (account.secret) account.token = await generateTotp(account.secret, now, account);
  }
}

async function enableOfflineFromCache() {
  const stored = readStoredCache();
  const cached = stored?.v === 3 ? await unlockOfflineCache(stored) : await loadCachedAccounts();
  if (!cached || !cached.length) return false;

  state.accounts = await hydrateAccounts(cached);
  state.offlineMode = true;
  state.canAddSecrets = false;
  if (!state.accounts.some((account) => account.id === state.selectedId)) {
    state.selectedId = state.accounts[0]?.id || "";
  }

  els.discordUser.textContent = "オフラインモード";
  updatePermissionUi();
  els.workspace.classList.remove("hidden");
  renderAccounts();
  updateSyncStatus();
  return true;
}

// オフライン用キャッシュ。シードは AES-256-GCM で暗号化して localStorage に置く。
// 鍵は取り出し不可 (extractable: false) の CryptoKey として IndexedDB に保存するので、
// localStorage やディスク上のデータをコピーされても、このブラウザ外では復号できない。
async function cacheAccounts(accounts, offlineKey = null) {
  const payload = accounts.map(({ id, service, account, role, secret, algorithm, digits, period }) => ({
    id,
    service,
    account,
    role,
    secret,
    algorithm,
    digits,
    period,
  }));

  if (offlineKey) {
    await cacheAccountsWithPasscode(payload, offlineKey);
    removeLegacyPlaintextCache();
    return;
  }
  localStorage.removeItem(OFFLINE_WRAP_KEY);

  try {
    const key = await getCacheKey({ create: true });
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: CACHE_AAD },
      key,
      new TextEncoder().encode(JSON.stringify(payload)),
    );
    localStorage.setItem(
      ACCOUNT_CACHE_KEY,
      JSON.stringify({ v: 2, iv: bytesToBase64(iv), data: bytesToBase64(new Uint8Array(ciphertext)) }),
    );
  } catch (error) {
    // 暗号化できない環境 (IndexedDB が使えない等) では平文で残さず、オフライン機能を諦める。
    localStorage.removeItem(ACCOUNT_CACHE_KEY);
  }
  removeLegacyPlaintextCache();
}

async function loadCachedAccounts() {
  const legacy = readLegacyPlaintextCache();
  if (legacy) {
    removeLegacyPlaintextCache();
    if (legacy.length) await cacheAccounts(legacy);
    return legacy;
  }

  try {
    const stored = JSON.parse(localStorage.getItem(ACCOUNT_CACHE_KEY) || "null");
    if (!stored || stored.v !== 2) return [];
    const key = await getCacheKey({ create: false });
    if (!key) throw new Error("cache key missing");
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64ToBytes(stored.iv), additionalData: CACHE_AAD },
      key,
      base64ToBytes(stored.data),
    );
    const parsed = JSON.parse(new TextDecoder().decode(plain));
    return Array.isArray(parsed) ? parsed.filter((account) => account.secret) : [];
  } catch (error) {
    localStorage.removeItem(ACCOUNT_CACHE_KEY);
    return [];
  }
}

function readLegacyPlaintextCache() {
  for (const name of LEGACY_PLAINTEXT_CACHE_KEYS) {
    const raw = localStorage.getItem(name);
    if (raw === null) continue;
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) return parsed.filter((account) => account.secret);
    } catch (error) {
      // 壊れたデータは捨てる
    }
  }
  return null;
}

function removeLegacyPlaintextCache() {
  for (const name of LEGACY_PLAINTEXT_CACHE_KEYS) localStorage.removeItem(name);
}

async function clearAccountCache() {
  localStorage.removeItem(ACCOUNT_CACHE_KEY);
  localStorage.removeItem(OFFLINE_WRAP_KEY);
  localStorage.removeItem(OFFLINE_FAILURES_KEY);
  forgetPendingPasscode();
  state.unlockToken = "";
  removeLegacyPlaintextCache();
  cacheKeyPromise = null;
  try {
    await withKeyStore("readwrite", (store) => store.delete(CACHE_KEY_ID));
  } catch (error) {
    // 鍵の削除に失敗しても暗号文は消えているので続行
  }
}

let cacheKeyPromise = null;

function getCacheKey({ create }) {
  if (!cacheKeyPromise) {
    cacheKeyPromise = (async () => {
      const existing = await withKeyStore("readonly", (store) => store.get(CACHE_KEY_ID));
      if (existing) return existing;
      if (!create) return null;
      const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
      await withKeyStore("readwrite", (store) => store.put(key, CACHE_KEY_ID));
      return key;
    })().catch((error) => {
      cacheKeyPromise = null;
      throw error;
    });
  }
  return cacheKeyPromise.then((key) => {
    if (!key) cacheKeyPromise = null;
    if (!key && create) return getCacheKey({ create });
    return key;
  });
}

function withKeyStore(mode, action) {
  return new Promise((resolve, reject) => {
    if (!("indexedDB" in window)) {
      reject(new Error("IndexedDB is not available."));
      return;
    }
    const open = indexedDB.open(CACHE_KEY_DB, 1);
    open.onupgradeneeded = () => open.result.createObjectStore(CACHE_KEY_STORE);
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const db = open.result;
      const tx = db.transaction(CACHE_KEY_STORE, mode);
      const request = action(tx.objectStore(CACHE_KEY_STORE));
      tx.oncomplete = () => {
        db.close();
        resolve(request.result);
      };
      tx.onerror = tx.onabort = () => {
        db.close();
        reject(tx.error);
      };
    };
  });
}

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value) {
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}

function updatePermissionUi() {
  els.addPanel.classList.toggle("hidden", !state.canAddSecrets || state.offlineMode);
  els.deleteButton.classList.toggle("hidden", !state.canAddSecrets || state.offlineMode);
}

function applyServerTime(serverTime) {
  if (Number.isFinite(serverTime)) {
    state.serverTimeOffsetMs = serverTime - Date.now();
    state.syncConfirmed = true;
  }
}

function syncedNow() {
  return Date.now() + state.serverTimeOffsetMs;
}

function updateSyncStatus() {
  if (!els.syncStatus) return;

  if (state.offlineMode) {
    els.syncStatus.textContent = "オフライン: 保存したデータで認証コードを表示中";
    return;
  }

  if (!state.syncConfirmed) {
    els.syncStatus.textContent = "サーバー同期確認中";
    return;
  }

  const drift = Math.round(state.serverTimeOffsetMs / 1000);
  const absolute = Math.abs(drift);
  const syncText = absolute <= 1
    ? "サーバー時刻と同期済み"
    : `サーバー時刻との差 ${drift > 0 ? "+" : ""}${drift}秒`;
  els.syncStatus.textContent = state.offlineReady ? `${syncText} / オフラインでも使えます` : syncText;
}

function formatTime(timestamp) {
  return new Intl.DateTimeFormat("ja-JP", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(new Date(timestamp));
}

async function prepareOfflineApp() {
  if (!("serviceWorker" in navigator) || !("caches" in window)) return;

  try {
    await navigator.serviceWorker.ready;
    const cache = await caches.open(SERVICE_WORKER_CACHE);
    const required = [
      "/index.html",
      "/styles.css",
      "/app.js",
      "/dist/authenticator.bundle.js",
      "/manifest.webmanifest",
      "/icons/icon-192.png",
      "/icons/icon-512.png",
    ];

    await Promise.all(
      required.map(async (url) => {
        const response = await fetch(new Request(url, { cache: "reload", credentials: "same-origin" }));
        if (response.ok && response.type === "basic" && !response.redirected) {
          await cache.put(url, response);
        }
      }),
    );
    state.offlineReady = true;
    updateSyncStatus();
  } catch (error) {
    state.offlineReady = false;
  }
}

async function handleQrFile(event) {
  const file = event.target.files?.[0];
  if (!file) return;

  try {
    setQrStatus("QR画像を読み取っています...");
    const image = await loadImage(file);
    const result = decodeQrFromSource(image);
    applyQrResult(result);
  } catch (error) {
    setQrStatus(error.message || "QRコードを読み取れませんでした。");
  } finally {
    els.qrFileInput.value = "";
  }
}

async function startQrCamera() {
  if (!navigator.mediaDevices?.getUserMedia) {
    setQrStatus("このブラウザではカメラでの読み取りを使えません。QR画像を選択してください。");
    return;
  }

  try {
    stopQrCamera();
    setQrStatus("カメラを起動しています...");
    state.cameraStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: "environment" },
      audio: false,
    });
    els.qrVideo.srcObject = state.cameraStream;
    els.cameraPanel.classList.remove("hidden");
    await els.qrVideo.play();
    setQrStatus("QRコードをカメラに向けてください。");
    scanQrVideo();
  } catch (error) {
    setQrStatus("カメラを起動できませんでした。権限を確認するか、QR画像を選択してください。");
  }
}

function scanQrVideo() {
  if (!state.cameraStream) return;

  try {
    const result = decodeQrFromSource(els.qrVideo);
    applyQrResult(result);
    stopQrCamera();
  } catch (error) {
    state.qrFrameId = window.requestAnimationFrame(scanQrVideo);
  }
}

function stopQrCamera() {
  if (state.qrFrameId) {
    window.cancelAnimationFrame(state.qrFrameId);
    state.qrFrameId = 0;
  }
  if (state.cameraStream) {
    for (const track of state.cameraStream.getTracks()) {
      track.stop();
    }
  }
  state.cameraStream = null;
  els.qrVideo.srcObject = null;
  els.cameraPanel.classList.add("hidden");
}

function decodeQrFromSource(source) {
  const width = source.videoWidth || source.naturalWidth || source.width;
  const height = source.videoHeight || source.naturalHeight || source.height;
  if (!width || !height) {
    throw new Error("QRコードを読み取る準備ができていません。");
  }

  const canvas = els.qrCanvas;
  canvas.width = width;
  canvas.height = height;
  const context = canvas.getContext("2d", { willReadFrequently: true });
  context.drawImage(source, 0, 0, width, height);
  const imageData = context.getImageData(0, 0, width, height);
  const result = window.SharedQr?.decode(imageData.data, width, height);
  if (!result) {
    throw new Error("QRコードを読み取れませんでした。");
  }
  return result;
}

function applyQrResult(value) {
  const parsed = parseOtpAuth(value);
  if (!parsed.secret) {
    throw new Error("TOTP用のQRコードではありません。");
  }

  els.secretInput.value = value;
  applyOtpParamsToForm(parsed);
  els.serviceInput.value = parsed.issuer || els.serviceInput.value || "X";
  els.accountInput.value = parsed.account || els.accountInput.value;
  els.roleInput.value = els.roleInput.value || "SNS";
  setQrStatus("QRコードを読み取りました。内容を確認して保存してください。");
}

function parseOtpAuth(value) {
  if (!value.startsWith("otpauth://")) {
    return { secret: value.trim(), issuer: "", account: "", ...OTP_DEFAULTS };
  }

  const url = new URL(value);
  if (url.hostname.toLowerCase() !== "totp") {
    throw new Error("時間ベース (TOTP) のQRコードのみ対応しています。");
  }
  const label = decodeURIComponent(url.pathname.replace(/^\/+/, ""));
  const [labelIssuer, ...accountParts] = label.split(":");
  const issuer = url.searchParams.get("issuer") || (accountParts.length ? labelIssuer : "");
  const account = accountParts.length ? accountParts.join(":") : labelIssuer;

  const otp = normalizeOtpParams({
    algorithm: url.searchParams.get("algorithm"),
    digits: url.searchParams.get("digits"),
    period: url.searchParams.get("period"),
  });
  const requestedAlgorithm = (url.searchParams.get("algorithm") || "").toUpperCase().replace(/-/g, "");
  if (requestedAlgorithm && requestedAlgorithm !== otp.algorithm) {
    throw new Error(`未対応のアルゴリズムです: ${url.searchParams.get("algorithm")}`);
  }
  if (url.searchParams.get("digits") && String(otp.digits) !== url.searchParams.get("digits")) {
    throw new Error(`未対応の桁数です: ${url.searchParams.get("digits")}`);
  }
  if (url.searchParams.get("period") && String(otp.period) !== url.searchParams.get("period")) {
    throw new Error(`未対応の更新間隔です: ${url.searchParams.get("period")}`);
  }

  return {
    secret: url.searchParams.get("secret") || "",
    issuer,
    account,
    ...otp,
  };
}

function applyOtpParamsToForm({ algorithm, digits, period }) {
  els.algorithmInput.value = algorithm;
  els.digitsInput.value = String(digits);
  if (![...els.periodInput.options].some((option) => option.value === String(period))) {
    els.periodInput.append(new Option(`${period}秒`, String(period)));
  }
  els.periodInput.value = String(period);
  const isDefault =
    algorithm === OTP_DEFAULTS.algorithm && digits === OTP_DEFAULTS.digits && period === OTP_DEFAULTS.period;
  if (!isDefault) els.otpOptions.open = true;
}

function loadImage(file) {
  return new Promise((resolve, reject) => {
    const image = new Image();
    image.onload = () => {
      URL.revokeObjectURL(image.src);
      resolve(image);
    };
    image.onerror = () => reject(new Error("画像を読み込めませんでした。"));
    image.src = URL.createObjectURL(file);
  });
}

function setQrStatus(message) {
  els.qrStatus.textContent = message;
}

async function loadCurrentUser() {
  try {
    const { response, data } = await api("/api/me");
    if (response.status === 401 || response.status === 403) {
      forceLogout();
      return null;
    }
    if (!response.ok || !data.authenticated) return null;
    applyMe(data);
    return data;
  } catch (error) {
    els.discordUser.textContent = "オフラインモード";
    return null;
  }
}

function forceLogout() {
  state.accessRevoked = true;
  state.offlineMode = false;
  state.accounts = [];
  clearAccountCache().finally(() => location.replace("/login"));
}

function shouldUseOfflineFallback() {
  return !state.accessRevoked && navigator.onLine === false;
}

function currentAccount() {
  return state.accounts.find((account) => account.id === state.selectedId);
}

function formatTokenForDisplay(token) {
  if (!/^\d{6,8}$/.test(token || "")) return "------";
  const split = token.length === 6 ? 3 : token.length - 4;
  return `${token.slice(0, split)} ${token.slice(split)}`;
}

function normalizeOtpParams(raw = {}) {
  const algorithm = String(raw.algorithm ?? "").trim().toUpperCase().replace(/-/g, "");
  const digits = Number(raw.digits);
  const period = Number(raw.period);
  return {
    algorithm: algorithm in OTP_HASHES ? algorithm : OTP_DEFAULTS.algorithm,
    digits: Number.isInteger(digits) && digits >= 6 && digits <= 8 ? digits : OTP_DEFAULTS.digits,
    period: Number.isInteger(period) && period >= 10 && period <= 300 ? period : OTP_DEFAULTS.period,
  };
}

async function generateTotp(secret, timestamp, params = OTP_DEFAULTS) {
  const { algorithm, digits, period } = normalizeOtpParams(params);
  const key = await crypto.subtle.importKey(
    "raw",
    base32ToBytes(secret),
    { name: "HMAC", hash: OTP_HASHES[algorithm] },
    false,
    ["sign"],
  );
  const counter = Math.floor(timestamp / 1000 / period);
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  view.setUint32(0, Math.floor(counter / 0x100000000));
  view.setUint32(4, counter >>> 0);
  const hash = new Uint8Array(await crypto.subtle.sign("HMAC", key, buffer));
  const offset = hash[hash.length - 1] & 0x0f;
  const binary =
    ((hash[offset] & 0x7f) << 24) |
    (hash[offset + 1] << 16) |
    (hash[offset + 2] << 8) |
    hash[offset + 3];
  return String(binary % 10 ** digits).padStart(digits, "0");
}

function base32ToBytes(secret) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = secret.replace(/=+$/, "").replace(/\s+/g, "").toUpperCase();
  let bits = "";
  for (const char of clean) {
    const value = alphabet.indexOf(char);
    if (value === -1) throw new Error("Invalid base32 secret.");
    bits += value.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(Number.parseInt(bits.slice(i, i + 8), 2));
  }
  return new Uint8Array(bytes);
}

function registerServiceWorker() {
  if (!("serviceWorker" in navigator)) return;

  window.addEventListener("load", async () => {
    try {
      const registration = await navigator.serviceWorker.register("/sw.js");
      if (registration.waiting) registration.waiting.postMessage({ type: "SKIP_WAITING" });
      registration.addEventListener("updatefound", () => {
        const worker = registration.installing;
        if (!worker) return;
        worker.addEventListener("statechange", () => {
          if (worker.state === "installed" && navigator.serviceWorker.controller) {
            worker.postMessage({ type: "SKIP_WAITING" });
          }
        });
      });
    } catch (error) {
      state.offlineReady = false;
    }
  });
}

// ===========================================================================
// API
// ===========================================================================

async function api(path, { method = "GET", body } = {}) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (state.unlockToken) headers[UNLOCK_HEADER] = state.unlockToken;
  const response = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    cache: "no-store",
    credentials: "same-origin",
  });
  let data = {};
  try {
    data = await response.clone().json();
  } catch (error) {
    data = {};
  }
  return { response, data };
}

// 2段階認証が切れた・ロックされた等のときに確認画面へ戻す。処理したら true。
async function handleAccessError(response, data, { retry } = {}) {
  if (response.status === 423) {
    await requireSecurityAgain();
    return true;
  }
  if (response.status === 401) {
    if (["mfa_required", "unlock_required", "mfa_setup_required"].includes(data.error)) {
      if (data.error === "unlock_required") state.unlockToken = "";
      await requireSecurityAgain();
      if (retry) await retry();
      return true;
    }
    forceLogout();
    return true;
  }
  if (response.status === 403 && data.error !== "forbidden") {
    forceLogout();
    return true;
  }
  return false;
}

async function requireSecurityAgain() {
  const me = await loadCurrentUser();
  if (!me) return;
  await ensureSecurity(me);
}

function applyMe(data) {
  state.me = data;
  applyServerTime(data.serverTime);
  const name = data.user.globalName || data.user.username || data.user.id;
  els.discordUser.textContent = name;
  els.gateUser.textContent = `${name} としてログイン中`;
  state.canAddSecrets = Boolean(data.user.canAddSecrets);
  state.isAdmin = Boolean(data.security?.isAdmin);
  els.adminButton.classList.toggle("hidden", !state.isAdmin);
}

// ===========================================================================
// 2段階認証の画面 (登録・確認・開いたときのロック・アカウントロック)
// ===========================================================================

function ensureSecurity(me) {
  if (!state.gatePromise) {
    state.gatePromise = runSecurityGate(me).finally(() => {
      state.gatePromise = null;
    });
  }
  return state.gatePromise;
}

async function runSecurityGate(initial) {
  let me = initial;
  while (me.security.stage !== "ready") {
    els.workspace.classList.add("hidden");
    els.gate.classList.remove("hidden");
    await renderGateStage(me);
    const next = await loadCurrentUser();
    if (!next) return new Promise(() => {});
    me = next;
  }
  destroyActivePad();
  els.gate.classList.add("hidden");
  els.gateBody.replaceChildren();
  return me;
}

function renderGateStage(me) {
  const security = me.security;
  setGateError("");
  if (security.stage === "locked") return renderLockedStage(security);
  if (security.stage === "setup") {
    if (!security.hasPasscode) return renderPasscodeSetupStage();
    if (!security.passkeyCount && passkeySupported() && !state.passkeyOfferDone) return renderPasskeyOfferStage();
    return renderUnlockChoiceStage();
  }
  return renderVerifyStage(security);
}

function renderLockedStage(security) {
  setGate(
    "アカウントがロックされています",
    security.lockReason === "admin"
      ? "管理者がこのアカウントをロックしました。使えるようにするには、管理者に連絡してください。"
      : `パスコードかパスキーの確認に${MAX_ATTEMPTS}回失敗したため、ロックしました。解除するには管理者に連絡してください。`,
  );
  els.gateBody.replaceChildren();
  return new Promise(() => {});
}

function renderPasscodeSetupStage() {
  const intro =
    "Discord アカウントが乗っ取られても PhosMFA を開けないように、2段階認証を設定します。パスキーが使えない端末でも使えるパスコードを決めてください。";

  return new Promise((resolve) => {
    let length = 6;
    let first = "";

    const showFirst = () => {
      first = "";
      setGate("パスコードを登録してください", intro);
      const switcher = button(length === 6 ? "4桁のパスコードにする" : "6桁のパスコードにする", "button", "link-button");
      switcher.addEventListener("click", () => {
        length = length === 6 ? 4 : 6;
        setGateError("");
        showFirst();
      });
      const pad = passcodePad({
        length,
        onComplete: async (code) => {
          if (passcodeTooSimple(code)) {
            setGateError("推測されやすい番号（同じ数字の繰り返しや連番）は使えません。");
            return false;
          }
          setGateError("");
          first = code;
          showConfirm();
          return true;
        },
      });
      els.gateBody.replaceChildren(pad.element, switcher);
    };

    const showConfirm = () => {
      setGate("もう一度入力してください", "確認のため、同じパスコードをもう一度入力してください。");
      const back = button("最初からやり直す", "button", "link-button");
      back.addEventListener("click", () => {
        setGateError("");
        showFirst();
      });
      const pad = passcodePad({
        length,
        onComplete: async (code) => {
          if (code !== first) {
            setGateError("パスコードが一致しませんでした。最初から入力し直してください。");
            window.setTimeout(showFirst, 450);
            return false;
          }
          const { response, data } = await api("/api/mfa/passcode/setup", { method: "POST", body: { passcode: code } });
          if (!response.ok) {
            setGateError(errorMessage(data));
            window.setTimeout(showFirst, 450);
            return false;
          }
          acceptVerification(data, code);
          resolve();
          return true;
        },
      });
      els.gateBody.replaceChildren(pad.element, back);
    };

    showFirst();
  });
}

function renderPasskeyOfferStage() {
  setGate(
    "パスキーも登録しませんか",
    "パスキーを登録すると、指紋・顔認証・端末のロック解除だけで PhosMFA を開けます。パスコードより安全で、入力の手間もかかりません。",
  );

  return new Promise((resolve) => {
    const register = button("パスキーを登録する");
    const skip = button("あとで", "button", "link-button");
    register.addEventListener("click", () =>
      busy(register, async () => {
        const result = await registerPasskey();
        if (result.ok) {
          state.passkeyOfferDone = true;
          resolve();
        } else if (result.message) {
          setGateError(result.message);
        }
      }),
    );
    skip.addEventListener("click", () => {
      state.passkeyOfferDone = true;
      resolve();
    });
    els.gateBody.replaceChildren(register, skip, hint("あとから「セキュリティ設定」でも追加できます。"));
  });
}

function renderUnlockChoiceStage() {
  setGate(
    "開いたときにもロックしますか",
    "オンにすると、ページや PWA を開くたびにパスキーかパスコードを求めます。オフにすると、Discord でログインしたときだけ確認します。",
  );

  return new Promise((resolve) => {
    const yes = button("開くたびに確認する（おすすめ）");
    const no = button("ログインのときだけ確認する", "button", "secondary");
    const choose = (value, target) =>
      busy(target, async () => {
        const { response, data } = await api("/api/mfa/preferences", { method: "POST", body: { unlockOnOpen: value } });
        if (!response.ok) return setGateError(errorMessage(data));
        if (data.unlockToken) state.unlockToken = data.unlockToken;
        resolve();
      });
    yes.addEventListener("click", () => choose(true, yes));
    no.addEventListener("click", () => choose(false, no));
    els.gateBody.replaceChildren(yes, no, hint("あとから「セキュリティ設定」で変更できます。"));
  });
}

function renderVerifyStage(security) {
  const unlocking = security.stage === "unlock";
  const canUsePasskey = security.passkeyCount > 0 && passkeySupported();
  setGate(
    unlocking ? "パスコードを入力" : "2段階認証",
    unlocking
      ? canUsePasskey
        ? "パスコードを入力するか、パスキーで本人確認をしてください。"
        : "パスコードを入力すると、認証コードを表示します。"
      : "Discord でのログインを確認しました。続けて、パスコードかパスキーで本人確認をしてください。",
  );

  return new Promise((resolve) => {
    const remaining = hint("");
    const showRemaining = (count) => {
      remaining.textContent = count < MAX_ATTEMPTS ? `あと${count}回失敗すると、アカウントがロックされます。` : "";
    };
    showRemaining(security.remainingAttempts);

    const pad = passcodePad({
      length: security.passcodeLength || null,
      extraKey: canUsePasskey
        ? {
            label: "パスキー",
            ariaLabel: "パスキーで本人確認",
            onPress: async () => {
              setGateError("");
              const result = await authenticateWithPasskey();
              if (result.ok || result.locked) return resolve();
              if (result.message) setGateError(result.message);
              if (Number.isFinite(result.remainingAttempts)) showRemaining(result.remainingAttempts);
            },
          }
        : null,
      onComplete: async (passcode) => {
        const { response, data } = await api("/api/mfa/passcode/verify", { method: "POST", body: { passcode } });
        if (response.status === 423) {
          resolve();
          return true;
        }
        if (!response.ok) {
          // 残り回数はキーの下に出すので、エラーは短く
          setGateError(data.error === "invalid_passcode" ? "パスコードが違います。" : errorMessage(data));
          if (Number.isFinite(data.remainingAttempts)) showRemaining(data.remainingAttempts);
          return false;
        }
        setGateError("");
        acceptVerification(data, passcode);
        resolve();
        return true;
      },
    });

    els.gateBody.replaceChildren(pad.element, remaining);
  });
}

function acceptVerification(data, passcode = "") {
  if (data.unlockToken) state.unlockToken = data.unlockToken;
  if (passcode) rememberPendingPasscode(passcode);
}

function setGate(title, message) {
  els.gateTitle.textContent = title;
  els.gateMessage.textContent = message;
}

function setGateError(message) {
  els.gateError.textContent = message || "";
}

function errorMessage(data) {
  const remaining = Number.isFinite(data.remainingAttempts) ? data.remainingAttempts : null;
  switch (data.error) {
    case "passcode_format":
      return "パスコードは4桁か6桁の数字にしてください。";
    case "passcode_too_simple":
      return "推測されやすい番号（同じ数字の繰り返しや連番）は使えません。";
    case "invalid_passcode":
      return `パスコードが違います。あと${remaining}回失敗するとロックされます。`;
    case "invalid_passkey":
      return `パスキーを確認できませんでした。あと${remaining}回失敗するとロックされます。`;
    case "locked":
      return "アカウントがロックされています。管理者に連絡してください。";
    case "challenge_expired":
      return "時間切れになりました。もう一度お試しください。";
    case "passkey_invalid":
      return "このパスキーは登録できませんでした。";
    case "passkey_already_registered":
      return "このパスキーはすでに登録されています。";
    case "too_many_passkeys":
      return "パスキーは10個まで登録できます。";
    case "cannot_lock_self":
      return "自分自身はロックできません。";
    default:
      return "処理できませんでした。時間をおいて、もう一度お試しください。";
  }
}

// --- 画面部品 ---

function button(text, type = "button", className = "") {
  const element = document.createElement("button");
  element.type = type;
  element.textContent = text;
  if (className) element.className = className;
  return element;
}

function hint(text) {
  const element = document.createElement("p");
  element.className = "hint";
  element.textContent = text;
  return element;
}

function divider(text) {
  const element = document.createElement("div");
  element.className = "divider";
  element.textContent = text;
  return element;
}

// パスコード入力。スマホ・タブレットはロック画面のような数字キー、
// パソコン (マウスやトラックパッドで操作する端末) はキーボードで打つ入力欄にする。
// length が null のときは 4〜6桁で、「確定」で送る。
let activePad = null;

function usesKeyboardEntry() {
  return window.matchMedia("(hover: hover) and (pointer: fine)").matches;
}

function passcodePad(options) {
  return usesKeyboardEntry() ? passcodeField(options) : passcodeKeypad(options);
}

// パソコン用: 桁数分の枠に、キーボードで入力する。
// 実際の入力は見えない input で受けるので、日本語入力がオンでも、貼り付けでも入力できる。
function passcodeField({ length, onComplete, extraKey = null }) {
  destroyActivePad();
  const maxLength = length || 6;
  let value = "";
  let busy = false;

  const element = document.createElement("div");
  element.className = "pin pin-desktop";

  const field = document.createElement("div");
  field.className = "pin-field";
  const boxes = [];
  for (let i = 0; i < maxLength; i += 1) {
    const box = document.createElement("span");
    box.className = "pin-box";
    box.setAttribute("aria-hidden", "true");
    boxes.push(box);
    field.append(box);
  }

  const input = document.createElement("input");
  input.className = "pin-input";
  input.type = "password";
  input.inputMode = "numeric";
  input.autocomplete = "off";
  input.spellcheck = false;
  input.maxLength = maxLength;
  input.setAttribute("aria-label", length ? `パスコード（${length}桁）` : "パスコード（4〜6桁）");
  field.append(input);

  const help = hint(length ? "キーボードで数字を入力してください。" : "キーボードで数字を入力し、Enter キーで確定してください。");
  help.classList.add("pin-help");

  const actions = document.createElement("div");
  actions.className = "pin-actions";
  let okButton = null;
  if (!length) {
    okButton = button("確定", "button");
    okButton.addEventListener("click", submit);
    actions.append(okButton);
  }
  let extraButton = null;
  if (extraKey) {
    extraButton = button(extraKey.ariaLabel || extraKey.label, "button", "secondary");
    extraButton.addEventListener("click", async () => {
      if (busy) return;
      setBusy(true);
      try {
        await extraKey.onPress();
      } finally {
        setBusy(false);
        focusInput();
      }
    });
    actions.append(extraButton);
  }

  element.append(field, help);
  if (actions.childElementCount) element.append(actions);
  field.addEventListener("animationend", () => element.classList.remove("shake"));
  field.addEventListener("mousedown", (event) => {
    if (event.target !== input) {
      event.preventDefault();
      focusInput();
    }
  });

  function normalize(text) {
    // 全角数字も受け付ける
    return text.replace(/[０-９]/g, (char) => String.fromCharCode(char.charCodeAt(0) - 0xfee0)).replace(/\D/g, "").slice(0, maxLength);
  }

  function render() {
    boxes.forEach((box, i) => {
      box.classList.toggle("filled", i < value.length);
      box.classList.toggle("current", i === Math.min(value.length, maxLength - 1) && !busy);
    });
    if (okButton) okButton.disabled = busy || value.length < 4;
  }

  function setBusy(next) {
    busy = next;
    element.classList.toggle("busy", next);
    input.disabled = next;
    for (const control of actions.querySelectorAll("button")) control.disabled = next;
    render();
  }

  function focusInput() {
    if (!input.disabled && document.contains(input)) input.focus({ preventScroll: true });
  }

  input.addEventListener("input", () => {
    value = normalize(input.value);
    if (input.value !== value) input.value = value;
    render();
    if (length && value.length === length) submit();
  });
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      submit();
    }
  });
  input.addEventListener("focus", () => element.classList.add("focused"));
  input.addEventListener("blur", () => element.classList.remove("focused"));

  async function submit() {
    if (busy || value.length < 4) return;
    const code = value;
    setBusy(true);
    let ok = false;
    try {
      ok = await onComplete(code);
    } catch (error) {
      setGateError("通信できませんでした。接続を確認して、もう一度お試しください。");
    }
    if (activePad !== controller) return;
    setBusy(false);
    if (!ok) {
      value = "";
      input.value = "";
      render();
      element.classList.remove("shake");
      void element.offsetWidth;
      element.classList.add("shake");
    }
    focusInput();
  }

  const controller = { element, destroy() {} };
  activePad = controller;
  render();
  // 画面に入ったらすぐ打てるようにする
  window.requestAnimationFrame(focusInput);
  return controller;
}

// スマホ・タブレット用: ロック画面のような数字キー
function passcodeKeypad({ length, onComplete, extraKey = null }) {
  destroyActivePad();
  const maxLength = length || 6;
  let value = "";
  let busy = false;

  const element = document.createElement("div");
  element.className = "pin";

  const dots = document.createElement("div");
  dots.className = "pin-dots";
  dots.setAttribute("aria-hidden", "true");
  const dotCount = length || 6;
  for (let i = 0; i < dotCount; i += 1) dots.append(Object.assign(document.createElement("span"), { className: "pin-dot" }));

  const live = document.createElement("p");
  live.className = "sr-only";
  live.setAttribute("aria-live", "polite");

  const keys = document.createElement("div");
  keys.className = "pin-keys";
  const letters = ["", "", "ABC", "DEF", "GHI", "JKL", "MNO", "PQRS", "TUV", "WXYZ"];
  const digitKey = (digit) => {
    const key = button("", "button", "pin-key");
    key.setAttribute("aria-label", String(digit));
    key.append(Object.assign(document.createElement("span"), { textContent: String(digit) }));
    key.append(Object.assign(document.createElement("small"), { textContent: letters[digit] || " " }));
    key.addEventListener("click", () => press(String(digit)));
    return key;
  };
  for (let digit = 1; digit <= 9; digit += 1) keys.append(digitKey(digit));

  let okKey = null;
  if (!length) {
    okKey = button("確定", "button", "pin-key text");
    okKey.addEventListener("click", submit);
    keys.append(okKey);
  } else if (extraKey) {
    const key = button(extraKey.label, "button", "pin-key text");
    key.setAttribute("aria-label", extraKey.ariaLabel || extraKey.label);
    key.addEventListener("click", async () => {
      if (busy) return;
      setBusy(true);
      try {
        await extraKey.onPress();
      } finally {
        setBusy(false);
      }
    });
    keys.append(key);
  } else {
    keys.append(Object.assign(document.createElement("span"), { className: "pin-key blank" }));
  }
  keys.append(digitKey(0));
  const deleteKey = button("", "button", "pin-key text");
  deleteKey.setAttribute("aria-label", "1文字消す");
  deleteKey.innerHTML =
    '<svg viewBox="0 0 24 24" width="26" height="26" aria-hidden="true"><path d="M9 5h10a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H9l-6-7 6-7z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="m12 9.5 5 5m0-5-5 5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>';
  deleteKey.addEventListener("click", () => {
    if (busy) return;
    value = value.slice(0, -1);
    render();
  });
  keys.append(deleteKey);

  element.append(dots, live, keys);
  dots.addEventListener("animationend", () => element.classList.remove("shake"));

  function render() {
    [...dots.children].forEach((dot, i) => dot.classList.toggle("filled", i < value.length));
    live.textContent = `${value.length}桁 入力済み`;
    if (okKey) okKey.disabled = busy || value.length < 4;
  }

  function setBusy(next) {
    busy = next;
    element.classList.toggle("busy", next);
    for (const key of keys.querySelectorAll("button")) key.disabled = next;
    render();
  }

  function press(digit) {
    if (busy || value.length >= maxLength) return;
    value += digit;
    render();
    if (length && value.length === length) submit();
  }

  async function submit() {
    if (busy || value.length < 4) return;
    const code = value;
    setBusy(true);
    let ok = false;
    try {
      ok = await onComplete(code);
    } catch (error) {
      setGateError("通信できませんでした。接続を確認して、もう一度お試しください。");
    }
    if (activePad !== controller) return;
    setBusy(false);
    if (!ok) {
      value = "";
      render();
      element.classList.remove("shake");
      void element.offsetWidth;
      element.classList.add("shake");
      if (navigator.vibrate) navigator.vibrate(120);
    }
  }

  const onKeyDown = (event) => {
    if (event.target.closest?.("dialog") || event.metaKey || event.ctrlKey || event.altKey) return;
    if (/^\d$/.test(event.key)) {
      event.preventDefault();
      press(event.key);
    } else if (event.key === "Backspace") {
      event.preventDefault();
      if (!busy) {
        value = value.slice(0, -1);
        render();
      }
    } else if (event.key === "Enter" && !length) {
      event.preventDefault();
      submit();
    }
  };
  document.addEventListener("keydown", onKeyDown);

  const controller = {
    element,
    destroy() {
      document.removeEventListener("keydown", onKeyDown);
    },
  };
  activePad = controller;
  render();
  return controller;
}

function destroyActivePad() {
  if (activePad) activePad.destroy();
  activePad = null;
}

// サーバーと同じ基準 (同じ数字の繰り返し・連番は不可)
function passcodeTooSimple(passcode) {
  if (/^(\d)\1+$/.test(passcode)) return true;
  const digits = [...passcode].map(Number);
  const ascending = digits.every((digit, i) => i === 0 || digit === (digits[i - 1] + 1) % 10);
  const descending = digits.every((digit, i) => i === 0 || digit === (digits[i - 1] + 9) % 10);
  return ascending || descending;
}

function passcodeInput(labelText) {
  const label = document.createElement("label");
  const caption = document.createElement("span");
  caption.textContent = labelText;
  const input = document.createElement("input");
  input.type = "password";
  input.inputMode = "numeric";
  input.autocomplete = "off";
  input.pattern = "\\d*";
  input.maxLength = 6;
  input.className = "passcode-input";
  input.addEventListener("input", () => {
    input.value = input.value.replace(/\D/g, "").slice(0, input.maxLength);
  });
  label.append(caption, input);
  return { label, input };
}

function choiceGroup(name, options) {
  const element = document.createElement("div");
  element.className = "choice-group";
  element.setAttribute("role", "radiogroup");
  for (const option of options) {
    const label = document.createElement("label");
    const input = document.createElement("input");
    input.type = "radio";
    input.name = name;
    input.value = option.value;
    input.checked = Boolean(option.checked);
    const span = document.createElement("span");
    span.textContent = option.label;
    label.append(input, span);
    element.append(label);
  }
  return { element, value: () => element.querySelector("input:checked")?.value };
}

async function busy(target, action) {
  target.disabled = true;
  try {
    await action();
  } catch (error) {
    setGateError("通信できませんでした。接続を確認して、もう一度お試しください。");
  } finally {
    target.disabled = false;
  }
}

// ===========================================================================
// パスキー (WebAuthn)
// ===========================================================================

function passkeySupported() {
  return Boolean(window.PublicKeyCredential && navigator.credentials?.create && window.isSecureContext);
}

async function registerPasskey() {
  const { response, data } = await api("/api/mfa/passkey/register/options", { method: "POST", body: {} });
  if (!response.ok) return { ok: false, message: errorMessage(data) };

  let credential;
  try {
    credential = await navigator.credentials.create({
      publicKey: {
        ...data,
        challenge: base64UrlToBuffer(data.challenge),
        user: { ...data.user, id: base64UrlToBuffer(data.user.id) },
        excludeCredentials: data.excludeCredentials.map((item) => ({ ...item, id: base64UrlToBuffer(item.id) })),
      },
    });
  } catch (error) {
    return { ok: false, message: passkeyErrorMessage(error) };
  }
  if (!credential) return { ok: false, message: "パスキーを作成できませんでした。" };

  const body = {
    credential: {
      id: credential.id,
      rawId: bufferToBase64Url(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: bufferToBase64Url(credential.response.clientDataJSON),
        attestationObject: bufferToBase64Url(credential.response.attestationObject),
        transports: credential.response.getTransports?.() || [],
      },
    },
  };
  const result = await api("/api/mfa/passkey/register", { method: "POST", body });
  if (!result.response.ok) return { ok: false, message: errorMessage(result.data) };
  return { ok: true };
}

async function authenticateWithPasskey() {
  const { response, data } = await api("/api/mfa/passkey/auth/options", { method: "POST", body: {} });
  if (response.status === 423) return { ok: false, locked: true };
  if (!response.ok) return { ok: false, message: errorMessage(data) };

  let assertion;
  try {
    assertion = await navigator.credentials.get({
      publicKey: {
        ...data,
        challenge: base64UrlToBuffer(data.challenge),
        allowCredentials: data.allowCredentials.map((item) => ({ ...item, id: base64UrlToBuffer(item.id) })),
      },
    });
  } catch (error) {
    return { ok: false, message: passkeyErrorMessage(error) };
  }
  if (!assertion) return { ok: false, message: "パスキーを確認できませんでした。" };

  const body = {
    credential: {
      id: assertion.id,
      rawId: bufferToBase64Url(assertion.rawId),
      type: assertion.type,
      response: {
        clientDataJSON: bufferToBase64Url(assertion.response.clientDataJSON),
        authenticatorData: bufferToBase64Url(assertion.response.authenticatorData),
        signature: bufferToBase64Url(assertion.response.signature),
        userHandle: assertion.response.userHandle ? bufferToBase64Url(assertion.response.userHandle) : null,
      },
    },
  };
  const result = await api("/api/mfa/passkey/auth", { method: "POST", body });
  if (result.response.status === 423) return { ok: false, locked: true };
  if (!result.response.ok) {
    return { ok: false, message: errorMessage(result.data), remainingAttempts: result.data.remainingAttempts };
  }
  acceptVerification(result.data);
  return { ok: true };
}

function passkeyErrorMessage(error) {
  if (error?.name === "NotAllowedError") return "パスキーの確認がキャンセルされたか、時間切れになりました。";
  if (error?.name === "InvalidStateError") return "このパスキーはすでに登録されています。";
  if (error?.name === "NotSupportedError") return "この端末ではパスキーを使えません。パスコードを使ってください。";
  return "パスキーを使えませんでした。パスコードを使ってください。";
}

function base64UrlToBuffer(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(base64), (char) => char.charCodeAt(0)).buffer;
}

function bufferToBase64Url(buffer) {
  return bytesToBase64(new Uint8Array(buffer)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

// ===========================================================================
// 開いたときのロックが有効な人のオフライン用キャッシュ (v3)
// ===========================================================================

function rememberPendingPasscode(passcode) {
  forgetPendingPasscode();
  state.pendingPasscode = passcode;
  state.pendingPasscodeTimer = window.setTimeout(forgetPendingPasscode, 2 * 60 * 1000);
}

function forgetPendingPasscode() {
  if (state.pendingPasscodeTimer) window.clearTimeout(state.pendingPasscodeTimer);
  state.pendingPasscode = "";
  state.pendingPasscodeTimer = 0;
}

function readStoredCache() {
  try {
    return JSON.parse(localStorage.getItem(ACCOUNT_CACHE_KEY) || "null");
  } catch (error) {
    return null;
  }
}

async function cacheAccountsWithPasscode(payload, offlineKey) {
  try {
    const rawKey = new Uint8Array(base64UrlToBuffer(offlineKey));
    const kid = await keyId(rawKey);
    let wrap = null;
    try {
      wrap = JSON.parse(localStorage.getItem(OFFLINE_WRAP_KEY) || "null");
    } catch (error) {
      wrap = null;
    }

    // パスコードを入力した直後なら、オフライン用の鍵をパスコードで包み直す
    if (state.pendingPasscode) {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const wrappingKey = await passcodeKey(state.pendingPasscode, salt, ["encrypt"]);
      const wrapped = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, wrappingKey, rawKey);
      wrap = {
        v: 1,
        kid,
        len: state.pendingPasscode.length,
        salt: bytesToBase64(salt),
        iv: bytesToBase64(iv),
        data: bytesToBase64(new Uint8Array(wrapped)),
      };
      localStorage.setItem(OFFLINE_WRAP_KEY, JSON.stringify(wrap));
      localStorage.removeItem(OFFLINE_FAILURES_KEY);
      forgetPendingPasscode();
    }

    // この端末でまだパスコードを入力していない (パスキーだけ) ときは、オフライン用には保存しない
    if (!wrap || wrap.kid !== kid) {
      localStorage.removeItem(ACCOUNT_CACHE_KEY);
      localStorage.removeItem(OFFLINE_WRAP_KEY);
      return;
    }

    const key = await crypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["encrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: OFFLINE_CACHE_AAD },
      key,
      new TextEncoder().encode(JSON.stringify(payload)),
    );
    localStorage.setItem(
      ACCOUNT_CACHE_KEY,
      JSON.stringify({ v: 3, kid, iv: bytesToBase64(iv), data: bytesToBase64(new Uint8Array(ciphertext)) }),
    );
  } catch (error) {
    localStorage.removeItem(ACCOUNT_CACHE_KEY);
  }
}

function unlockOfflineCache(stored) {
  let wrap = null;
  try {
    wrap = JSON.parse(localStorage.getItem(OFFLINE_WRAP_KEY) || "null");
  } catch (error) {
    wrap = null;
  }
  if (!wrap || wrap.kid !== stored.kid) return Promise.resolve(null);

  els.workspace.classList.add("hidden");
  els.gate.classList.remove("hidden");
  els.gateUser.textContent = "オフライン";
  setGate("パスコードを入力", "オフラインのため、この端末に保存したデータをパスコードで開きます。パスキーはオフラインでは使えません。");
  setGateError("");

  return new Promise((resolve) => {
    const remainingHint = hint("");
    const showRemaining = () => {
      const failures = Number(localStorage.getItem(OFFLINE_FAILURES_KEY) || 0);
      remainingHint.textContent =
        failures > 0 ? `あと${MAX_ATTEMPTS - failures}回失敗すると、この端末に保存したデータを消去します。` : "";
    };
    showRemaining();

    const pad = passcodePad({
      length: wrap.len || null,
      onComplete: async (passcode) => {
        try {
          const wrappingKey = await passcodeKey(passcode, base64ToBytes(wrap.salt), ["decrypt"]);
          const rawKey = await crypto.subtle.decrypt({ name: "AES-GCM", iv: base64ToBytes(wrap.iv) }, wrappingKey, base64ToBytes(wrap.data));
          const key = await crypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["decrypt"]);
          const plain = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: base64ToBytes(stored.iv), additionalData: OFFLINE_CACHE_AAD },
            key,
            base64ToBytes(stored.data),
          );
          localStorage.removeItem(OFFLINE_FAILURES_KEY);
          const parsed = JSON.parse(new TextDecoder().decode(plain));
          els.gate.classList.add("hidden");
          resolve(Array.isArray(parsed) ? parsed.filter((account) => account.secret) : []);
          return true;
        } catch (error) {
          const failures = Number(localStorage.getItem(OFFLINE_FAILURES_KEY) || 0) + 1;
          if (failures >= MAX_ATTEMPTS) {
            await clearAccountCache();
            setGate("データを消去しました", `パスコードを${MAX_ATTEMPTS}回間違えたため、この端末に保存したデータを消去しました。オンラインに戻ってからログインしてください。`);
            destroyActivePad();
            els.gateBody.replaceChildren();
            setGateError("");
            return true;
          }
          localStorage.setItem(OFFLINE_FAILURES_KEY, String(failures));
          setGateError("パスコードが違います。");
          showRemaining();
          return false;
        }
      },
    });

    els.gateBody.replaceChildren(pad.element, remainingHint);
  });
}

async function passcodeKey(passcode, salt, usages) {
  const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(passcode), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERATIONS },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    usages,
  );
}

async function keyId(rawKey) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", rawKey));
  return bytesToBase64(digest.slice(0, 9));
}

// ===========================================================================
// セキュリティ設定
// ===========================================================================

async function openSettings() {
  if (state.offlineMode) {
    alert("オフライン中は設定を変更できません。");
    return;
  }
  for (const element of [els.unlockOnOpenStatus, els.passkeyStatus, els.passcodeChangeStatus]) setStatus(element, "");
  els.passcodeChangeForm.reset();
  els.unlockOnOpenToggle.checked = Boolean(state.me?.security?.unlockOnOpen);
  els.addPasskeyButton.classList.toggle("hidden", !passkeySupported());
  els.settingsDialog.showModal();
  await loadPasskeys();
}

async function updateUnlockOnOpen() {
  const value = els.unlockOnOpenToggle.checked;
  els.unlockOnOpenToggle.disabled = true;
  try {
    const { response, data } = await api("/api/mfa/preferences", { method: "POST", body: { unlockOnOpen: value } });
    if (await handleSettingsAccessError(response, data)) return;
    if (!response.ok) throw new Error(data.error);
    if (data.unlockToken) state.unlockToken = data.unlockToken;
    if (state.me?.security) state.me.security.unlockOnOpen = value;
    setStatus(
      els.unlockOnOpenStatus,
      value
        ? "オンにしました。オフラインでも使うには、次にロックを解除するときに、この端末でパスコードを入力してください。"
        : "オフにしました。",
    );
    state.lastSyncAt = 0;
  } catch (error) {
    els.unlockOnOpenToggle.checked = !value;
    setStatus(els.unlockOnOpenStatus, "変更できませんでした。", true);
  } finally {
    els.unlockOnOpenToggle.disabled = false;
  }
}

async function loadPasskeys() {
  els.passkeyList.replaceChildren();
  const { response, data } = await api("/api/mfa/passkeys");
  if (await handleSettingsAccessError(response, data)) return;
  if (!response.ok) {
    setStatus(els.passkeyStatus, "パスキーを読み込めませんでした。", true);
    return;
  }

  if (!data.passkeys.length) {
    const empty = document.createElement("li");
    empty.className = "empty";
    empty.textContent = "パスキーは登録されていません。";
    els.passkeyList.append(empty);
  }
  for (const passkey of data.passkeys) {
    const item = document.createElement("li");
    const text = document.createElement("div");
    const name = document.createElement("strong");
    name.textContent = passkey.name;
    const meta = document.createElement("small");
    meta.textContent = `登録 ${formatDate(passkey.createdAt)}・最終使用 ${passkey.lastUsedAt ? formatDate(passkey.lastUsedAt) : "なし"}`;
    text.append(name, meta);
    const remove = button("削除", "button", "danger small-button");
    remove.addEventListener("click", async () => {
      if (!confirm(`パスキー「${passkey.name}」を削除しますか？`)) return;
      remove.disabled = true;
      const result = await api(`/api/mfa/passkeys/${encodeURIComponent(passkey.id)}`, { method: "DELETE" });
      if (await handleSettingsAccessError(result.response, result.data)) return;
      setStatus(els.passkeyStatus, result.response.ok ? "削除しました。" : "削除できませんでした。", !result.response.ok);
      await loadPasskeys();
    });
    item.append(text, remove);
    els.passkeyList.append(item);
  }
  if (state.me?.security) state.me.security.passkeyCount = data.passkeys.length;
}

async function addPasskeyFromSettings() {
  els.addPasskeyButton.disabled = true;
  try {
    const result = await registerPasskey();
    setStatus(els.passkeyStatus, result.ok ? "パスキーを登録しました。" : result.message, !result.ok);
    if (result.ok) await loadPasskeys();
  } catch (error) {
    setStatus(els.passkeyStatus, "パスキーを登録できませんでした。", true);
  } finally {
    els.addPasskeyButton.disabled = false;
  }
}

async function changePasscodeFromSettings(event) {
  event.preventDefault();
  const current = els.currentPasscodeInput.value;
  const passcode = els.newPasscodeInput.value;
  if (!/^(\d{4}|\d{6})$/.test(passcode)) return setStatus(els.passcodeChangeStatus, "新しいパスコードは4桁か6桁の数字にしてください。", true);
  if (passcode !== els.confirmPasscodeInput.value) return setStatus(els.passcodeChangeStatus, "確認用の入力が一致しません。", true);

  const submit = els.passcodeChangeForm.querySelector("button[type=submit]");
  submit.disabled = true;
  try {
    const { response, data } = await api("/api/mfa/passcode/change", { method: "POST", body: { current, passcode } });
    if (response.status === 423) {
      els.settingsDialog.close();
      await requireSecurityAgain();
      return;
    }
    if (await handleSettingsAccessError(response, data)) return;
    if (!response.ok) return setStatus(els.passcodeChangeStatus, errorMessage(data), true);
    els.passcodeChangeForm.reset();
    rememberPendingPasscode(passcode);
    state.lastSyncAt = 0;
    setStatus(els.passcodeChangeStatus, "パスコードを変更しました。");
  } finally {
    submit.disabled = false;
  }
}

async function handleSettingsAccessError(response, data) {
  if (response.status === 401 && data.error !== "invalid_passcode" && data.error !== "invalid_passkey") {
    els.settingsDialog.close();
    els.adminDialog.close();
    await handleAccessError(response, data);
    return true;
  }
  if (response.status === 423) {
    els.settingsDialog.close();
    els.adminDialog.close();
    await requireSecurityAgain();
    return true;
  }
  return false;
}

function setStatus(element, message, isError = false) {
  element.textContent = message || "";
  element.classList.toggle("error", Boolean(isError && message));
}

// ===========================================================================
// 管理者: 利用者の管理
// ===========================================================================

const EVENT_LABELS = {
  discord_login: "Discord でログイン",
  passcode_set: "パスコードを登録",
  passcode_changed: "パスコードを変更",
  verified: "本人確認に成功",
  passcode_failed: "パスコードを間違えた",
  passcode_change_failed: "パスコードの変更で、今のパスコードを間違えた",
  passkey_failed: "パスキーの確認に失敗",
  passkey_added: "パスキーを追加",
  passkey_removed: "パスキーを削除",
  unlock_on_open: "開いたときのロックを変更",
  locked: "ロックされた",
  admin_unlock: "管理者がロックを解除",
  admin_lock: "管理者がロック",
  admin_reset: "管理者が2段階認証をリセット",
  admin_visibility: "管理者が、表示するアカウントを変更",
  admin_reorder: "管理者がアカウントの並び順を変更",
};

async function openAdmin() {
  if (state.offlineMode) {
    alert("オフライン中は管理画面を使えません。");
    return;
  }
  selectAdminTab("users");
  els.adminDialog.showModal();
  await reloadAdmin();
}

async function reloadAdmin() {
  // 利用者ごとの表示設定でアカウント一覧を使うので、先に読む
  await loadAdminAccounts();
  await loadAdminUsers();
}

function selectAdminTab(name) {
  const users = name === "users";
  els.adminUsersTab.setAttribute("aria-selected", String(users));
  els.adminOrderTab.setAttribute("aria-selected", String(!users));
  els.adminUsersTab.tabIndex = users ? 0 : -1;
  els.adminOrderTab.tabIndex = users ? -1 : 0;
  els.adminUsersPanel.hidden = !users;
  els.adminOrderPanel.hidden = users;
}

async function loadAdminAccounts() {
  const { response, data } = await api("/api/admin/accounts");
  if (await handleSettingsAccessError(response, data)) return;
  if (!response.ok) {
    setStatus(els.adminOrderStatus, "アカウントを読み込めませんでした。", true);
    return;
  }
  state.adminAccounts = data.accounts;
  state.adminOrder = [...data.accounts];
  setStatus(els.adminOrderStatus, data.accounts.length ? "" : "アカウントがまだありません。");
  renderAccountOrder();
}

function orderChanged() {
  return state.adminOrder.some((account, index) => account.id !== state.adminAccounts[index]?.id);
}

function renderAccountOrder(focus = null) {
  const items = state.adminOrder.map((account, index) => {
    const item = document.createElement("li");
    if (account.id !== state.adminAccounts[index]?.id) item.classList.add("moved");

    const name = document.createElement("div");
    name.className = "order-name";
    const title = document.createElement("strong");
    title.textContent = account.service;
    const sub = document.createElement("small");
    sub.textContent = `${account.account}・${account.role}`;
    name.append(title, sub);

    const buttons = document.createElement("div");
    buttons.className = "order-buttons";
    const move = (label, direction) => {
      const control = button(label, "button", "secondary");
      control.setAttribute("aria-label", `${account.service} ${account.account} を${direction < 0 ? "上" : "下"}へ`);
      control.dataset.id = String(account.id);
      control.dataset.direction = String(direction);
      control.disabled = direction < 0 ? index === 0 : index === state.adminOrder.length - 1;
      control.addEventListener("click", () => moveAccount(index, direction));
      return control;
    };
    buttons.append(move("上へ", -1), move("下へ", 1));
    item.append(name, buttons);
    return item;
  });
  els.adminOrderList.replaceChildren(...items);

  const changed = orderChanged();
  els.adminOrderSaveButton.disabled = !changed;
  els.adminOrderResetButton.disabled = !changed;

  // 動かしたあとも同じボタンにフォーカスを置き、続けて押せるようにする
  if (focus) {
    const target =
      els.adminOrderList.querySelector(`button[data-id="${focus.id}"][data-direction="${focus.direction}"]:not(:disabled)`) ||
      els.adminOrderList.querySelector(`button[data-id="${focus.id}"]:not(:disabled)`);
    target?.focus();
  }
}

function moveAccount(index, direction) {
  const target = index + direction;
  if (target < 0 || target >= state.adminOrder.length) return;
  const order = [...state.adminOrder];
  [order[index], order[target]] = [order[target], order[index]];
  state.adminOrder = order;
  setStatus(els.adminOrderStatus, "");
  renderAccountOrder({ id: order[target].id, direction });
}

async function saveAccountOrder() {
  els.adminOrderSaveButton.disabled = true;
  const ids = state.adminOrder.map((account) => account.id);
  const { response, data } = await api("/api/admin/accounts/order", { method: "POST", body: { ids } });
  if (await handleSettingsAccessError(response, data)) return;
  if (response.status === 409) {
    await loadAdminAccounts();
    setStatus(els.adminOrderStatus, "ほかの人がアカウントを追加・削除したため、保存できませんでした。最新の一覧を読み込んだので、もう一度並べ替えてください。", true);
    return;
  }
  if (!response.ok) {
    setStatus(els.adminOrderStatus, "保存できませんでした。", true);
    els.adminOrderSaveButton.disabled = false;
    return;
  }
  state.adminAccounts = [...state.adminOrder];
  renderAccountOrder();
  setStatus(els.adminOrderStatus, "並び順を保存しました。全員の一覧に反映されます。");
  // 自分の一覧もすぐ読み直す
  state.lastSyncAt = 0;
}

function renderVisibilityEditor(user, container, onSaved) {
  const list = document.createElement("div");
  list.className = "visibility-list";
  const status = document.createElement("p");
  status.className = "status-line";
  status.setAttribute("aria-live", "polite");
  container.append(list);

  (async () => {
    setStatus(status, "読み込んでいます…");
    const { response, data } = await api(`/api/admin/users/${user.id}/visibility`);
    if (await handleSettingsAccessError(response, data)) return;
    if (!response.ok) {
      setStatus(status, "読み込めませんでした。", true);
      container.append(status);
      return;
    }
    setStatus(status, "");
    if (!state.adminAccounts.length) {
      list.append(hint("アカウントがまだありません。"));
      return;
    }

    const hidden = new Set(data.hiddenAccountIds);
    const checkboxes = state.adminAccounts.map((account) => {
      const label = document.createElement("label");
      label.className = "check-row";
      const input = document.createElement("input");
      input.type = "checkbox";
      input.checked = !hidden.has(account.id);
      input.value = String(account.id);
      const text = document.createElement("span");
      text.textContent = account.service;
      const sub = document.createElement("small");
      sub.textContent = account.account;
      text.append(sub);
      label.append(input, text);
      list.append(label);
      return input;
    });

    const actions = document.createElement("div");
    actions.className = "visibility-actions";
    const all = button("すべて表示", "button", "link-button");
    all.addEventListener("click", () => checkboxes.forEach((input) => (input.checked = true)));
    const save = button("保存", "button", "small-button");
    save.addEventListener("click", async () => {
      save.disabled = true;
      const hiddenAccountIds = checkboxes.filter((input) => !input.checked).map((input) => Number(input.value));
      const result = await api(`/api/admin/users/${user.id}/visibility`, { method: "POST", body: { hiddenAccountIds } });
      save.disabled = false;
      if (await handleSettingsAccessError(result.response, result.data)) return;
      if (!result.response.ok) {
        setStatus(status, "保存できませんでした。", true);
        return;
      }
      setStatus(status, hiddenAccountIds.length ? `保存しました。${hiddenAccountIds.length}件を非表示にしています。` : "保存しました。すべて表示しています。");
      onSaved(hiddenAccountIds.length);
      if (user.id === state.me?.user?.id) state.lastSyncAt = 0;
    });
    actions.append(save, all, status);
    container.append(actions);
  })();
}

async function loadAdminUsers() {
  setStatus(els.adminStatus, "読み込んでいます…");
  const { response, data } = await api("/api/admin/users");
  if (await handleSettingsAccessError(response, data)) return;
  if (!response.ok) {
    setStatus(els.adminStatus, "読み込めませんでした。", true);
    return;
  }
  setStatus(els.adminStatus, `${data.users.length}人`);
  els.adminUserList.replaceChildren(...data.users.map(renderAdminUser));
}

function renderAdminUser(user) {
  const card = document.createElement("article");
  card.className = `admin-user${user.lockedAt ? " is-locked" : ""}`;
  const isSelf = user.id === state.me?.user?.id;

  const head = document.createElement("div");
  head.className = "admin-user-head";
  const name = document.createElement("div");
  name.className = "admin-user-name";
  name.textContent = `${user.globalName || user.username || user.id}${isSelf ? "（自分）" : ""}${user.isAdmin ? "・管理者" : ""}`;
  const sub = document.createElement("small");
  sub.textContent = `@${user.username || "-"} / ${user.id}`;
  name.append(sub);

  const pill = document.createElement("span");
  if (user.lockedAt) {
    pill.className = "pill danger";
    pill.textContent = user.lockReason === "admin" ? "管理者がロック中" : `${MAX_ATTEMPTS}回失敗でロック中`;
  } else if (!user.hasPasscode) {
    pill.className = "pill warn";
    pill.textContent = "2段階認証 未登録";
  } else {
    pill.className = "pill ok";
    pill.textContent = "利用中";
  }
  head.append(name, pill);

  const facts = document.createElement("dl");
  facts.className = "admin-facts";
  const addFact = (label, value) => {
    const wrapper = document.createElement("div");
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    dd.textContent = value;
    wrapper.append(dt, dd);
    facts.append(wrapper);
  };
  addFact("2段階認証", user.hasPasscode ? `パスコード${user.passkeyCount ? `＋パスキー${user.passkeyCount}個` : "のみ"}` : "なし");
  addFact("開いたときのロック", user.unlockOnOpen === null ? "未選択" : user.unlockOnOpen ? "オン" : "オフ");
  addFact("最終ログイン", user.lastLoginAt ? formatDate(user.lastLoginAt) : "-");
  addFact("最終確認", user.lastVerifiedAt ? formatDate(user.lastVerifiedAt) : "-");
  addFact("連続失敗", `${user.failedAttempts}回${user.lastFailedAt ? `（最後 ${formatDate(user.lastFailedAt)}）` : ""}`);
  if (user.lockedAt) addFact("ロック日時", formatDate(user.lockedAt));
  const visibilityText = (count) => (count ? `${count}件を非表示` : "すべて");
  addFact("表示するアカウント", visibilityText(user.hiddenAccountCount));
  const visibilityFact = facts.lastElementChild.querySelector("dd");

  const actions = document.createElement("div");
  actions.className = "admin-actions";
  const action = (label, path, message, className = "secondary small-button") => {
    const element = button(label, "button", className);
    element.addEventListener("click", async () => {
      if (!confirm(message)) return;
      element.disabled = true;
      const result = await api(`/api/admin/users/${user.id}/${path}`, { method: "POST", body: {} });
      if (await handleSettingsAccessError(result.response, result.data)) return;
      if (!result.response.ok) {
        setStatus(els.adminStatus, errorMessage(result.data), true);
        element.disabled = false;
        return;
      }
      if (isSelf && path === "reset") {
        location.reload();
        return;
      }
      await loadAdminUsers();
    });
    actions.append(element);
  };
  const displayName = user.globalName || user.username || user.id;
  if (user.lockedAt) action("ロックを解除", "unlock", `${displayName} のロックを解除しますか？`, "small-button");
  if (user.hasPasscode || user.passkeyCount) {
    action(
      "2段階認証をリセット",
      "reset",
      `${displayName} のパスコードとパスキーを削除し、ログイン中のセッションも無効にします。次にログインするときに、登録し直す必要があります。よろしいですか？`,
    );
  }
  if (!user.lockedAt && !isSelf) {
    action(
      "ロックして強制ログアウト",
      "lock",
      `${displayName} をロックし、ログイン中のセッションも無効にします。解除するまで使えなくなります。よろしいですか？`,
      "danger small-button",
    );
  }

  const visibility = document.createElement("details");
  visibility.className = "admin-events";
  const visibilitySummary = document.createElement("summary");
  visibilitySummary.textContent = "表示するアカウント";
  visibility.append(visibilitySummary);
  visibility.addEventListener("toggle", () => {
    if (!visibility.open || visibility.dataset.loaded) return;
    visibility.dataset.loaded = "1";
    renderVisibilityEditor(user, visibility, (count) => {
      visibilityFact.textContent = visibilityText(count);
    });
  });

  const events = document.createElement("details");
  events.className = "admin-events";
  const summary = document.createElement("summary");
  summary.textContent = "ログイン・認証の履歴";
  const list = document.createElement("ol");
  events.append(summary, list);
  events.addEventListener("toggle", async () => {
    if (!events.open || list.childElementCount) return;
    const result = await api(`/api/admin/users/${user.id}/events`);
    if (!result.response.ok) {
      list.append(Object.assign(document.createElement("li"), { textContent: "読み込めませんでした。" }));
      return;
    }
    if (!result.data.events.length) {
      list.append(Object.assign(document.createElement("li"), { textContent: "履歴はありません。" }));
    }
    for (const event of result.data.events) {
      const item = document.createElement("li");
      const time = document.createElement("time");
      time.textContent = formatDate(event.createdAt);
      const text = document.createElement("span");
      const detail = event.detail ? `（${eventDetailLabel(event.detail)}）` : "";
      const where = [event.ip, event.country].filter(Boolean).join(" / ");
      text.textContent = `${EVENT_LABELS[event.event] || event.event}${detail}${where ? ` — ${where}` : ""}`;
      item.append(time, text);
      list.append(item);
    }
  });

  card.append(head, facts, actions, visibility, events);
  return card;
}

const EVENT_DETAIL_LABELS = {
  too_many_attempts: `${MAX_ATTEMPTS}回失敗`,
  admin: "管理者",
  on: "オン",
  off: "オフ",
  passcode: "パスコード",
  passkey: "パスキー",
};

// パスキーの検証で失敗した理由 (signature_invalid など) は管理者向けにまとめて表示する
function eventDetailLabel(detail) {
  if (!detail) return "";
  if (EVENT_DETAIL_LABELS[detail]) return EVENT_DETAIL_LABELS[detail];
  if (/^\d+\/\d+$/.test(detail)) return `${detail.split("/")[0]}回目`;
  if (/^\d+$/.test(detail)) return `${detail}件を非表示`;
  if (/^[a-z_]+$/.test(detail)) return "検証エラー";
  return detail;
}

// D1 の CURRENT_TIMESTAMP は UTC の "YYYY-MM-DD HH:MM:SS"
function formatDate(value) {
  if (!value) return "-";
  const date = new Date(String(value).includes("T") ? value : `${String(value).replace(" ", "T")}Z`);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat("ja-JP", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

// パスコード画面の表示に合わせて、後ろのページのスクロールを止める
function syncGateScrollLock() {
  const update = () => document.documentElement.classList.toggle("gate-open", !els.gate.classList.contains("hidden"));
  new MutationObserver(update).observe(els.gate, { attributes: true, attributeFilter: ["class"] });
  update();
}
