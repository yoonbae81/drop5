(async () => {
  // Session state
  const pathParts = location.pathname.split('/').filter(Boolean);
  // The last path segment is always the session code; everything before it is
  // the deployment base path (e.g. /drop5/<code> -> base=/drop5, code=<code>).
  const SESSION_CODE = pathParts[pathParts.length - 1] || '';
  const BASE_URL = pathParts.length > 1 ? '/' + pathParts.slice(0, -1).join('/') : '';
  const apiUrl = () => {
    const currentPath = location.pathname.replace(/\/+$/, '');
    return `${currentPath}`;
  };

  const locale = document.documentElement.lang || 'en';
  async function loadLocale(code) {
    const response = await fetch(`${BASE_URL}/locales/${encodeURIComponent(code)}.json`, { cache: 'force-cache' });
    if (!response.ok) throw new Error(`Locale ${code} returned ${response.status}`);
    return response.json();
  }
  const englishPromise = loadLocale('en').catch(() => ({}));
  const [english, selected] = await Promise.all([
    englishPromise,
    locale === 'en' ? Promise.resolve({}) : loadLocale(locale).catch(() => ({})),
  ]);
  const TRANSLATIONS = { ...english, ...selected };
  const interpolate = (template, params = {}) => String(template).replace(
    /\{\{([A-Za-z0-9_]+)\}\}|\{([A-Za-z0-9_]+)\}/g,
    (token, doubleKey, singleKey) => Object.hasOwn(params, doubleKey || singleKey)
      ? String(params[doubleKey || singleKey])
      : token,
  );
  const t = (key, params = {}) => interpolate(TRANSLATIONS[key] || key, params);
  document.querySelectorAll('[data-i18n]').forEach(node => {
    const translated = TRANSLATIONS[node.dataset.i18n];
    if (translated) node.innerHTML = translated;
  });
  for (const attribute of ['title', 'placeholder', 'aria-label']) {
    document.querySelectorAll(`[data-i18n-${attribute}]`).forEach(node => {
      const key = node.getAttribute(`data-i18n-${attribute}`);
      if (TRANSLATIONS[key]) node.setAttribute(attribute, TRANSLATIONS[key]);
    });
  }

  let CLIENT_ID = sessionStorage.getItem('drop5_client_id');
  if (!CLIENT_ID) {
    CLIENT_ID = crypto.randomUUID();
    sessionStorage.setItem('drop5_client_id', CLIENT_ID);
  }

  let isApproved = false;
  let pendingRequests = [];
  let pollTimer = null;
  let pollBackoffMs = 4000;
  const FALLBACK_POLL_MAX_MS = 30000;
  let pollInFlight = false;
  let lastSyncHash = '';
  let isUploading = false;

  // DOM elements
  const dropZone = document.getElementById('dropZone');
  const progressOverlay = document.getElementById('progressOverlay');
  const toast = document.getElementById('toast');
  const themeToggle = document.getElementById('themeToggle');
  const themeIcon = document.getElementById('themeIcon');
  const fileInput = document.getElementById('fileInput');
  const progressBar = document.getElementById('progressBar');
  const progressContainer = document.getElementById('progressContainer');
  const progressText = document.getElementById('progressText');

  function apiError(data, status) {
    if (data.errorKey === 'file_too_large_with_max' && Array.isArray(data.files)) {
      const maxMb = data.errorParams && data.errorParams.max_mb;
      return data.files.map(file => t(data.errorKey, {
        filename: file.name,
        max_mb: maxMb ?? Math.floor(Number(file.maxBytes) / (1024 * 1024)),
      })).join('\n');
    }
    if (data.errorKey) return t(data.errorKey, data.errorParams || {});
    return data.error || `Request failed (${status})`;
  }

  // Theme management
  function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return null;
  }
  function setCookie(name, value, days) {
    const expires = new Date();
    expires.setTime(expires.getTime() + (days * 24 * 60 * 60 * 1000));
    document.cookie = `${name}=${value};expires=${expires.toUTCString()};path=/`;
  }
  function isNightTime() {
    const hour = new Date().getHours();
    return hour >= 20 || hour < 7;
  }
  function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    if (themeIcon) themeIcon.textContent = theme === 'dark' ? '☀️' : '🌙';
    setCookie('theme', theme, 365);
  }
  function initTheme() {
    const savedTheme = getCookie('theme');
    setTheme(savedTheme || (isNightTime() ? 'dark' : 'light'));
  }
  function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme');
    setTheme(currentTheme === 'dark' ? 'light' : 'dark');
  }
  if (themeToggle) themeToggle.addEventListener('click', toggleTheme);

  // Language toggle: switch between current locale and the native counterpart
  // (original behavior: en <-> native, native defaults to ko like the Python app).
  const nativeLocale = (() => {
    const cookieLocale = (() => {
      const match = document.cookie.match(/(?:^|;\s*)drop5_lang=([A-Za-z-]+)/);
      return match ? match[1] : null;
    })();
    if (cookieLocale && cookieLocale !== 'en') return cookieLocale;
    // Original app derives "native" from IP; Accept-Language is its fallback.
    const accept = navigator.language || 'ko';
    const candidate = accept.split(',')[0].trim().split('-')[0];
    return candidate === 'en' || !candidate ? 'ko' : candidate;
  })();
  const langToggle = document.getElementById('langToggle');
  if (langToggle) {
    langToggle.addEventListener('click', () => {
      const target = locale === 'en' ? nativeLocale : 'en';
      // Max-age so the cookie is not a session cookie; path=/ covers base paths.
      document.cookie = `drop5_lang=${target};path=/;max-age=${365 * 24 * 60 * 60};samesite=lax`;
      location.reload();
    });
  }

  function showToast(message) {
    if (!toast) return;
    toast.textContent = message;
    toast.classList.add('show');
    setTimeout(() => { toast.classList.remove('show'); }, 3000);
  }

  function formatSize(sizeBytes) {
    if (sizeBytes < 1024 * 1024) return `${(sizeBytes / 1024).toFixed(1)} kB`;
    return `${(sizeBytes / (1024 * 1024)).toFixed(1)} MB`;
  }

  function formatBrowserInfo(ua) {
    if (!ua || ua === 'Unknown') return 'Unknown Browser';
    let browser = 'Browser';
    let os = 'OS';
    if (ua.includes('Windows NT 10.')) os = 'Windows 10/11';
    else if (ua.includes('Windows NT 6.1')) os = 'Windows 7';
    else if (ua.includes('Macintosh')) os = 'macOS';
    else if (ua.includes('iPhone')) os = 'iPhone';
    else if (ua.includes('iPad')) os = 'iPad';
    else if (ua.includes('Android')) os = 'Android';
    else if (ua.includes('Linux')) os = 'Linux';
    if (ua.includes('Edg/')) browser = 'Edge';
    else if (ua.includes('Chrome/')) browser = 'Chrome';
    else if (ua.includes('Firefox/')) browser = 'Firefox';
    else if (ua.includes('Safari/') && !ua.includes('Chrome/')) browser = 'Safari';
    return `${browser} on ${os}`;
  }

  // Countdown timer - update display every second
  function updateCountdownDisplay() {
    document.querySelectorAll('.file-card[data-remaining]').forEach(card => {
      let remaining = parseInt(card.dataset.remaining, 10);
      if (Number.isNaN(remaining) || remaining <= 0) {
        card.style.display = 'none';
        return;
      }
      remaining--;
      card.dataset.remaining = remaining;
      const timerSpan = card.querySelector('.countdown-timer');
      if (timerSpan) {
        const minutes = Math.floor(remaining / 60);
        const seconds = remaining % 60;
        timerSpan.textContent = `${minutes}m ${seconds.toString().padStart(2, '0')}s`;
        const timeBadge = card.querySelector('.time-badge');
        if (remaining < 60) timeBadge.classList.remove('safe');
        else timeBadge.classList.add('safe');
      }
    });
  }

  // --- Session management & polling ---

  function updateSessionState(status) {
    const waitingOverlay = document.getElementById('waitingOverlay');
    if (status === 'approved') {
      isApproved = true;
      if (waitingOverlay) waitingOverlay.style.display = 'none';
    } else if (status === 'pending') {
      isApproved = false;
      if (waitingOverlay) {
        waitingOverlay.style.display = 'flex';
        const title = waitingOverlay.querySelector('.waiting-title');
        const desc = waitingOverlay.querySelector('.waiting-desc');
        if (title) title.textContent = t('waiting_host_approval');
        if (desc) desc.innerHTML = t('waiting_approval_desc');
        const icon = waitingOverlay.querySelector('.waiting-icon');
        if (icon) icon.textContent = '🔒';
      }
    } else if (status === 'rejected') {
      isApproved = false;
      if (waitingOverlay) {
        waitingOverlay.style.display = 'flex';
        const title = waitingOverlay.querySelector('.waiting-title');
        const desc = waitingOverlay.querySelector('.waiting-desc');
        if (title) title.textContent = t('host_refused_connection') !== 'host_refused_connection' ? t('host_refused_connection') : 'Connection refused';
        if (desc) desc.textContent = '';
        const icon = waitingOverlay.querySelector('.waiting-icon');
        if (icon) icon.textContent = '🚫';
      }
    }
  }

  function showApprovalModal() {
    const modal = document.getElementById('approvalModal');
    const infoDiv = document.getElementById('approvalDeviceInfo');
    if (infoDiv && pendingRequests.length > 0) {
      const req = pendingRequests[0];
      infoDiv.textContent = `${req.ip ?? 'Unknown'} • ${formatBrowserInfo(req.browser)}`;
    }
    if (modal && !modal.classList.contains('show')) {
      modal.classList.add('show');
      setTimeout(() => {
        const approveBtn = modal.querySelector('.btn-approve');
        if (approveBtn) approveBtn.focus();
      }, 400);
    }
  }

  function hideApprovalModal() {
    const modal = document.getElementById('approvalModal');
    if (modal && modal.classList.contains('show')) modal.classList.remove('show');
  }

  async function handleApprovalDecision(decision) {
    if (pendingRequests.length === 0) return;
    const target = pendingRequests[0];
    try {
      const response = await fetch(`${apiUrl()}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ clientId: CLIENT_ID, targetId: target.clientId, decision }),
      });
      const data = await response.json();
      if (data.success) {
        pendingRequests.shift();
        if (pendingRequests.length === 0) hideApprovalModal();
        else showApprovalModal();
      }
    } catch (error) {
      console.error('Approval error:', error);
    }
  }
  document.querySelectorAll('#approvalModal .btn-approve').forEach(btn => btn.addEventListener('click', () => handleApprovalDecision('approve')));
  document.querySelectorAll('#approvalModal .btn-reject').forEach(btn => btn.addEventListener('click', () => handleApprovalDecision('reject')));

  function applyPendingRequests(pending) {
    const incoming = pending || [];
    // Reconcile by clientId: never duplicate an approval-modal entry that a
    // WebSocket event already added, and drop entries the server no longer
    // reports as pending (already approved, rejected, or removed).
    const pendingIds = new Set(incoming.map(req => req.clientId));
    if (incoming.length > 0) {
      pendingRequests = pendingRequests.filter(req => pendingIds.has(req.clientId));
      const known = new Set(pendingRequests.map(req => req.clientId));
      for (const req of incoming) {
        if (!known.has(req.clientId)) {
          pendingRequests.push(req);
          known.add(req.clientId);
        }
      }
    }
    if (isApproved && pendingRequests.length > 0) showApprovalModal();
    else hideApprovalModal();
  }

  async function joinSession() {
    try {
      const response = await fetch(`${apiUrl()}/join`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ clientId: CLIENT_ID, userAgent: navigator.userAgent }),
      });
      const data = await response.json();
      if (data.success) {
        updateSessionState(data.status);
        applyPendingRequests(data.pending_requests);
        connectWebSocket();
      } else {
        console.error('Join failed:', data.error);
      }
    } catch (error) {
      console.error('Join error:', error);
    }
  }

  // --- Fallback polling (ONLY while the WebSocket is not open) ---
  // When the socket is down, a slow bounded exponential poll keeps state
  // roughly fresh. When the socket is open, updates are event-driven and no
  // periodic HTTP heartbeat/files traffic runs at all.

  function stopFallbackPolling() {
    if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
  }

  function startFallbackPolling() {
    if (webSocket) return;
    stopFallbackPolling();
    pollLoop();
  }

  async function pollLoop() {
    if (webSocket) return;
    await pollSessionState();
    if (webSocket) return; // socket came back while the request was in flight
    pollTimer = setTimeout(pollLoop, pollBackoffMs);
    pollBackoffMs = Math.min(pollBackoffMs * 2, FALLBACK_POLL_MAX_MS);
  }

  async function pollSessionState() {
    if (pollInFlight) return;
    pollInFlight = true;
    try {
      const response = await fetch(`${apiUrl()}/heartbeat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ clientId: CLIENT_ID }),
      });
      const data = await response.json();
      if (data.success) {
        updateSessionState(data.status);
        applyPendingRequests(data.pending_requests);
        if (isApproved) syncFiles();
      }
    } catch (error) {
      console.error('Polling error:', error);
    } finally {
      pollInFlight = false;
    }
  }

  // --- WebSocket: the event-driven path ---
  // Lifecycle: one socket at a time, one reconnect timer at a time, a timeout
  // for sockets stuck in CONNECTING, and stale sockets from a previous
  // generation can never schedule reconnects or apply updates.

  let webSocket = null;
  let webSocketBackoffMs = 2000;
  const WEB_SOCKET_BACKOFF_MAX_MS = 30000;
  const CONNECT_TIMEOUT_MS = 15000;
  let reconnectTimer = null;
  let connectTimer = null;
  let socketGeneration = 0;
  let connectSyncInFlight = false;

  function clearReconnectTimer() {
    if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
  }

  function clearConnectTimer() {
    if (connectTimer) { clearTimeout(connectTimer); connectTimer = null; }
  }

  // One synchronization per connection: refresh approval status / pending
  // requests, then pull the initial-or-reconnect file snapshot.
  async function synchronizeOnConnect() {
    if (connectSyncInFlight) return;
    connectSyncInFlight = true;
    try {
      const response = await fetch(`${apiUrl()}/heartbeat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ clientId: CLIENT_ID }),
      });
      const data = await response.json();
      if (data.success) {
        updateSessionState(data.status);
        applyPendingRequests(data.pending_requests);
      }
    } catch (error) {
      console.error('Socket sync error:', error);
    }
    // Force a fresh render: the list may have changed while disconnected.
    lastSyncHash = '';
    await syncFiles();
    connectSyncInFlight = false;
  }

  function handleSocketDown() {
    if (webSocket) {
      webSocket = null;
      clearConnectTimer();
      // Slow bounded fallback polling covers the disconnected window.
      startFallbackPolling();
      // Exactly one reconnect timer may be pending at any time.
      clearReconnectTimer();
      reconnectTimer = setTimeout(connectWebSocket, webSocketBackoffMs);
      webSocketBackoffMs = Math.min(webSocketBackoffMs * 2, WEB_SOCKET_BACKOFF_MAX_MS);
    }
  }

  function connectWebSocket() {
    if (webSocket) return;
    clearReconnectTimer();
    const generation = ++socketGeneration;
    try {
      const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const socket = new WebSocket(`${scheme}//${location.host}${apiUrl()}/ws?clientId=${encodeURIComponent(CLIENT_ID)}`);
      webSocket = socket;
      const isCurrent = () => webSocket === socket && generation === socketGeneration;
      // A socket stuck in CONNECTING must not stall the session forever.
      clearConnectTimer();
      connectTimer = setTimeout(() => {
        if (webSocket === socket && socket.readyState === 0) {
          try { socket.close(); } catch { /* already dead */ }
        }
      }, CONNECT_TIMEOUT_MS);
      socket.onopen = () => {
        if (!isCurrent()) return;
        clearConnectTimer();
        webSocketBackoffMs = 2000;
        pollBackoffMs = 4000;
        // Event-driven from here: no periodic polling while the socket is open.
        stopFallbackPolling();
        synchronizeOnConnect();
      };
      socket.onmessage = async event => {
        if (!isCurrent()) return; // stale event from a previous socket
        webSocketBackoffMs = 2000;
        const message = JSON.parse(event.data);
        if (message.type === 'client-joined' && isApproved) {
          if (!pendingRequests.some(req => req.clientId === message.client.clientId)) {
            pendingRequests.push(message.client);
            showApprovalModal();
          }
        }
        if (message.type === 'client-approved' && message.clientId === CLIENT_ID) {
          updateSessionState('approved');
          syncFiles();
        }
        if (message.type === 'client-rejected' && message.clientId === CLIENT_ID) {
          updateSessionState('rejected');
        }
        if (['file-uploaded', 'file-deleted', 'file-expired'].includes(message.type) && isApproved) syncFiles();
      };
      socket.onclose = () => {
        if (webSocket !== socket) return; // superseded socket: no stale reconnect
        handleSocketDown();
      };
      socket.onerror = () => { /* onclose fires for real failures. */ };
    } catch {
      // Polling keeps the session alive without WebSockets.
      handleSocketDown();
    }
  }

  // Visibility and connectivity changes drive immediate reconnection attempts
  // instead of waiting out the backoff.
  if (typeof document.addEventListener === 'function') {
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible' && !webSocket) {
        webSocketBackoffMs = 2000;
        pollBackoffMs = 4000;
        connectWebSocket();
      }
    });
  }
  if (typeof window.addEventListener === 'function') {
    window.addEventListener('offline', () => {
      // Going offline: cancel pending reconnects and paused-interval polling.
      clearReconnectTimer();
      stopFallbackPolling();
    });
    window.addEventListener('online', () => {
      if (!webSocket) {
        webSocketBackoffMs = 2000;
        pollBackoffMs = 4000;
        connectWebSocket();
      }
    });
  }

  // --- Files ---
  function updateFileListUI(files) {
    const fileItems = document.getElementById('fileItems');
    if (!fileItems) return;

    const currentHash = files.map(file => `${file.id}:${Math.ceil((file.expiresAt - Date.now()) / 1000)}`).join('|');
    if (currentHash === lastSyncHash) return;
    lastSyncHash = currentHash;

    const deleteAllBtn = document.getElementById('deleteAllBtn');
    if (deleteAllBtn) deleteAllBtn.classList.toggle('show', files.length > 0);

    if (files.length === 0) {
      fileItems.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon">📭</div>
          <div class="upload-text">${t('no_files_yet')}</div>
        </div>`;
      return;
    }

    const grid = document.createElement('div');
    grid.className = 'file-grid';

    files.forEach(file => {
      const remaining = Math.max(0, Math.ceil((file.expiresAt - Date.now()) / 1000));
      const card = document.createElement('a');
      card.href = `${apiUrl()}/download/${encodeURIComponent(file.id)}?clientId=${encodeURIComponent(CLIENT_ID)}`;
      card.className = 'file-card';
      card.setAttribute('download', '');
      card.dataset.remaining = remaining;

      const icon = document.createElement('div');
      icon.className = 'file-icon';
      icon.textContent = '📄';

      const name = document.createElement('div');
      name.className = 'file-name';
      name.title = file.name;
      name.textContent = file.name;

      const meta = document.createElement('div');
      meta.className = 'file-meta';

      const size = document.createElement('span');
      size.style.whiteSpace = 'nowrap';
      size.textContent = formatSize(file.size);

      const timeBadge = document.createElement('div');
      timeBadge.className = 'time-badge';
      if (remaining >= 60) timeBadge.classList.add('safe');

      const timerSpan = document.createElement('span');
      timerSpan.className = 'countdown-timer';
      timerSpan.textContent = `${Math.floor(remaining / 60)}m ${remaining % 60}s`;

      timeBadge.textContent = '⏱️ ';
      timeBadge.appendChild(timerSpan);

      meta.appendChild(size);
      meta.appendChild(timeBadge);
      card.appendChild(icon);
      card.appendChild(name);
      card.appendChild(meta);
      grid.appendChild(card);
    });

    fileItems.innerHTML = '';
    fileItems.appendChild(grid);
  }

  async function syncFiles() {
    if (progressOverlay && progressOverlay.style.display === 'flex') return;
    if (!isApproved) return;
    try {
      const response = await fetch(`${apiUrl()}/files?clientId=${encodeURIComponent(CLIENT_ID)}&_=${Date.now()}`, { cache: 'no-store' });
      if (response.status === 403) return;
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      if (data.success && data.files) updateFileListUI(data.files);
    } catch (error) {
      console.warn('Sync failed:', error.message);
    }
  }

  // --- Uploads ---
  async function uploadFiles(files) {
    if (isUploading) return;
    const maxFileBytes = Number(dropZone?.dataset.maxFileBytes);
    if (Number.isFinite(maxFileBytes) && maxFileBytes > 0) {
      for (const file of files) {
        if (file.size > maxFileBytes) {
          showToast(`❌ ${t('file_too_large_with_max', { filename: file.name, max_mb: Math.floor(maxFileBytes / (1024 * 1024)) })}`);
          return;
        }
      }
    }

    isUploading = true;
    if (progressOverlay) {
      progressOverlay.style.display = 'flex';
      if (progressContainer) progressContainer.style.display = 'block';
      if (progressBar) progressBar.style.width = '0%';
      if (progressText) progressText.textContent = t('preparing');
    }

    const totalFiles = files.length;
    const formData = new FormData();
    for (const file of files) {
      let fileName = file.name;
      if (fileName.normalize) fileName = fileName.normalize('NFC');
      formData.append('content', file, fileName);
    }
    formData.append('clientId', CLIENT_ID);

    try {
      const finalData = await new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.upload.addEventListener('progress', event => {
          if (!event.lengthComputable) return;
          const percent = Math.round((event.loaded / event.total) * 100);
          if (progressBar) progressBar.style.width = `${percent}%`;
          if (progressText) {
            progressText.textContent = totalFiles > 1
              ? t('upload_progress_multiple', { count: totalFiles, percent })
              : t('upload_progress_single', { percent });
          }
        });
        xhr.onload = () => {
          let payload = {};
          try { payload = JSON.parse(xhr.responseText); } catch { /* handled below */ }
          if (xhr.status >= 200 && xhr.status < 300) resolve(payload);
          else reject(new Error(apiError(payload, xhr.status)));
        };
        xhr.onerror = () => reject(new Error(t('network_error')));
        xhr.onabort = () => reject(new Error(t('upload_aborted')));
        xhr.ontimeout = () => reject(new Error(t('upload_timeout')));
        xhr.open('POST', `${apiUrl()}/upload`);
        xhr.send(formData);
      });
      if (progressBar) progressBar.style.width = '100%';
      if (progressText) progressText.textContent = t('upload_complete');
      if (finalData.success) {
        // Hide the progress overlay first: syncFiles() skips while it is
        // visible, so awaiting it before this would be a no-op and the new
        // file would only appear on the next 4s polling tick.
        if (progressOverlay) progressOverlay.style.display = 'none';
        isUploading = false;
        await syncFiles();
      } else {
        throw new Error(apiError(finalData, 200));
      }
    } catch (error) {
      console.error('Upload error:', error);
      showToast(`❌ ${error.message}`);
      if (progressOverlay) progressOverlay.style.display = 'none';
      isUploading = false;
    }
  }

  async function deleteAllFiles() {
    const cards = document.querySelectorAll('.file-card');
    if (cards.length === 0) return;

    cards.forEach((card, index) => {
      setTimeout(() => { card.classList.add('falling'); }, index * 50);
    });

    const deleteAllBtn = document.getElementById('deleteAllBtn');
    if (deleteAllBtn) deleteAllBtn.classList.remove('show');

    await new Promise(resolve => setTimeout(resolve, 800));

    try {
      const response = await fetch(`${apiUrl()}/delete_all`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ clientId: CLIENT_ID }),
      });
      const data = await response.json();
      if (data.success) {
        lastSyncHash = '';
        await syncFiles();
      }
    } catch (error) {
      console.error('Error:', error);
      showToast(`❌ ${t('delete_failed')}`);
    }
  }
  const deleteAllBtn = document.getElementById('deleteAllBtn');
  if (deleteAllBtn) deleteAllBtn.addEventListener('click', deleteAllFiles);

  // Text modal
  const textModal = document.getElementById('textModal');
  const textInputTextArea = document.getElementById('textInputTextArea');
  const openTextModal = event => {
    if (event) event.stopPropagation();
    if (textModal) {
      textModal.classList.add('show');
      setTimeout(() => { if (textInputTextArea) textInputTextArea.focus(); }, 100);
    }
  };
  window.closeTextModal = () => { if (textModal) textModal.classList.remove('show'); };
  window.openTextModal = openTextModal;
  const textInputBtn = document.getElementById('textInputBtn');
  if (textInputBtn) textInputBtn.addEventListener('click', openTextModal);
  const closeTextModalBtn = document.getElementById('closeTextModal');
  if (closeTextModalBtn) closeTextModalBtn.addEventListener('click', window.closeTextModal);
  if (textModal) {
    textModal.addEventListener('click', event => { if (event.target === textModal) window.closeTextModal(); });
  }
  if (textInputTextArea) {
    textInputTextArea.addEventListener('keydown', event => {
      if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) {
        event.preventDefault();
        saveText();
      }
    });
  }

  async function saveText() {
    const text = textInputTextArea ? textInputTextArea.value : '';
    if (!text.trim()) {
      showToast(`❌ ${t('enter_content')}`);
      return;
    }
    const saveBtn = document.querySelector('.save-text-btn');
    const originalText = saveBtn ? saveBtn.textContent : '';
    if (saveBtn) { saveBtn.textContent = t('text_uploading'); saveBtn.disabled = true; }

    try {
      const response = await fetch(`${apiUrl()}/upload`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: text, clientId: CLIENT_ID }),
      });
      const data = await response.json();
      if (!data.success) throw new Error(apiError(data, response.status));
      showToast(`✅ ${t('text_file_created')}`);
      if (textInputTextArea) textInputTextArea.value = '';
      window.closeTextModal();
      lastSyncHash = '';
      await syncFiles();
    } catch (error) {
      console.error('Text upload error:', error);
      showToast(`❌ ${t('save_failed_prefix')} ${error.message}`);
    } finally {
      if (saveBtn) { saveBtn.textContent = originalText; saveBtn.disabled = false; }
    }
  }
  const saveTextBtn = document.getElementById('saveTextBtn');
  if (saveTextBtn) saveTextBtn.addEventListener('click', saveText);

  // Session code copy link
  const sessionCodeEl = document.getElementById('sessionCode');
  function copyURL() {
    navigator.clipboard.writeText(location.href).then(() => {
      showToast(`✅ ${t('link_copied')}`);
    }).catch(() => {
      showToast(`❌ ${t('copy_failed')}`);
    });
  }
  if (sessionCodeEl) {
    sessionCodeEl.textContent = `${SESSION_CODE} 🔗`;
    sessionCodeEl.addEventListener('click', copyURL);
    sessionCodeEl.addEventListener('keydown', event => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        copyURL();
      }
    });
  }

  // Drag & drop
  if (dropZone) {
    dropZone.addEventListener('click', event => {
      if (event.target === textInputBtn) return;
      if (fileInput) fileInput.click();
    });
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
      dropZone.addEventListener(eventName, event => {
        event.preventDefault();
        event.stopPropagation();
      }, false);
    });
    ['dragenter', 'dragover'].forEach(eventName => {
      dropZone.addEventListener(eventName, () => dropZone.classList.add('dragover'), false);
    });
    ['dragleave', 'drop'].forEach(eventName => {
      dropZone.addEventListener(eventName, () => dropZone.classList.remove('dragover'), false);
    });
    dropZone.addEventListener('drop', event => {
      if (event.dataTransfer.files.length > 0) uploadFiles(event.dataTransfer.files);
    }, false);
    dropZone.addEventListener('keydown', event => {
      if (event.key === 'Enter' || event.key === ' ') {
        if (event.target === dropZone) {
          event.preventDefault();
          if (fileInput) fileInput.click();
        }
      }
    });
  }
  if (fileInput) {
    fileInput.addEventListener('change', event => {
      if (event.target.files.length > 0) uploadFiles(event.target.files);
      event.target.value = '';
    });
  }

  // Init
  initTheme();
  setInterval(updateCountdownDisplay, 1000);
  joinSession();
})();
