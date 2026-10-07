(async () => {
  const locale = document.documentElement.lang || 'en';
  async function loadLocale(code) {
    const response = await fetch(`/locales/${encodeURIComponent(code)}.json`, { cache: 'force-cache' });
    if (!response.ok) throw new Error(`Locale ${code} returned ${response.status}`);
    return response.json();
  }
  const englishPromise = loadLocale('en').catch(() => ({}));
  const [english, selected] = await Promise.all([
    englishPromise,
    locale === 'en' ? Promise.resolve({}) : loadLocale(locale).catch(() => ({})),
  ]);
  const translations = { ...english, ...selected };
  const interpolate = (template, params = {}) => String(template).replace(
    /\{\{([A-Za-z0-9_]+)\}\}|\{([A-Za-z0-9_]+)\}/g,
    (token, doubleKey, singleKey) => Object.hasOwn(params, doubleKey || singleKey)
      ? String(params[doubleKey || singleKey])
      : token,
  );
  const t = (key, params = {}) => interpolate(translations[key] || key, params);
  document.querySelectorAll('[data-i18n]').forEach(node => {
    const translated = translations[node.dataset.i18n];
    if (translated) node.textContent = translated;
  });
  for (const attribute of ['title', 'placeholder', 'aria-label']) {
    document.querySelectorAll(`[data-i18n-${attribute}]`).forEach(node => {
      const key = node.getAttribute(`data-i18n-${attribute}`);
      if (translations[key]) node.setAttribute(attribute, translations[key]);
    });
  }

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

  const code = location.pathname.split('/').filter(Boolean)[0] || '';
  const api = `/${encodeURIComponent(code)}`;
  const clientId = sessionStorage.getItem('drop5_client_id') || crypto.randomUUID();
  sessionStorage.setItem('drop5_client_id', clientId);
  const filesNode = document.querySelector('#files');
  const statusNode = document.querySelector('#status');
  const pendingNode = document.querySelector('#pending');
  const dropZone = document.querySelector('#dropZone');
  const fileInput = document.querySelector('#fileInput');
  const escape = value => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  let approved = false;
  let host = false;
  let pending = [];
  let currentFiles = [];
  const clientQuery = `clientId=${encodeURIComponent(clientId)}`;
  document.querySelector('#shareCode').textContent = `${code} 🔗`;
  document.querySelector('#shareCode').onclick = async () => { await navigator.clipboard.writeText(location.href); statusNode.textContent = t('link_copied'); };

  async function request(path, options = {}) {
    const response = await fetch(`${api}/${path}`, { cache: 'no-store', ...options });
    const data = await response.json().catch(() => ({}));
    if (!response.ok && data.status !== 'pending') throw new Error(apiError(data, response.status));
    return data;
  }
  function renderPending() {
    pendingNode.style.display = pending.length && host ? 'block' : 'none';
    pendingNode.innerHTML = pending.map(item => `<span>${escape(t('new_device_request'))}</span><button data-id="${escape(item.clientId)}" data-decision="approve">${escape(t('approve'))}</button><button data-id="${escape(item.clientId)}" data-decision="reject">${escape(t('reject'))}</button>`).join('');
    pendingNode.querySelectorAll('button').forEach(button => button.onclick = async () => {
      try { await request('approve', { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({clientId,targetId:button.dataset.id,decision:button.dataset.decision}) }); pending = pending.filter(item => item.clientId !== button.dataset.id); renderPending(); }
      catch (error) { statusNode.textContent = error.message; }
    });
  }
  function renderFiles() {
    if (!approved) { filesNode.innerHTML = `<p class="cf-empty">${escape(t('waiting_host_approval'))}</p>`; return; }
    if (!currentFiles.length) { filesNode.innerHTML = `<p class="cf-empty">${escape(t('no_files_yet'))}</p>`; return; }
    filesNode.innerHTML = currentFiles.map(file => `<a class="cf-file" href="${api}/download/${encodeURIComponent(file.id)}?${clientQuery}">${escape(file.name)}<small>${(file.size / 1024).toFixed(1)} KB · <span data-expiry="${file.expiresAt}"></span></small></a>`).join('');
    updateCountdowns();
  }
  async function refresh() {
    const data = await request(`files?${clientQuery}`);
    if (!data.success) { approved = false; renderFiles(); return; }
    currentFiles = data.files; renderFiles();
  }
  async function join() {
    const data = await request('join', { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({clientId}) });
    approved = data.status === 'approved'; host = data.host === true; pending = data.pending_requests || []; renderPending();
    if (approved) await refresh(); else renderFiles();
    connect();
  }
  function connect() {
    const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const socket = new WebSocket(`${scheme}//${location.host}${api}/ws?${clientQuery}`);
    socket.onmessage = async event => {
      const message = JSON.parse(event.data);
      if (message.type === 'client-joined' && host) { pending.push(message.client); renderPending(); }
      if (message.type === 'client-approved' && message.clientId === clientId) { approved = true; statusNode.textContent = t('approve'); await refresh(); }
      if (message.type === 'client-rejected' && message.clientId === clientId) { approved = false; renderFiles(); statusNode.textContent = t('host_refused_connection'); }
      if (['file-uploaded','file-deleted','file-expired'].includes(message.type) && approved) await refresh();
    };
    socket.onclose = () => setTimeout(connect, 2000);
  }
  async function sendFiles(fileList) {
    const files = Array.from(fileList);
    const maxFileBytes = Number(dropZone.dataset.maxFileBytes);
    const maxMb = Math.floor(maxFileBytes / (1024 * 1024));
    const tooLarge = Number.isFinite(maxFileBytes) && maxFileBytes > 0
      ? files.filter(file => file.size > maxFileBytes)
      : [];
    if (tooLarge.length) {
      statusNode.textContent = tooLarge.map(file => t('file_too_large_with_max', {
        filename: file.name,
        max_mb: maxMb,
      })).join('\n');
      return;
    }
    const form = new FormData();
    for (const file of files) form.append('content', file, file.name);
    form.append('clientId', clientId);
    statusNode.textContent = t('preparing');
    try {
      const data = await new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.upload.addEventListener('progress', event => {
          if (!event.lengthComputable) return;
          const percent = Math.round((event.loaded / event.total) * 100);
          statusNode.textContent = files.length > 1
            ? t('upload_progress_multiple', { count: files.length, percent })
            : t('upload_progress_single', { percent });
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
        xhr.open('POST', `${api}/upload`);
        xhr.send(form);
      });
      statusNode.textContent = data.success ? t('upload_complete') : apiError(data, 200);
      await refresh();
    }
    catch (error) { statusNode.textContent = error.message; }
  }
  dropZone.onclick = () => fileInput.click();
  fileInput.onchange = () => { if (fileInput.files.length) sendFiles(fileInput.files); fileInput.value = ''; };
  for (const event of ['dragenter','dragover']) dropZone.addEventListener(event, e => {e.preventDefault();dropZone.classList.add('drag');});
  for (const event of ['dragleave','drop']) dropZone.addEventListener(event, e => {e.preventDefault();dropZone.classList.remove('drag');});
  dropZone.addEventListener('drop', e => { if (e.dataTransfer.files.length) sendFiles(e.dataTransfer.files); });
  document.querySelector('#sendText').onclick = async () => {
    const content = document.querySelector('#textInput').value;
    if (!content.trim()) { statusNode.textContent = t('enter_content'); return; }
    statusNode.textContent = t('text_uploading');
    try {
      await request('upload', {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({content,clientId})});
      document.querySelector('#textInput').value = '';
      statusNode.textContent = t('upload_complete');
      await refresh();
    }
    catch (error) { statusNode.textContent = error.message; }
  };
  document.querySelector('#deleteAll').onclick = async () => {
    try { await request('delete_all', {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({clientId})}); await refresh(); }
    catch (error) { statusNode.textContent = error.message; }
  };
  function updateCountdowns() {
    document.querySelectorAll('[data-expiry]').forEach(node => { const seconds = Math.max(0, Math.ceil((Number(node.dataset.expiry)-Date.now())/1000)); node.textContent = `${Math.floor(seconds/60)}m ${seconds%60}s`; });
  }
  setInterval(updateCountdowns, 1000);
  setInterval(async () => {
    try {
      const state = await request('heartbeat', {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({clientId})});
      approved = state.status === 'approved';
      if (state.host) host = true;
      pending = state.pending_requests || pending;
      renderPending(); renderFiles();
    } catch { try { await join(); } catch { /* A reload can rejoin if a session has expired. */ } }
  }, 30_000);
  join().catch(error => { statusNode.textContent = error.message; });
})();
