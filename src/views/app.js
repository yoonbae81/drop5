// Session State
let SESSION_CODE = "{{code}}";
if (!SESSION_CODE || SESSION_CODE === "{{code}}") {
    // Fallback: Extract code from URL path if baked-in value is missing or template not rendered
    const pathParts = window.location.pathname.split('/').filter(Boolean);
    // If we're at /drop5/abc12, pathParts is ['drop5', 'abc12'], so take the last one
    // But we need to be careful if there's no code (e.g. just /drop5/)
    if (pathParts.length > 0) {
        const potentialCode = pathParts[pathParts.length - 1];
        if (potentialCode !== 'drop5' && potentialCode.length >= 3) {
            SESSION_CODE = potentialCode;
        }
    }
}
const BASE_URL = "{{base_url}}"; // e.g. /drop5 OR empty
const CURRENT_LANG = "{{lang}}";
const NATIVE_LANG_CODE = "{{native_lang_code}}";
const LANGUAGE_COOKIE_NAME = "{{language_cookie_name}}";

// Translations object - populated by server-side template
const TRANSLATIONS = {
    upload_failed: "{{translations.upload_failed}}",
    file_too_large: "{{translations.file_too_large}}",
    network_error: "{{translations.network_error}}",
    upload_aborted: "{{translations.upload_aborted}}",
    upload_timeout: "{{translations.upload_timeout}}",
    upload_complete: "{{translations.upload_complete}}",
    upload_progress_single: "{{translations.upload_progress_single}}",
    upload_progress_multiple: "{{translations.upload_progress_multiple}}",
    delete_failed: "{{translations.delete_failed}}",
    enter_content: "{{translations.enter_content}}",
    save_text: "{{translations.save_text}}",
    text_uploading: "{{translations.text_uploading}}",
    blocked_extension: "{{translations.blocked_extension}}",
    file_size_exceeded: "{{translations.file_size_exceeded}}",
    storage_limit_exceeded: "{{translations.storage_limit_exceeded}}",
    upload_error_prefix: "{{translations.upload_error_prefix}}",
    save_failed_prefix: "{{translations.save_failed_prefix}}",
    preparing: "{{translations.preparing}}",
    file_too_large_with_max: "{{translations.file_too_large_with_max}}",
    connection_refused_title: "{{translations.connection_refused_title}}",
    connection_refused_desc: "{{translations.connection_refused_desc}}"
};
let CLIENT_ID = sessionStorage.getItem('drop5_client_id');
if (!CLIENT_ID) {
    if (window.crypto && window.crypto.randomUUID) {
        CLIENT_ID = crypto.randomUUID();
    } else if (window.crypto && window.crypto.getRandomValues) {
        // Fallback for older browsers
        CLIENT_ID = ([1e7] + -1e3 + -4e3 + -8e3 + -1e11).replace(/[018]/g, c =>
            (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
        );
    } else {
        // Simple fallback
        CLIENT_ID = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
            var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }
    sessionStorage.setItem('drop5_client_id', CLIENT_ID);
}

let isApproved = false;
let pendingRequests = [];
let pollingInterval = null;

// DOM elements - will be initialized in DOMContentLoaded
let dropZone, progressOverlay, toast, themeToggle, themeIcon;
let fileInput, progressBar, progressContainer, progressText;

// Theme Management
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
    const now = new Date();
    const hour = now.getHours();
    // Dark mode from 20:00 to 07:00
    return hour >= 20 || hour < 7;
}

function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    themeIcon.textContent = theme === 'dark' ? '☀️' : '🌙';
    setCookie('theme', theme, 365);
}

function initTheme() {
    // Check if user has a saved preference
    const savedTheme = getCookie('theme');
    if (savedTheme) {
        setTheme(savedTheme);
    } else {
        // Auto-detect based on time
        setTheme(isNightTime() ? 'dark' : 'light');
    }
}

function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    setTheme(newTheme);
}


// Mark current language as active in the modal and initialize all DOM elements
document.addEventListener('DOMContentLoaded', function () {
    // Initialize DOM elements
    dropZone = document.getElementById('dropZone');
    progressOverlay = document.getElementById('progressOverlay');
    toast = document.getElementById('toast');
    themeToggle = document.getElementById('themeToggle');
    themeIcon = document.getElementById('themeIcon');
    fileInput = document.getElementById('fileInput');
    progressBar = document.getElementById('progressBar');
    progressContainer = document.getElementById('progressContainer');
    progressText = document.getElementById('progressText');


    // Theme toggle click handler
    if (themeToggle) {
        themeToggle.addEventListener('click', toggleTheme);
    }


    // Drop zone click handler
    if (dropZone) {
        dropZone.addEventListener('click', function () {
            if (fileInput) fileInput.click();
        });
    }

    // Drag & Drop Handling
    if (dropZone) {
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, function (e) {
                e.preventDefault();
                e.stopPropagation();
            }, false);
        });

        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => dropZone.classList.add('dragover'), false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => dropZone.classList.remove('dragover'), false);
        });

        dropZone.addEventListener('drop', function (e) {
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                console.log(`Drop5: Files dropped (${files.length} files)`);
                uploadFiles(files);
            }
        }, false);

        dropZone.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                if (e.target === dropZone) {
                    e.preventDefault();
                    if (fileInput) fileInput.click();
                }
            }
        });
    }

    // File input change handler
    if (fileInput) {
        fileInput.onchange = (e) => {
            if (e.target.files.length > 0) {
                console.log(`Drop5: Files selected via input (${e.target.files.length} files)`);
                uploadFiles(e.target.files);
                // Clear value so the same file(s) can be selected again
                e.target.value = '';
            }
        };
    }

    // Initialize theme on page load (after elements are initialized)
    initTheme();

    // Initial sync and join on load
    console.log('Drop5: Session joining...');
    joinSession();

    // Start countdown (UI smooth update every second)
    setInterval(updateCountdownDisplay, 1000);

    // Initialize keyboard support for session code
    const sessionCode = document.getElementById('sessionCode');
    if (sessionCode) {
        sessionCode.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                copyURL();
            }
        });
    }

    // Add keyboard listener for textarea
    const textInputTextArea = document.getElementById('textInputTextArea');
    if (textInputTextArea) {
        textInputTextArea.addEventListener('keydown', function (e) {
            if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
                e.preventDefault();
                saveText();
            }
            if (e.key === 'Tab' && !e.shiftKey) {
                // Ensure tab key moves focus to the save button
                // Normally browser does this, but if it's failing, we can force it
                e.preventDefault();
                document.querySelector('.save-text-btn').focus();
            }
        });
    }
});


function selectLanguage(lang) {
    setCookie(LANGUAGE_COOKIE_NAME, lang, 365);
    location.reload();
}

function toggleLanguage() {
    const target = CURRENT_LANG === 'en' ? NATIVE_LANG_CODE : 'en';
    selectLanguage(target);
}

function formatBrowserInfo(ua) {
    if (!ua || ua === 'Unknown') return 'Unknown Browser';

    let browser = "Browser";
    let os = "OS";

    if (ua.includes("Windows NT 10.0")) os = "Windows 10/11";
    else if (ua.includes("Windows NT 6.1")) os = "Windows 7";
    else if (ua.includes("Macintosh")) os = "macOS";
    else if (ua.includes("iPhone")) os = "iPhone";
    else if (ua.includes("iPad")) os = "iPad";
    else if (ua.includes("Android")) os = "Android";
    else if (ua.includes("Linux")) os = "Linux";

    if (ua.includes("Edg/")) browser = "Edge";
    else if (ua.includes("Chrome/")) browser = "Chrome";
    else if (ua.includes("Firefox/")) browser = "Firefox";
    else if (ua.includes("Safari/") && !ua.includes("Chrome/")) browser = "Safari";

    return `${browser} on ${os}`;
}

// Countdown Timer - Update display every second
function updateCountdownDisplay() {
    const fileCards = document.querySelectorAll('.file-card[data-remaining]');
    fileCards.forEach(card => {
        let remaining = parseInt(card.dataset.remaining);
        if (isNaN(remaining) || remaining <= 0) {
            // Remove expired files from the list
            card.style.display = 'none';
            return;
        }

        // Decrement remaining time
        remaining--;
        card.dataset.remaining = remaining;

        // Update display
        const timerSpan = card.querySelector('.countdown-timer');
        if (timerSpan) {
            const minutes = Math.floor(remaining / 60);
            const seconds = remaining % 60;
            timerSpan.textContent = `${minutes}m ${seconds.toString().padStart(2, '0')}s`;

            // Change color when time is running low (less than 1 minute)
            const timeBadge = card.querySelector('.time-badge');
            if (remaining < 60) {
                timeBadge.classList.remove('safe');
            } else {
                timeBadge.classList.add('safe');
            }
        }
    });
}

// --- Session Management & Polling ---

async function joinSession() {
    try {
        const response = await fetch(`${BASE_URL}/${SESSION_CODE}/join`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ clientId: CLIENT_ID })
        });
        const data = await response.json();

        if (data.success) {
            updateSessionState(data.status);
            startPolling();
        } else {
            console.error("Join failed:", data.error);
        }
    } catch (e) {
        console.error("Join error:", e);
    }
}

let isUploading = false;

function startPolling() {
    if (pollingInterval) clearTimeout(pollingInterval);
    pollSessionLoop();
}

async function pollSessionLoop() {
    if (!isUploading) {
        await pollSessionState();
    }
    pollingInterval = setTimeout(pollSessionLoop, 2000);
}

async function pollSessionState() {
    try {
        // We can combine heartbeat and file sync eventually, but for now separate
        // 1. Heartbeat
        const response = await fetch(`${BASE_URL}/${SESSION_CODE}/heartbeat`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ clientId: CLIENT_ID })
        });
        const data = await response.json();

        if (data.success) {
            updateSessionState(data.status);

            if (data.pending_requests && data.pending_requests.length > 0) {
                // Store pending requests
                pendingRequests = data.pending_requests;
                showApprovalModal();
            } else {
                pendingRequests = [];
                hideApprovalModal();
            }
        }

        // 2. File Sync (Only if approved)
        if (isApproved) {
            syncFiles();
        }

    } catch (e) {
        console.error("Polling error:", e);
    }
}

function updateSessionState(status) {
    const waitingOverlay = document.getElementById('waitingOverlay');

    if (status === 'approved') {
        isApproved = true;
        if (waitingOverlay) waitingOverlay.style.display = 'none';
    } else if (status === 'pending') {
        isApproved = false;
        if (waitingOverlay) waitingOverlay.style.display = 'flex';
    } else if (status === 'rejected') {
        isApproved = false;
        if (waitingOverlay) {
            waitingOverlay.style.display = 'flex';
            waitingOverlay.querySelector('.waiting-title').textContent = TRANSLATIONS.connection_refused_title;
            waitingOverlay.querySelector('.waiting-desc').textContent = TRANSLATIONS.connection_refused_desc;
            waitingOverlay.querySelector('.waiting-icon').textContent = '🚫';
        }
        // Stop polling if rejected? Or keep polling in case they are approved later?
        // Let's keep polling for now, maybe they get approved.
    }
}

function showApprovalModal() {
    const modal = document.getElementById('approvalModal');
    const infoDiv = document.getElementById('approvalDeviceInfo');

    if (infoDiv && pendingRequests.length > 0) {
        const req = pendingRequests[0];
        const browserStr = formatBrowserInfo(req.browser);
        infoDiv.textContent = `${req.ip} • ${browserStr}`;
    }

    if (modal && !modal.classList.contains('show')) {
        modal.classList.add('show');
        // Auto-focus the approve button for convenience
        setTimeout(() => {
            const approveBtn = modal.querySelector('.btn-approve');
            if (approveBtn) approveBtn.focus();
        }, 400);
    }
}

function hideApprovalModal() {
    const modal = document.getElementById('approvalModal');
    if (modal && modal.classList.contains('show')) {
        modal.classList.remove('show');
    }
}

async function handleApprovalDecision(decision) {
    if (pendingRequests.length === 0) return;

    // Approve the first one (FIFO) or logic could be more complex
    const target = pendingRequests[0];

    try {
        const response = await fetch(`${BASE_URL}/${SESSION_CODE}/approve`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                clientId: CLIENT_ID,
                targetId: target.clientId,
                decision: decision
            })
        });

        const data = await response.json();
        if (data.success) {
            // Remove processed request locally immediately for UI responsiveness
            pendingRequests.shift();
            if (pendingRequests.length === 0) {
                hideApprovalModal();
            } else {
                showApprovalModal(); // Update with next request info
            }
        }
    } catch (e) {
        console.error("Approval error:", e);
    }
}

// Define syncFiles here to be used in polling


// Redundant initialization removed from here, handled in DOMContentLoaded

async function syncFiles() {
    // Don't sync if uploading
    if (typeof progressOverlay !== 'undefined' && progressOverlay && progressOverlay.style.display === 'flex') {
        return;
    }

    if (!isApproved) {
        // If not approved, we shouldn't even try to see files, 
        // but if we did, the server would reject us (403 or pending status).
        // Join session handles the approval polling loop.
        return;
    }

    try {
        // Construct API URL based on current browser path
        const currentPath = window.location.pathname.replace(/\/$/, "");
        const apiUrl = `${currentPath}/files?_=${Date.now()}&clientId=${CLIENT_ID}`;

        console.log('Syncing files from:', apiUrl);

        const res = await fetch(apiUrl, { cache: 'no-store' });
        console.log('Drop5: Response status:', res.status);

        if (res.status === 403) {
            // Maybe we got kicked out?
            return;
        }

        if (!res.ok) throw new Error(`HTTP ${res.status}`);

        const data = await res.json();
        console.log('Drop5: Data received:', data);
        if (data.success && data.files) {
            updateFileListUI(data.files);
        }
    } catch (e) {
        console.warn('Sync failed:', e.message);
    }
}

let lastSyncHash = "";
function updateFileListUI(files) {
    const fileItems = document.getElementById('fileItems');
    if (!fileItems) return;

    // Generate a unique hash for the current state (filenames + remaining time)
    // This ensures we catch changes even if the file count is the same
    const currentHash = files.map(f => `${f.name}:${f.remaining_total}`).join('|');

    // Only rebuild the entire HTML if something meaningful changed
    if (currentHash === lastSyncHash) {
        return;
    }
    lastSyncHash = currentHash;

    const deleteAllBtn = document.getElementById('deleteAllBtn');
    if (files.length > 0) {
        deleteAllBtn.classList.add('show');
    } else {
        deleteAllBtn.classList.remove('show');
    }

    if (files.length === 0) {
        fileItems.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">📭</div>
                <div class="upload-text">{{translations.no_files_yet}}</div>
            </div>`;
        return;
    }

    const baseUrl = "{{base_url}}".replace(/\/$/, "");
    const code = "{{code}}";

    // Construct new grid content using DOM manipulation to prevent XSS
    const grid = document.createElement('div');
    grid.className = 'file-grid';

    files.forEach(file => {
        const card = document.createElement('a');
        card.href = `${baseUrl}/${code}/download/${encodeURIComponent(file.name)}?clientId=${CLIENT_ID}`;
        card.className = 'file-card';
        card.setAttribute('download', '');
        card.dataset.remaining = file.remaining_total;

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
        size.textContent = file.formatted_size;

        const timeBadge = document.createElement('div');
        timeBadge.className = 'time-badge';
        if (file.remaining_total >= 60) {
            timeBadge.classList.add('safe');
        }

        const timerSpan = document.createElement('span');
        timerSpan.className = 'countdown-timer';
        timerSpan.textContent = `${file.remaining_min}m ${file.remaining_sec}s`;

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

async function uploadFiles(files) {
    if (isUploading) return;

    console.log(`Drop5: uploadFiles execution started for ${files.length} files`);
    const MAX_SIZE = Number("{{ max_size_mb }}") * 1024 * 1024;

    // Initial check
    for (let i = 0; i < files.length; i++) {
        if (files[i].size > MAX_SIZE) {
            const errorMsg = TRANSLATIONS.file_too_large_with_max
                .replace('{filename}', files[i].name)
                .replace('{max_mb}', '{{max_size_mb}}');
            showToast(`❌ ${errorMsg}`);
            return;
        }
    }

    isUploading = true;
    progressOverlay.style.display = 'flex';
    progressContainer.style.display = 'block';
    progressBar.style.width = '0%';
    progressText.textContent = TRANSLATIONS.preparing;

    const totalFiles = files.length;
    const currentPath = window.location.pathname.replace(/\/+$/, "");
    const uploadUrl = `${currentPath}/upload`;

    const formData = new FormData();
    for (let i = 0; i < totalFiles; i++) {
        let fileName = files[i].name;
        if (fileName.normalize) fileName = fileName.normalize('NFC');
        formData.append('file', files[i], fileName);
    }
    formData.append('clientId', CLIENT_ID);

    try {
        const xhr = new XMLHttpRequest();

        // Track upload progress
        xhr.upload.addEventListener('progress', (e) => {
            if (e.lengthComputable) {
                const percent = (e.loaded / e.total) * 100;
                progressBar.style.width = `${percent}%`;
                if (totalFiles > 1) {
                    progressText.textContent = TRANSLATIONS.upload_progress_multiple
                        .replace('{count}', totalFiles)
                        .replace('{percent}', Math.round(percent));
                } else {
                    progressText.textContent = TRANSLATIONS.upload_progress_single
                        .replace('{percent}', Math.round(percent));
                }
            }
        });

        const promise = new Promise((resolve, reject) => {
            xhr.onload = () => {
                if (xhr.status >= 200 && xhr.status < 300) {
                    try {
                        resolve(JSON.parse(xhr.responseText));
                    } catch (e) {
                        reject(new Error('Invalid server response'));
                    }
                } else if (xhr.status === 403) {
                    reject(new Error(TRANSLATIONS.device_approval_required));
                } else {
                    reject(new Error(`HTTP ${xhr.status}`));
                }
            };
            xhr.onerror = () => reject(new Error(TRANSLATIONS.network_error));
            xhr.onabort = () => reject(new Error(TRANSLATIONS.upload_aborted));
            xhr.ontimeout = () => reject(new Error(TRANSLATIONS.upload_timeout));
        });

        xhr.open('POST', uploadUrl);
        xhr.send(formData);

        const data = await promise;
        if (data.success) {
            // Success - briefly show 100% then reload
            progressBar.style.width = '100%';
            progressText.textContent = TRANSLATIONS.upload_complete;
            setTimeout(() => {
                window.location.reload();
            }, 500);
        } else {
            throw new Error(data.error || TRANSLATIONS.upload_failed);
        }
    } catch (error) {
        console.error('Upload error:', error);
        showToast(`❌ ${TRANSLATIONS.upload_error_prefix} ${error.message}`);
        progressOverlay.style.display = 'none';
        isUploading = false;
    }
}

function copyURL() {
    const url = `{{url_root}}{{base_url}}/{{code}}`;
    navigator.clipboard.writeText(url).then(() => {
        showToast('✅ {{translations.link_copied}}');
    }).catch(() => {
        showToast('❌ {{translations.copy_failed}}');
    });
}

function showToast(message) {
    toast.textContent = message;
    toast.classList.add('show');
    setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}

async function deleteAllFiles() {
    const cards = document.querySelectorAll('.file-card');
    if (cards.length === 0) return;

    // Trigger falling animation
    cards.forEach((card, index) => {
        setTimeout(() => {
            card.classList.add('falling');
        }, index * 50); // Staggered effect
    });

    const deleteAllBtn = document.getElementById('deleteAllBtn');
    deleteAllBtn.classList.remove('show');

    // Wait for animation to mostly complete
    await new Promise(resolve => setTimeout(resolve, 800));

    try {
        const formData = new FormData();
        formData.append('clientId', CLIENT_ID); // Add security token

        const currentPath = window.location.pathname.replace(/\/$/, "");
        const response = await fetch(`${currentPath}/delete_all`, {
            method: 'POST',
            body: formData
        });

        if (response.ok) {
            const data = await response.json();
            if (data.success) {
                // Success - clear UI
                const fileItems = document.getElementById('fileItems');
                if (fileItems) {
                    fileItems.innerHTML = `
                        <div class="empty-state">
                            <div class="empty-icon">📭</div>
                            <div class="upload-text">{{translations.no_files_yet}}</div>
                        </div>`;
                }
            }
        }
    } catch (error) {
        console.error('Error:', error);
        showToast(`❌ ${TRANSLATIONS.delete_failed}`);
    }
}

function openTextModal(e) {
    if (e) e.stopPropagation();
    const modal = document.getElementById('textModal');
    modal.classList.add('show');
    setTimeout(() => {
        document.getElementById('textInputTextArea').focus();
    }, 100);
}

function closeTextModal() {
    document.getElementById('textModal').classList.remove('show');
}

function handleOverlayClick(e) {
    if (e.target.id === 'textModal') {
        closeTextModal();
    }
}

async function saveText() {
    const textarea = document.getElementById('textInputTextArea');
    const text = textarea.value;
    if (!text.trim()) {
        showToast(`❌ ${TRANSLATIONS.enter_content}`);
        return;
    }

    const saveBtn = document.querySelector('.save-text-btn');
    const originalText = saveBtn.textContent;
    saveBtn.textContent = TRANSLATIONS.save_text;
    saveBtn.disabled = true;

    const currentPath = window.location.pathname.replace(/\/+$/, "");
    const uploadUrl = `${currentPath}/text-upload`;

    try {
        const response = await fetch(uploadUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ text: text, clientId: CLIENT_ID }) // Add security token
        });

        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        if (!data.success) throw new Error(data.error || TRANSLATIONS.upload_failed);

        showToast('✅ {{translations.text_file_created}}');
        textarea.value = ''; // Clear after success
        closeTextModal();
        syncFiles(); // Refresh file list immediately
    } catch (error) {
        console.error('Text upload error:', error);
        showToast(`❌ ${TRANSLATIONS.save_failed_prefix} ${error.message}`);
    } finally {
        saveBtn.textContent = originalText;
        saveBtn.disabled = false;
    }
}
