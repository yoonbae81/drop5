import { Session } from './session-do';
import {
  SUPPORTED_LOCALES,
  localeHeaders,
  requestTranslations,
  translate,
  type TranslationParams,
} from './i18n';

export { Session };

interface RateLimiter { limit: (options: { key: string }) => Promise<{ success: boolean }> }
export interface Env {
  ASSETS: Fetcher;
  FILES: R2Bucket;
  SESSIONS: DurableObjectNamespace<Session>;
  MAX_FILE_SIZE?: string;
  MAX_STORAGE_SIZE?: string;
  MAX_FILES?: string;
  FILE_TTL_SECONDS?: string;
  SESSION_TTL_SECONDS?: string;
  BASE_PATH?: string;
  SESSION_CREATE_LIMITER?: RateLimiter;
  UPLOAD_LIMITER?: RateLimiter;
}

const CODE_RE = /^[A-Za-z0-9_-]{3,128}$/;
const CLIENT_RE = /^[A-Za-z0-9_-]{8,64}$/;
const BLOCKED = new Set(['exe','bat','cmd','com','pif','scr','vbs','msi','jar','app','dll','sys','cpl','ps1','ps1xml','psc1','psm1','cdxml','docm','dotm','xlsm','xltm','xlam','pptm','potm','ppsm','sldm','js','jse','wsf','wsh','sh','deb','gid','inf','ini','url','zone']);
const LOCALE_ASSET_RE = /^\/locales\/([A-Za-z-]+)\.json$/;
const SUPPORTED_LOCALE_SET = new Set<string>(SUPPORTED_LOCALES);

const json = (data: unknown, status = 200, extraHeaders: HeadersInit = {}) => new Response(JSON.stringify(data), {
  status,
  headers: {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    ...extraHeaders,
  },
});

function secure(response: Response): Response {
  if (response.status === 101) return response;
  const headers = new Headers(response.headers);
  headers.set('x-content-type-options', 'nosniff');
  headers.set('x-frame-options', 'DENY');
  headers.set('referrer-policy', 'no-referrer');
  headers.set('strict-transport-security', 'max-age=31536000; includeSubDomains');
  headers.set('x-download-options', 'noopen');
  headers.set('permissions-policy', 'camera=(), microphone=(), geolocation=()');
  headers.set('content-security-policy', "default-src 'self'; connect-src 'self' wss:; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function sessionCode(path: string): string | null {
  const candidate = path.split('/').filter(Boolean)[0] ?? '';
  if (!CODE_RE.test(candidate) || candidate.includes('..')) return null;
  return candidate;
}

function sessionStub(env: Env, code: string): DurableObjectStub<Session> {
  return env.SESSIONS.get(env.SESSIONS.idFromName(code));
}

interface CommandResult {
  data: Record<string, any>;
  status: number;
}

async function command(stub: DurableObjectStub<Session>, op: string, data: Record<string, unknown> = {}): Promise<CommandResult> {
  const response = await stub.fetch('https://session.internal/_command', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ op, ...data }),
  });
  return { data: await response.json() as Record<string, any>, status: response.status };
}

async function failure(
  request: Request,
  env: Env,
  status: number,
  errorKey: string,
  fallback: string,
  errorParams: TranslationParams = {},
  extra: Record<string, unknown> = {},
): Promise<Response> {
  const { locale, translations } = await requestTranslations(request, env.ASSETS);
  return json({
    success: false,
    error: translate(translations, errorKey, fallback, errorParams),
    errorKey,
    errorParams,
    ...extra,
  }, status, localeHeaders(locale));
}

async function commandResponse(result: CommandResult, request: Request, env: Env): Promise<Response> {
  const errorKey = result.data.errorKey;
  if (result.data.success !== false || typeof errorKey !== 'string') return json(result.data, result.status);
  const errorParams = typeof result.data.errorParams === 'object' && result.data.errorParams
    ? result.data.errorParams as TranslationParams
    : {};
  const { locale, translations } = await requestTranslations(request, env.ASSETS);
  return json({
    ...result.data,
    error: translate(translations, errorKey, String(result.data.error ?? 'Request failed'), errorParams),
  }, result.status, localeHeaders(locale));
}

function localeAsset(path: string): boolean {
  const match = LOCALE_ASSET_RE.exec(path);
  return !!match && SUPPORTED_LOCALE_SET.has(match[1]);
}

async function indexResponse(request: Request, env: Env, sessionCode: string): Promise<Response> {
  const { locale, translations } = await requestTranslations(request, env.ASSETS);
  const url = new URL(request.url);
  const asset = await env.ASSETS.fetch(new Request(new URL('/', url), request));
  if (!asset.ok) return asset;
  const maxFile = Number(env.MAX_FILE_SIZE ?? 30 * 1024 * 1024);
  const localized = new HTMLRewriter()
    .on('html', {
      element(element) { element.setAttribute('lang', locale); },
    })
    .on('[data-i18n]', {
      element(element) {
        const key = element.getAttribute('data-i18n');
        if (key && translations[key]) element.setInnerContent(translations[key]);
      },
    })
    .on('[data-i18n-title]', {
      element(element) {
        const key = element.getAttribute('data-i18n-title');
        if (key && translations[key]) element.setAttribute('title', translations[key]);
      },
    })
    .on('[data-i18n-placeholder]', {
      element(element) {
        const key = element.getAttribute('data-i18n-placeholder');
        if (key && translations[key]) element.setAttribute('placeholder', translations[key]);
      },
    })
    .on('[data-i18n-aria-label]', {
      element(element) {
        const key = element.getAttribute('data-i18n-aria-label');
        if (key && translations[key]) element.setAttribute('aria-label', translations[key]);
      },
    })
    .on('#dropZone', {
      element(element) { element.setAttribute('data-max-file-bytes', String(maxFile)); },
    })
    .on('#sessionCode', {
      element(element) { element.append(`${sessionCode} 🔗`); },
    })
    .transform(asset);
  const headers = new Headers(localized.headers);
  headers.set('content-language', locale);
  headers.set('vary', 'Accept-Language');
  headers.set('cache-control', 'no-store');
  return new Response(localized.body, { status: localized.status, statusText: localized.statusText, headers });
}

function cleanName(raw: string): string | null {
  if (/[\x00-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff\u180e]/u.test(raw)) return null;
  if (raw.includes('/') || raw.includes('\\') || raw.includes('..')) return null;
  const name = raw.normalize('NFC').trim();
  if (!name || name.startsWith('.') || name.length > 255) return null;
  const ext = name.includes('.') ? name.split('.').pop()!.toLowerCase() : '';
  return BLOCKED.has(ext) ? null : name;
}

function disposition(name: string): string {
  const fallback = name.replace(/[\r\n"\\]/g, '_').replace(/[^\x20-\x7e]/g, '_');
  return `attachment; filename="${fallback}"; filename*=UTF-8''${encodeURIComponent(name)}`;
}

async function upload(request: Request, env: Env, code: string): Promise<Response> {
  const maxFile = Number(env.MAX_FILE_SIZE ?? 30 * 1024 * 1024);
  const maxBytes = Number(env.MAX_STORAGE_SIZE ?? 100 * 1024 * 1024);
  const maxFiles = Number(env.MAX_FILES ?? 30);
  const ttlMs = Number(env.FILE_TTL_SECONDS ?? 300) * 1000;
  const stub = sessionStub(env, code);
  const type = request.headers.get('content-type') ?? '';
  let entries: Array<{ name: string; body: ReadableStream<Uint8Array>; size: number; type: string }> = [];
  let clientId: unknown;
  if (type.includes('application/json')) {
    const data = await request.json().catch(() => ({})) as { content?: unknown; clientId?: string };
    clientId = data.clientId;
    if (typeof data.content !== 'string' || !data.content.trim()) return failure(request, env, 400, 'enter_content', 'No content provided');
    const title = data.content.trim().split('\n')[0].slice(0, 10).trim().replace(/[\\/*?:"<>|]/g, '_') || 'text_input';
    const blob = new Blob([data.content], { type: 'text/plain; charset=utf-8' });
    entries = [{ name: `${title}.txt`, body: blob.stream(), size: blob.size, type: blob.type }];
  } else if (type.includes('multipart/form-data')) {
    const form = await request.formData();
    clientId = form.get('clientId');
    const override = form.get('name');
    for (const value of form.getAll('content')) {
      if (value instanceof File) entries.push({ name: typeof override === 'string' && override ? override : value.name, body: value.stream(), size: value.size, type: value.type || 'application/octet-stream' });
    }
  } else return failure(request, env, 415, 'upload_failed', 'Unsupported upload format');
  if (!entries.length) return failure(request, env, 400, 'upload_failed', 'No files provided');
  if (clientId !== undefined && clientId !== null && clientId !== '' && (typeof clientId !== 'string' || !CLIENT_RE.test(clientId))) {
    return failure(request, env, 400, 'device_approval_required', 'Invalid client ID');
  }
  const tooLarge = entries.filter(file => file.size > maxFile);
  if (tooLarge.length) {
    const maxMb = Math.floor(maxFile / (1024 * 1024));
    const { locale, translations } = await requestTranslations(request, env.ASSETS);
    const files = tooLarge.map(file => ({ name: file.name, size: file.size, maxBytes: maxFile }));
    const errors = files.map(file => translate(
      translations,
      'file_too_large_with_max',
      '{filename} is too large (max {max_mb}MB)',
      { filename: file.name, max_mb: maxMb },
    ));
    return json({
      success: false,
      error: errors.join('\n'),
      errorKey: 'file_too_large_with_max',
      errorParams: { filename: files[0].name, max_mb: maxMb },
      files,
    }, 413, localeHeaders(locale));
  }
  const files = entries.map(file => {
    const id = crypto.randomUUID();
    return { id, objectKey: `sessions/${code}/${id}`, name: cleanName(file.name), size: file.size, contentType: file.type, expiresAt: Date.now() + ttlMs };
  });
  if (files.some(file => !file.name)) {
    const names = entries.filter((_, index) => !files[index].name).map(file => file.name);
    return failure(request, env, 400, 'blocked_extension', 'Invalid or blocked filename', {}, { files: names });
  }
  const reservation = await command(stub, 'reserve', { files, maxBytes, maxFiles, clientId });
  if (!reservation.data.success) return commandResponse(reservation, request, env);
  const written: string[] = [];
  try {
    for (let i = 0; i < entries.length; i++) {
      const key = files[i].objectKey;
      await env.FILES.put(key, entries[i].body, { httpMetadata: { contentType: files[i].contentType } });
      written.push(key);
    }
    const uploadedAt = Date.now();
    const result = await command(stub, 'commit', { files: files.map((f, i) => ({ ...f, objectKey: written[i], uploadedAt, expiresAt: uploadedAt + ttlMs })) });
    if (!result.data.success) throw new Error('Session metadata commit failed');
    return json({ success: true, files: files.map(({ id, name }) => ({ id, name })) });
  } catch {
    await Promise.all(written.map(key => env.FILES.delete(key)));
    await command(stub, 'release', { ids: files.map(file => file.id) });
    return failure(request, env, 500, 'upload_failed', 'Upload failed');
  }
}

function basePath(env: Env): string {
  const raw = (env.BASE_PATH ?? '').trim();
  if (!raw || raw === '/') return '';
  return '/' + raw.replace(/^\/+|\/+$/g, '');
}

async function route(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const base = basePath(env);
  let path = url.pathname;
  if (base) {
    if (path === base || path === base + '/') {
      const ip = request.headers.get('cf-connecting-ip') ?? 'unknown';
      if (!await rateLimited(env.SESSION_CREATE_LIMITER, ip)) return failure(request, env, 429, 'connection_refused', 'Too many requests');
      const bytes = crypto.getRandomValues(new Uint8Array(16));
      const code = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
      return Response.redirect(new URL(`${base}/${code}`, url), 302);
    }
    if (path.startsWith(base + '/')) path = path.slice(base.length);
    else return failure(request, env, 404, 'connection_refused', 'Not found');
  }
  return routeSession(request, env, url, path);
}

function isAssetPath(path: string): boolean {
  return path === '/favicon.ico' || path === '/style.css' || path === '/app.js' || localeAsset(path);
}

async function rateLimited(limiter: RateLimiter | undefined, key: string): Promise<boolean> {
  // Absent binding (local tests) means unlimited; fail open on limiter errors
  // so a limiter outage never takes downloads down.
  if (!limiter) return true;
  try {
    return (await limiter.limit({ key })).success;
  } catch {
    return true;
  }
}

async function routeSession(request: Request, env: Env, url: URL, path: string): Promise<Response> {
  if (path === '/' || path === '') {
    const ip = request.headers.get('cf-connecting-ip') ?? 'unknown';
    if (!await rateLimited(env.SESSION_CREATE_LIMITER, ip)) return failure(request, env, 429, 'connection_refused', 'Too many requests');
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    const code = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
    return Response.redirect(new URL(`/${code}`, url), 302);
  }
  if (isAssetPath(path)) return env.ASSETS.fetch(new Request(new URL(path, url), request));
  // The browser resolves page-relative asset URLs against the session page,
  // so /<code>/style.css and /<code>/locales/ko.json also mean the assets.
  const relativeAsset = /^\/[A-Za-z0-9_-]{3,128}(\/(?:style\.css|app\.js|favicon\.ico|locales\/[A-Za-z-]+\.json))$/.exec(path);
  if (relativeAsset) return env.ASSETS.fetch(new Request(new URL(relativeAsset[1], url), request));
  const code = sessionCode(path);
  if (!code) return failure(request, env, 400, 'connection_refused', 'Invalid session code');
  const stub = sessionStub(env, code);
  const parts = path.split('/').filter(Boolean);
  if (parts.length === 1 && request.method === 'GET') {
    await command(stub, 'touch');
    return indexResponse(request, env, code);
  }
  const action = parts[1];
  if (action === 'join' && request.method === 'POST') {
    const data = await request.json().catch(() => ({})) as Record<string, unknown>;
    if (typeof data.clientId !== 'string' || !CLIENT_RE.test(data.clientId)) return failure(request, env, 400, 'device_approval_required', 'Invalid client ID');
    return commandResponse(await command(stub, 'join', { clientId: data.clientId, userAgent: request.headers.get('user-agent') ?? '', ip: request.headers.get('cf-connecting-ip') ?? 'unknown' }), request, env);
  }
  if (action === 'heartbeat' && request.method === 'POST') {
    const data = await request.json().catch(() => ({})) as Record<string, unknown>;
    if (typeof data.clientId !== 'string' || !CLIENT_RE.test(data.clientId)) return failure(request, env, 400, 'device_approval_required', 'Invalid client ID');
    return commandResponse(await command(stub, 'heartbeat', { clientId: data.clientId }), request, env);
  }
  if (action === 'approve' && request.method === 'POST') {
    const data = await request.json().catch(() => ({})) as Record<string, unknown>;
    if (typeof data.clientId !== 'string' || !CLIENT_RE.test(data.clientId) || typeof data.targetId !== 'string' || !CLIENT_RE.test(data.targetId)) {
      return failure(request, env, 400, 'device_approval_required', 'Invalid client ID');
    }
    return commandResponse(await command(stub, 'approve', data), request, env);
  }
  if (action === 'files' && request.method === 'GET') {
    const clientId = url.searchParams.get('clientId') ?? '';
    if (!CLIENT_RE.test(clientId)) return failure(request, env, 400, 'device_approval_required', 'Invalid client ID');
    return commandResponse(await command(stub, 'list', { clientId }), request, env);
  }
  if (action === 'upload' && request.method === 'POST') {
    const clientId = url.searchParams.get('clientId') ?? 'anonymous';
    if (!await rateLimited(env.UPLOAD_LIMITER, `${code}:${clientId}`)) return failure(request, env, 429, 'upload_failed', 'Too many requests');
    return upload(request, env, code);
  }
  if (action === 'delete_all' && request.method === 'POST') {
    let data: Record<string, unknown>;
    if (request.headers.get('content-type')?.includes('application/json')) {
      data = await request.json().catch(() => ({})) as Record<string, unknown>;
    } else {
      const form = await request.formData();
      data = { clientId: form.get('clientId') };
    }
    if (typeof data.clientId !== 'string' || !CLIENT_RE.test(data.clientId)) return failure(request, env, 400, 'device_approval_required', 'Invalid client ID');
    return commandResponse(await command(stub, 'deleteAll', { clientId: data.clientId }), request, env);
  }
  if (action === 'download' && parts.length >= 3 && request.method === 'GET') {
    const fileIdOrName = decodeURIComponent(parts.slice(2).join('/'));
    const clientId = url.searchParams.get('clientId') ?? '';
    if (!CLIENT_RE.test(clientId)) return failure(request, env, 403, 'device_approval_required', 'Unauthorized');
    const found = await command(stub, 'getFile', { clientId, id: fileIdOrName, name: fileIdOrName });
    if (!found.data.success) return commandResponse(found, request, env);
    const object = await env.FILES.get(found.data.file.objectKey);
    if (!object) return failure(request, env, 404, 'upload_failed', 'File not found');
    return new Response(object.body, { headers: { 'content-type': object.httpMetadata?.contentType ?? 'application/octet-stream', 'content-length': String(object.size), 'content-disposition': disposition(found.data.file.name), 'cache-control': 'no-store' } });
  }
  if (action === 'ws' && request.headers.get('upgrade')?.toLowerCase() === 'websocket') {
    const clientId = url.searchParams.get('clientId') ?? '';
    if (!CLIENT_RE.test(clientId)) return failure(request, env, 403, 'device_approval_required', 'Unauthorized');
    return stub.fetch(new Request(`https://session.internal/_ws?clientId=${encodeURIComponent(clientId)}`, request));
  }
  return failure(request, env, 404, 'connection_refused', 'Not found');
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return secure(await route(request, env));
    } catch {
      return secure(await failure(request, env, 500, 'upload_failed', 'Internal server error'));
    }
  },
};
