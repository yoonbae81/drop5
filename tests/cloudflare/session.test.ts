import { env } from 'cloudflare:workers';
import { evictDurableObject, reset, runDurableObjectAlarm, runInDurableObject } from 'cloudflare:test';
import { afterEach, describe, expect, it } from 'vitest';
import worker from '../../src/worker';
import type { Session } from '../../src/session-do';

const origin = 'https://drop5.test';
const code = 'test-session';
const hostId = 'host-12345678';
const guestId = 'guest-12345678';

function request(path: string, init?: RequestInit, testEnv?: Record<string, unknown>): Promise<Response> {
  // Tests exercise the no-base-path deployment; the /drop5 prefix path is
  // covered separately in the base-path test below.
  return worker.fetch(new Request(`${origin}${path}`, init), { ...env, BASE_PATH: '', ...testEnv });
}

async function json(response: Response): Promise<Record<string, any>> {
  return response.json() as Promise<Record<string, any>>;
}

async function join(clientId: string): Promise<Record<string, any>> {
  return json(await request(`/${code}/join`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ clientId }),
  }));
}

afterEach(async () => {
  await reset();
});

describe('Cloudflare HTTP and Durable Object integration', () => {
  it('preserves host approval, upload, listing, download, and delete semantics', async () => {
    expect(await join(hostId)).toMatchObject({ success: true, status: 'approved', host: true });
    expect(await join(guestId)).toMatchObject({ success: true, status: 'pending', host: false });

    const denied = await request(`/${code}/files?clientId=${guestId}`);
    expect(denied.status).toBe(403);

    const approval = await request(`/${code}/approve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ clientId: hostId, targetId: guestId, decision: 'approve' }),
    });
    expect(approval.status).toBe(200);

    const form = new FormData();
    form.append('clientId', guestId);
    form.append('content', new File(['hello'], '한글.txt', { type: 'text/plain' }));
    const upload = await request(`/${code}/upload`, { method: 'POST', body: form });
    expect(upload.status).toBe(200);

    const listing = await json(await request(`/${code}/files?clientId=${guestId}`));
    expect(listing.files).toHaveLength(1);
    expect(listing.files[0]).toMatchObject({ name: '한글.txt', size: 5 });

    const download = await request(`/${code}/download/${listing.files[0].id}?clientId=${guestId}`);
    expect(download.status).toBe(200);
    expect(await download.text()).toBe('hello');
    expect(download.headers.get('content-disposition')).toContain("filename*=UTF-8''");

    const deletion = await request(`/${code}/delete_all`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ clientId: hostId }),
    });
    expect(deletion.status).toBe(200);
    expect((await json(await request(`/${code}/files?clientId=${hostId}`))).files).toHaveLength(0);
  });

  it('keeps Shortcut uploads compatible without a browser client ID', async () => {
    const response = await request('/shortcut-code/upload', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ content: 'shared from shortcut' }),
    });
    expect(response.status).toBe(200);
    expect(await json(response)).toMatchObject({ success: true });

    const validUnjoinedClient = await request('/shortcut-code/upload', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ content: 'shared with metadata', clientId: 'valid-123456' }),
    });
    expect(validUnjoinedClient.status).toBe(200);

    const malformedClient = await request('/shortcut-code/upload', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ content: 'bad metadata', clientId: 'short' }),
    });
    expect(malformedClient.status).toBe(400);
  });

  it('rejects unapproved downloads and dangerous filenames', async () => {
    await join(hostId);
    await join(guestId);

    const blocked = new FormData();
    blocked.append('content', new File(['bad'], 'payload.exe'));
    expect((await request(`/${code}/upload`, { method: 'POST', body: blocked })).status).toBe(400);

    for (const name of ['../secret.txt', '.session.json', `${'a'.repeat(256)}.txt`]) {
      const invalid = new FormData();
      invalid.append('content', new File(['bad'], name));
      expect((await request(`/${code}/upload`, { method: 'POST', body: invalid })).status).toBe(400);
    }

    const allowed = new FormData();
    allowed.append('content', new File(['ok'], 'safe.txt'));
    const uploaded = await json(await request(`/${code}/upload`, { method: 'POST', body: allowed }));
    const denied = await request(`/${code}/download/${uploaded.files[0].id}?clientId=${guestId}`);
    expect(denied.status).toBe(403);
  });

  it('normalizes decomposed Unicode filenames to NFC', async () => {
    const form = new FormData();
    form.append('content', new File(['unicode'], 'A\u0301.txt'));
    expect((await request(`/${code}/upload`, { method: 'POST', body: form })).status).toBe(200);

    expect(await join(hostId)).toMatchObject({ status: 'approved' });
    const listing = await json(await request(`/${code}/files?clientId=${hostId}`));
    expect(listing.files[0].name).toBe('Á.txt');
  });

  it('enforces atomic file-count and byte reservations', async () => {
    const stub = env.SESSIONS.get(env.SESSIONS.idFromName('quota-test'));
    const command = (body: object) => stub.fetch('https://session.internal/_command', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    const file = (id: string, size: number) => ({ id, name: `${id}.txt`, size, contentType: 'text/plain', expiresAt: Date.now() + 300_000 });

    expect((await command({ op: 'reserve', files: [file('one', 6)], maxBytes: 10, maxFiles: 2 })).status).toBe(200);
    await runInDurableObject(stub, async (_instance: Session, state) => {
      expect(await state.storage.getAlarm()).not.toBeNull();
    });
    expect((await command({ op: 'reserve', files: [file('two', 5)], maxBytes: 10, maxFiles: 2 })).status).toBe(409);
    expect((await command({ op: 'reserve', files: [file('two', 4), file('three', 0)], maxBytes: 10, maxFiles: 2 })).status).toBe(409);
  });

  it('recovers persisted session state after Durable Object eviction', async () => {
    await join(hostId);
    const form = new FormData();
    form.append('content', new File(['persisted'], 'persisted.txt'));
    await request(`/${code}/upload`, { method: 'POST', body: form });

    const stub = env.SESSIONS.get(env.SESSIONS.idFromName(code));
    await evictDurableObject(stub);

    const listing = await json(await request(`/${code}/files?clientId=${hostId}`));
    expect(listing.files).toHaveLength(1);
    expect(listing.files[0]).toMatchObject({ name: 'persisted.txt', size: 9 });
  });

  it('resumes a hibernated host WebSocket and delivers approval events', async () => {
    await join(hostId);
    const response = await request(`/${code}/ws?clientId=${hostId}`, {
      headers: { upgrade: 'websocket' },
    });
    expect(response.status).toBe(101);
    const socket = response.webSocket!;
    socket.accept();
    const connected = await new Promise<Record<string, any>>((resolve) => {
      socket.addEventListener('message', event => resolve(JSON.parse(event.data as string)), { once: true });
    });
    expect(connected.type).toBe('connected');

    const stub = env.SESSIONS.get(env.SESSIONS.idFromName(code));
    await evictDurableObject(stub);
    const joined = new Promise<Record<string, any>>((resolve) => {
      socket.addEventListener('message', event => resolve(JSON.parse(event.data as string)), { once: true });
    });
    expect(await join(guestId)).toMatchObject({ status: 'pending' });
    expect(await joined).toMatchObject({ type: 'client-joined', client: { clientId: guestId } });
    socket.close(1000, 'done');
  });

  it('expires R2 objects by alarm, schedules the next expiry, and is idempotent', async () => {
    await join(hostId);
    const first = new FormData();
    first.append('content', new File(['first'], 'first.txt'));
    const second = new FormData();
    second.append('content', new File(['second'], 'second.txt'));
    const firstResult = await json(await request(`/${code}/upload`, { method: 'POST', body: first }));
    const secondResult = await json(await request(`/${code}/upload`, { method: 'POST', body: second }));
    const stub = env.SESSIONS.get(env.SESSIONS.idFromName(code));

    await runInDurableObject(stub, async (instance: Session, state) => {
      const stored = await state.storage.get<any>('state');
      stored.files.find((file: any) => file.id === firstResult.files[0].id).expiresAt = Date.now() - 1;
      stored.files.find((file: any) => file.id === secondResult.files[0].id).expiresAt = Date.now() + 60_000;
      await state.storage.put('state', stored);
      (instance as any).data = stored;
      await state.storage.setAlarm(Date.now() + 1_000);
    });

    expect(await runDurableObjectAlarm(stub)).toBe(true);
    const remaining = (await json(await request(`/${code}/files?clientId=${hostId}`))).files;
    expect(remaining.map((file: any) => file.id)).toEqual([secondResult.files[0].id]);

    await runInDurableObject(stub, async (_instance: Session, state) => {
      expect(await state.storage.getAlarm()).not.toBeNull();
    });
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    expect((await json(await request(`/${code}/files?clientId=${hostId}`))).files).toHaveLength(1);
  });

  it('deletes all Durable Object storage when the final file expires', async () => {
    const sessionCode = 'final-file-expiry';
    const sessionHost = 'final-file-host';
    await json(await request(`/${sessionCode}/join`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ clientId: sessionHost }),
    }));
    const form = new FormData();
    form.append('content', new File(['ephemeral'], 'ephemeral.txt'));
    const uploaded = await json(await request(`/${sessionCode}/upload`, { method: 'POST', body: form }));
    const stub = env.SESSIONS.get(env.SESSIONS.idFromName(sessionCode));
    let objectKey = '';

    await runInDurableObject(stub, async (instance: Session, state) => {
      const stored = await state.storage.get<any>('state');
      const file = stored.files.find((item: any) => item.id === uploaded.files[0].id);
      file.expiresAt = Date.now() - 1;
      stored.expiresAt = Date.now() + 60_000;
      objectKey = file.objectKey;
      await state.storage.put('state', stored);
      (instance as any).data = stored;
      await state.storage.setAlarm(Date.now() + 1_000);
    });

    expect(await runDurableObjectAlarm(stub)).toBe(true);
    expect(await env.FILES.get(objectKey)).toBeNull();
    await runInDurableObject(stub, async (_instance: Session, state) => {
      expect((await state.storage.list()).size).toBe(0);
      expect(await state.storage.getAlarm()).toBeNull();
    });
  });

  it('deletes an abandoned fileless session when its session alarm expires', async () => {
    const sessionCode = 'abandoned-session';
    const sessionHost = 'abandoned-host';
    await json(await request(`/${sessionCode}/join`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ clientId: sessionHost }),
    }));
    const stub = env.SESSIONS.get(env.SESSIONS.idFromName(sessionCode));

    await runInDurableObject(stub, async (instance: Session, state) => {
      const stored = await state.storage.get<any>('state');
      expect(stored.files).toHaveLength(0);
      expect(stored.expiresAt).toBeGreaterThan(Date.now());
      stored.expiresAt = Date.now() - 1;
      await state.storage.put('state', stored);
      (instance as any).data = stored;
      await state.storage.setAlarm(Date.now() + 1_000);
    });

    expect(await runDurableObjectAlarm(stub)).toBe(true);
    await runInDurableObject(stub, async (_instance: Session, state) => {
      expect((await state.storage.list()).size).toBe(0);
      expect(await state.storage.getAlarm()).toBeNull();
    });
  });
});

describe('security boundary', () => {
  it('rejects malformed session and client identifiers', async () => {
    expect((await request('/bad%2Fcode/files?clientId=valid-123456')).status).toBe(400);
    expect((await request('/valid-code/files?clientId=short')).status).toBe(400);
  });

  it('adds security headers to API errors', async () => {
    const response = await request('/valid-code/unknown');
    expect(response.status).toBe(404);
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    expect(response.headers.get('content-security-policy')).toContain("default-src 'self'");
  });
});

describe('base path', () => {
  const baseRequest = (path: string, init?: RequestInit): Promise<Response> =>
    worker.fetch(new Request(`${origin}${path}`, init), env);

  it('redirects the base path to a session and serves session routes under it', async () => {
    const redirect = await baseRequest('/drop5');
    expect(redirect.status).toBe(302);
    const location = new URL(redirect.headers.get('location')!);
    expect(location.pathname).toMatch(/^\/drop5\/[A-Za-z0-9_-]{3,128}$/);

    const code = location.pathname.split('/').pop()!;
    const joinResponse = await baseRequest(`/drop5/${code}/join`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ clientId: hostId }),
    });
    expect(await json(joinResponse)).toMatchObject({ success: true, status: 'approved', host: true });
  });

  it('serves static assets under the base path and session-relative, rejects other prefixes', async () => {
    // With BASE_PATH set, only paths under the base reach the session router.
    const styleUnderBase = await baseRequest('/drop5/style.css');
    expect(styleUnderBase.status).toBe(200);
    const sessionRelative = await baseRequest('/drop5/test-session/app.js');
    expect(sessionRelative.status).toBe(200);
    const sessionLocale = await baseRequest('/drop5/test-session/locales/ko.json');
    expect(sessionLocale.status).toBe(200);
    expect((await baseRequest('/style.css')).status).toBe(404);
    expect((await baseRequest('/unknown-prefix/test-session')).status).toBe(404);
    // Same request under the configured base path reaches the session router.
    const underBase = await baseRequest('/drop5/valid-code/unknown');
    expect(underBase.status).toBe(404);
  });

  it('keeps root-mode behavior when BASE_PATH is empty', async () => {
    const rootRequest = (path: string, init?: RequestInit): Promise<Response> =>
      worker.fetch(new Request(`${origin}${path}`, init), { ...env, BASE_PATH: '' });
    const redirect = await rootRequest('/');
    expect(redirect.status).toBe(302);
    expect(new URL(redirect.headers.get('location')!).pathname).toMatch(/^\/[A-Za-z0-9_-]{3,128}$/);
  });
});

describe('rate limiting', () => {  function limiter(limit: number): { limit: (options: { key: string }) => Promise<{ success: boolean }>; calls: string[] } {
    const calls: string[] = [];
    return {
      calls,
      limit: async ({ key }) => {
        calls.push(key);
        return { success: calls.filter(entry => entry === key).length <= limit };
      },
    };
  }

  it('returns 429 when session creation exceeds the limit and keys by IP', async () => {
    const sessionLimiter = limiter(2);
    const testEnv = { ...env, BASE_PATH: '', SESSION_CREATE_LIMITER: sessionLimiter };
    const create = () => worker.fetch(new Request(`${origin}/`, { headers: { 'cf-connecting-ip': '1.2.3.4' } }), testEnv);
    expect((await create()).status).toBe(302);
    expect((await create()).status).toBe(302);
    expect((await create()).status).toBe(429);
    expect((await worker.fetch(new Request(`${origin}/`, { headers: { 'cf-connecting-ip': '5.6.7.8' } }), testEnv)).status).toBe(302);
  });

  it('returns 429 when uploads exceed the limit and fails open without a binding', async () => {
    const uploadLimiter = limiter(1);
    const testEnv = { ...env, BASE_PATH: '', UPLOAD_LIMITER: uploadLimiter };
    const form = () => { const data = new FormData(); data.append('content', new File(['x'], 'ok.txt')); return data; };
    const upload = () => request(`/${code}/upload`, { method: 'POST', body: form() }, testEnv);
    expect((await upload()).status).toBe(200);
    expect((await upload()).status).toBe(429);
    // No binding configured -> unlimited.
    expect((await request(`/${code}/upload`, { method: 'POST', body: form() })).status).toBe(200);
  });

  it('fails open when the limiter binding throws', async () => {
    const throwing = { limit: () => { throw new Error('limiter down'); } };
    const testEnv = { ...env, BASE_PATH: '', SESSION_CREATE_LIMITER: throwing };
    const response = await worker.fetch(new Request(`${origin}/`, { headers: { 'cf-connecting-ip': '1.2.3.4' } }), testEnv);
    expect(response.status).toBe(302);
  });
});
