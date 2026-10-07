import { env } from 'cloudflare:workers';
import { evictDurableObject, reset, runDurableObjectAlarm, runInDurableObject } from 'cloudflare:test';
import { afterEach, describe, expect, it } from 'vitest';
import worker from '../../src/worker';
import type { Session } from '../../src/session-do';

const origin = 'https://drop5.test';
const code = 'test-session';
const hostId = 'host-12345678';
const guestId = 'guest-12345678';

function request(path: string, init?: RequestInit): Promise<Response> {
  return worker.fetch(new Request(`${origin}${path}`, init), env);
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
