import { env } from 'cloudflare:workers';
import { reset, runDurableObjectAlarm, runInDurableObject } from 'cloudflare:test';
import { afterEach, describe, expect, it } from 'vitest';
import worker from '../../src/worker';
import type { Session } from '../../src/session-do';

const origin = 'https://drop5.test';
const code = 'hibernate-session';
const hostId = 'host-12345678';
const guestId = 'guest-12345678';

function request(path: string, init?: RequestInit): Promise<Response> {
  const headers = new Headers(init?.headers);
  if (!headers.has('cf-connecting-ip')) headers.set('cf-connecting-ip', '203.0.113.10');
  return worker.fetch(new Request(`${origin}${path}`, { ...init, headers }), { ...env, BASE_PATH: '' });
}

async function join(clientId: string): Promise<Record<string, any>> {
  return request(`/${code}/join`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'cf-connecting-ip': clientId.includes('host') ? '203.0.113.1' : '203.0.113.2' },
    body: JSON.stringify({ clientId }),
  }).then(r => r.json() as Promise<Record<string, any>>);
}

async function connect(clientId: string): Promise<WebSocket> {
  const response = await request(`/${code}/ws?clientId=${clientId}`, { headers: { upgrade: 'websocket' } });
  expect(response.status).toBe(101);
  const socket = response.webSocket!;
  socket.accept();
  return socket;
}

const stub = () => env.SESSIONS.get(env.SESSIONS.idFromName(code));

afterEach(async () => {
  await reset();
});

describe('Hibernation-API event-driven session lifecycle', () => {
  it('keeps a connected session alive past its TTL without heartbeats or keepalive writes', async () => {
    await join(hostId);
    const socket = await connect(hostId);
    await new Promise<void>(resolve => socket.addEventListener('message', () => resolve(), { once: true }));

    // Force the session TTL into the past, then let the alarm fire while the
    // host socket is still connected (hibernated or not).
    await runInDurableObject(stub(), async (instance: Session, state) => {
      const stored = await state.storage.get<any>('state');
      stored.expiresAt = Date.now() - 1;
      await state.storage.put('state', stored);
      // The DO instance is shared with this harness; drop its cached copy so
      // the alarm handler observes the expired state like a real eviction.
      (instance as any).data = stored;
      await state.storage.setAlarm(Date.now() + 1_000);
    });

    expect(await runDurableObjectAlarm(stub())).toBe(true);

    await runInDurableObject(stub(), async (instance: Session, state) => {
      const stored = await state.storage.get<any>('state');
      // Session must survive: an authoritative connected socket is presence.
      expect(stored).not.toBeNull();
      expect(stored.clients[hostId].status).toBe('approved');
      expect(stored.expiresAt).toBeGreaterThan(Date.now());
      // Event-driven mode: no periodic keepalive alarm is scheduled while a
      // socket stays connected; cleanup is armed by the disconnect event.
      expect(await state.storage.getAlarm()).toBeNull();
      expect((instance as any).ctx.getWebSockets().length).toBeGreaterThanOrEqual(1);
    });
    socket.close(1000, 'done');
  });

  it('schedules cleanup on the last socket disconnect and purges after the grace period', async () => {
    await join(hostId);
    const socket = await connect(hostId);
    await new Promise<void>(resolve => socket.addEventListener('message', () => resolve(), { once: true }));

    await runInDurableObject(stub(), async (_instance: Session, state) => {
      // Join schedules the session-TTL alarm (~5min out); the disconnect must
      // re-arm it to the much shorter grace window.
      expect(await state.storage.getAlarm()).toBeGreaterThan(Date.now() + 120_000);
    });
    socket.close(1000, 'done');

    // Disconnect is the cleanup trigger: closing the last socket must arm a
    // grace-period alarm even though the session TTL has not expired.
    let graceAlarm: number | null = null;
    for (let attempt = 0; attempt < 20 && graceAlarm === null; attempt++) {
      await runInDurableObject(stub(), async (_instance: Session, state) => {
        graceAlarm = await state.storage.getAlarm();
      });
      if (graceAlarm === null) await new Promise(resolve => setTimeout(resolve, 100));
    }
    expect(graceAlarm).not.toBeNull();
    expect(graceAlarm!).toBeLessThanOrEqual(Date.now() + 120_000); // within the grace window

    // Fast-forward past the grace deadline (same pattern as the TTL tests).
    await runInDurableObject(stub(), async (instance: Session, state) => {
      const stored = await state.storage.get<any>('state');
      stored.graceUntil = Date.now() - 1;
      await state.storage.put('state', stored);
      (instance as any).data = stored;
    });

    expect(await runDurableObjectAlarm(stub())).toBe(true);
    await runInDurableObject(stub(), async (_instance: Session, state) => {
      expect((await state.storage.list()).size).toBe(0);
      expect(await state.storage.getAlarm()).toBeNull();
    });
  });

  it('protects connected clients from heartbeat pruning while pruning idle ones', async () => {
    await join(hostId);
    await join(guestId);
    await request(`/${code}/approve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ clientId: hostId, targetId: guestId, decision: 'approve' }),
    });
    const socket = await connect(hostId);
    await new Promise<void>(resolve => socket.addEventListener('message', () => resolve(), { once: true }));

    // Age both clients past the 5-minute pruning window; only the host has a
    // connected (possibly hibernated) socket. The joinedAt marker proves the
    // host entry is preserved, not deleted-and-re-registered by the heartbeat.
    const joinedAtMarker = 1_700_000_000_000;
    await runInDurableObject(stub(), async (instance: Session, state) => {
      const stored = await state.storage.get<any>('state');
      stored.clients[hostId].lastSeen = Date.now() - 400_000;
      stored.clients[hostId].joinedAt = joinedAtMarker;
      stored.clients[guestId].lastSeen = Date.now() - 400_000;
      await state.storage.put('state', stored);
      (instance as any).data = stored;
    });

    const heartbeat = await request(`/${code}/heartbeat`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ clientId: hostId }),
    });
    expect(heartbeat.status).toBe(200);

    await runInDurableObject(stub(), async (_instance: Session, state) => {
      const stored = await state.storage.get<any>('state');
      expect(stored.clients[hostId].status).toBe('approved'); // connected → protected
      expect(stored.clients[hostId].joinedAt).toBe(joinedAtMarker); // preserved, not re-registered
      expect(stored.clients[guestId]).toBeUndefined(); // idle → pruned
      expect(stored.hostId).toBe(hostId);
    });
    socket.close(1000, 'done');
  });

  it('closes connected sockets with code 1001 when the session is purged', async () => {
    await join(hostId);
    const socket = await connect(hostId);
    await new Promise<void>(resolve => socket.addEventListener('message', () => resolve(), { once: true }));

    // Expire the session TTL, then issue a command request: commandRequest
    // purges an expired session even with a connected socket, and the purge
    // must actively close it (1001), not leave it dangling on a dead session.
    await runInDurableObject(stub(), async (instance: Session, state) => {
      const stored = await state.storage.get<any>('state');
      stored.expiresAt = Date.now() - 1;
      await state.storage.put('state', stored);
      (instance as any).data = stored;
    });

    const closed = new Promise<CloseEvent>(resolve =>
      socket.addEventListener('close', resolve as any, { once: true }),
    );
    const race = await Promise.race([
      request(`/${code}/heartbeat`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'cf-connecting-ip': '203.0.113.1' },
        body: JSON.stringify({ clientId: hostId }),
      }).then(() => 'command-done'),
      closed.then(event => ({ code: event.code })),
      new Promise<'timeout'>(resolve => setTimeout(() => resolve('timeout'), 2_000)),
    ]);
    if (race === 'command-done') {
      // The close event may land just after the response resolves.
      const event = await Promise.race([
        closed,
        new Promise<'timeout'>(resolve => setTimeout(() => resolve('timeout'), 2_000)),
      ]);
      expect(event).not.toBe('timeout');
      expect((event as CloseEvent).code).toBe(1001);
    } else {
      expect(race).not.toBe('timeout');
      expect((race as { code: number }).code).toBe(1001);
    }
    // Note: the triggering heartbeat then continues into its documented
    // re-registration path (a fresh state is synthesized and saved), so
    // storage is not asserted empty here — full-purge emptiness is covered
    // by the disconnect-grace test above.
  });

  it('serializes websocket acceptance with command operations (no interleaving)', async () => {
    await join(hostId);

    // Instrument the DO to detect overlap: websocket() starting while a
    // commandRequest is still in flight means acceptance bypassed the
    // exclusive() serialization queue.
    await runInDurableObject(stub(), async (instance: Session) => {
      let inCommand = false;
      const command = (instance as any).commandRequest.bind(instance);
      (instance as any).commandRequest = async (req: Request) => {
        inCommand = true;
        try {
          await new Promise(resolve => setTimeout(resolve, 50)); // widen the race window
          return await command(req);
        } finally { inCommand = false; }
      };
      const websocket = (instance as any).websocket.bind(instance);
      (instance as any).websocket = async (req: Request) => {
        if (inCommand) (instance as any).__sawInterleaving = true;
        return websocket(req);
      };
      (instance as any).__sawInterleaving = false;
    });

    // Start a command first, then a websocket connect while it is in flight.
    const commandPromise = request(`/${code}/heartbeat`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'cf-connecting-ip': '203.0.113.1' },
      body: JSON.stringify({ clientId: hostId }),
    });
    await new Promise(resolve => setTimeout(resolve, 15));
    const wsResponse = await request(`/${code}/ws?clientId=${hostId}`, { headers: { upgrade: 'websocket' } });
    expect(wsResponse.status).toBe(101);
    wsResponse.webSocket!.accept();
    await commandPromise;

    await runInDurableObject(stub(), async (instance: Session) => {
      expect((instance as any).__sawInterleaving).toBe(false);
    });
  });

  // Already-working behavior, pinned as passing regression tests.
  it('rejects websocket upgrades for unknown or rejected clients with 403', async () => {
    await join(hostId);
    await join(guestId);
    await request(`/${code}/approve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ clientId: hostId, targetId: guestId, decision: 'reject' }),
    });

    const unknown = await request(`/${code}/ws?clientId=stranger-999999`, { headers: { upgrade: 'websocket' } });
    expect(unknown.status).toBe(403);
    const rejected = await request(`/${code}/ws?clientId=${guestId}`, { headers: { upgrade: 'websocket' } });
    expect(rejected.status).toBe(403);
  });

  // Hibernation recovery (broadcasts delivered to sockets rehydrated from
  // storage after DO eviction) is covered by the existing broadcast tests in
  // tests/cloudflare/session.test.ts — intentionally not duplicated here.
});
