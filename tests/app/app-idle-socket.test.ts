import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// Root directory of the repo (tests/app/ -> repo root is two levels up).
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const APP_SOURCE = readFileSync(path.join(ROOT, 'public', 'app.js'), 'utf8');

type RecordedRequest = { url: string; init: RequestInit | undefined };

type ElementStub = {
  style: Record<string, string>;
  dataset: Record<string, string>;
  classList: { add(): void; remove(): void; toggle(): void; contains(): boolean };
  addEventListener(): void;
  removeEventListener(): void;
  setAttribute(): void;
  getAttribute(): string | null;
  appendChild(): void;
  querySelector(): ElementStub | null;
  querySelectorAll(): ElementStub[];
  focus(): void;
  click(): void;
  textContent: string;
  innerHTML: string;
  title: string;
};

function makeElement(): ElementStub {
  return {
    style: {},
    dataset: {},
    classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
    addEventListener() {},
    removeEventListener() {},
    setAttribute() {},
    getAttribute: () => null,
    appendChild() {},
    querySelector: () => null,
    querySelectorAll: () => [],
    focus() {},
    click() {},
    textContent: '',
    innerHTML: '',
    title: '',
  };
}

// Fake WebSocket: constructor records the URL and synchronously transitions to
// OPEN (equivalent to the server accepting the connection) before the app can
// schedule anything else.
class FakeWebSocket {
  static instances: FakeWebSocket[] = [];
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;
  url: string;
  readyState = 1;
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  constructor(url: string) {
    this.url = url;
    FakeWebSocket.instances.push(this);
    queueMicrotask(() => {
      if (this.onopen) this.onopen();
    });
  }
  send(): void {}
  close(): void {}
}

async function flushMicrotasks(): Promise<void> {
  for (let i = 0; i < 10; i += 1) {
    await Promise.resolve();
  }
}

  const globalBackup = new Map<string, PropertyDescriptor | undefined>();
  function setGlobal(name: string, value: unknown): void {
    if (!globalBackup.has(name)) {
      globalBackup.set(name, Object.getOwnPropertyDescriptor(globalThis, name));
    }
    Object.defineProperty(globalThis, name, { value, writable: true, configurable: true });
  }

  function restoreGlobals(): void {
    for (const [name, descriptor] of globalBackup) {
      if (descriptor) Object.defineProperty(globalThis, name, descriptor);
      else delete (globalThis as unknown as Record<string, unknown>)[name];
    }
    globalBackup.clear();
  }

  describe('app.js network behavior with an open WebSocket', () => {
  let requests: RecordedRequest[];

  beforeEach(() => {
    vi.useFakeTimers();
    requests = [];
    FakeWebSocket.instances = [];

    const fetchMock = vi.fn(async (input: unknown, init?: RequestInit) => {
      const url = String(input);
      requests.push({ url, init });
      let payload: unknown = {};
      if (url.includes('/locales/')) {
        payload = {};
      } else if (url.includes('/join')) {
        payload = { success: true, status: 'approved', pending_requests: [] };
      } else {
        payload = { success: true, files: [] };
      }
      return {
        ok: true,
        status: 200,
        json: async () => payload,
      } as unknown as Response;
    });

    setGlobal('fetch', fetchMock);
    setGlobal('WebSocket', FakeWebSocket);
    setGlobal('location', {
      pathname: '/testsession',
      protocol: 'https:',
      host: 'drop5.example',
      href: 'https://drop5.example/testsession',
      reload: () => {},
    });
    setGlobal('navigator', { userAgent: 'Vitest', language: 'en' });
    setGlobal('sessionStorage', {
      store: new Map<string, string>(),
      getItem(key: string) {
        return (this.store as Map<string, string>).get(key) ?? null;
      },
      setItem(key: string, value: string) {
        (this.store as Map<string, string>).set(key, value);
      },
    });
    setGlobal('crypto', { randomUUID: () => 'test-client-id' });
    setGlobal('window', globalThis);
    setGlobal('document', {
      documentElement: { lang: 'en', setAttribute() {}, getAttribute: () => null },
      cookie: '',
      getElementById: () => null,
      querySelectorAll: () => [],
      createElement: () => makeElement(),
      addEventListener() {},
    });
    // XMLHttpRequest is only used for uploads; the idle path must not touch it.
    setGlobal('XMLHttpRequest', class {
      open() {}
      send() {}
      upload = { addEventListener() {} };
      addEventListener() {}
    });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    restoreGlobals();
  });

  it('stops periodic heartbeat/files polling once the WebSocket is open', async () => {
    // Execute the real browser bundle (the IIFE runs joinSession() itself).
    new Function(APP_SOURCE)();
    await flushMicrotasks();

    // joinSession succeeded and the WebSocket was created and opened.
    expect(FakeWebSocket.instances.length).toBe(1);
    expect(FakeWebSocket.instances[0].readyState).toBe(1);
    const requestsAtConnect = requests.length;

    // Idle approved client: no uploads, no visibility changes, 20s on the clock.
    await vi.advanceTimersByTimeAsync(20_000);

    const postConnect = requests.slice(requestsAtConnect);
    const heartbeatCalls = postConnect.filter(r => r.url.includes('/heartbeat'));
    const filesCalls = postConnect.filter(r => r.url.includes('/files'));

    // DESIRED behavior: with an open WebSocket, the idle approved client must
    // not send periodic HTTP heartbeats or files requests. Event-driven
    // updates should replace the 4s poll loop (which may only run in a
    // back-off form while the socket is down).
    expect(heartbeatCalls, 'no periodic /heartbeat while WebSocket is open').toEqual([]);
    expect(filesCalls, 'no periodic /files while WebSocket is open').toEqual([]);
  });
});
