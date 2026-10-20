import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { afterEach, vi } from 'vitest';

// Shared browser harness for public/app.js tests. Executes the real browser
// IIFE in Node against hand-rolled DOM/WebSocket/fetch adapters plus vitest
// fake timers. The FakeWebSocket models the real lifecycle: the constructor
// leaves the socket in CONNECTING (readyState 0) and onopen fires only when
// the test (or autoOpen) moves it to OPEN.

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
export const APP_SOURCE = readFileSync(path.join(ROOT, 'public', 'app.js'), 'utf8');

export type RecordedRequest = { url: string; init: RequestInit | undefined };

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

export class HarnessWebSocket {
  static instances: HarnessWebSocket[] = [];
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;
  static autoOpen = true;
  url: string;
  readyState = 0; // CONNECTING until the connection is accepted
  sent: string[] = [];
  closed = false;
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  constructor(url: string) {
    this.url = url;
    HarnessWebSocket.instances.push(this);
    if (HarnessWebSocket.autoOpen) queueMicrotask(() => this.simulateOpen());
  }
  simulateOpen(): void {
    if (this.readyState !== 0) return;
    this.readyState = 1;
    if (this.onopen) this.onopen();
  }
  simulateMessage(data: unknown): void {
    if (this.readyState !== 1) return;
    if (this.onmessage) this.onmessage({ data: typeof data === 'string' ? data : JSON.stringify(data) });
  }
  simulateError(): void {
    if (this.onerror) this.onerror();
  }
  simulateClose(): void {
    if (this.readyState === 3) return;
    this.readyState = 3;
    if (this.onclose) this.onclose();
  }
  // Timeout path: close() on a CONNECTING socket goes straight to CLOSED.
  send(data: string): void { this.sent.push(data); }
  close(): void {
    if (this.readyState === 0) { this.simulateClose(); return; }
    this.readyState = 3;
  }
}

export async function flushMicrotasks(): Promise<void> {
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

export interface Harness {
  requests: RecordedRequest[];
  documentListeners: Map<string, Set<() => void>>;
  windowListeners: Map<string, Set<() => void>>;
  setVisibility: (state: 'visible' | 'hidden') => void;
  dispatchWindow: (type: string) => void;
  /** Join payload and subsequent heartbeat payloads. */
  setSessionPayload: (payload: Record<string, unknown>) => void;
  setFilesPayload: (payload: Record<string, unknown>) => void;
}

export function setupHarness(): Harness {
  const requests: RecordedRequest[] = [];
  const documentListeners = new Map<string, Set<() => void>>();
  const windowListeners = new Map<string, Set<() => void>>();
  let sessionPayload: Record<string, unknown> = { success: true, status: 'approved', pending_requests: [] };
  let filesPayload: Record<string, unknown> = { success: true, files: [] };

  // NOTE: setup is synchronous so tests may call setupHarness() at the top of
  // each test; cleanup is registered for the enclosing test automatically.
  vi.useFakeTimers();
  requests.length = 0;
  documentListeners.clear();
  windowListeners.clear();
  HarnessWebSocket.instances = [];
  HarnessWebSocket.autoOpen = true;

    const fetchMock = vi.fn(async (input: unknown, init?: RequestInit) => {
      const url = String(input);
      requests.push({ url, init });
      let payload: unknown = {};
      if (url.includes('/locales/')) {
        payload = {};
      } else if (url.includes('/join')) {
        payload = sessionPayload;
      } else if (url.includes('/heartbeat')) {
        payload = sessionPayload;
      } else if (url.includes('/files')) {
        payload = filesPayload;
      } else {
        payload = { success: true };
      }
      return {
        ok: true,
        status: 200,
        json: async () => payload,
      } as unknown as Response;
    });

    setGlobal('fetch', fetchMock);
    setGlobal('WebSocket', HarnessWebSocket);
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
      visibilityState: 'visible',
      cookie: '',
      getElementById: () => null,
      querySelectorAll: () => [],
      createElement: () => makeElement(),
      addEventListener(type: string, listener: () => void) {
        if (!documentListeners.has(type)) documentListeners.set(type, new Set());
        documentListeners.get(type)!.add(listener);
      },
    });
    // Capture the window-level lifecycle listeners the app registers.
    setGlobal('addEventListener', (type: string, listener: () => void) => {
      if (!windowListeners.has(type)) windowListeners.set(type, new Set());
      windowListeners.get(type)!.add(listener);
    });
    setGlobal('removeEventListener', () => {});
    // XMLHttpRequest is only used for uploads; idle/lifecycle paths must not touch it.
    setGlobal('XMLHttpRequest', class {
      open() {}
      send() {}
      upload = { addEventListener() {} };
      addEventListener() {}
    });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    restoreGlobals();
  });

  return {
    requests,
    documentListeners,
    windowListeners,
    setVisibility(state: 'visible' | 'hidden') {
      (globalThis as unknown as { document: { visibilityState: string } }).document.visibilityState = state;
    },
    dispatchWindow(type: string) {
      for (const listener of windowListeners.get(type) ?? []) listener();
    },
    setSessionPayload(payload: Record<string, unknown>) { sessionPayload = payload; },
    setFilesPayload(payload: Record<string, unknown>) { filesPayload = payload; },
  };
}

export async function bootApp(): Promise<void> {
  new Function(APP_SOURCE)();
  await flushMicrotasks();
}

export function requestsOf(harness: Harness, matcher: string, from = 0): RecordedRequest[] {
  return harness.requests.slice(from).filter(request => request.url.includes(matcher));
}

export { expect };
