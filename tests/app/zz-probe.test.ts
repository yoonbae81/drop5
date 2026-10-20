import { describe, expect, it } from 'vitest';
import { setupHarness, bootApp, HarnessWebSocket } from './harness';
describe('probe', () => {
  it('globals visible', async () => {
    setupHarness();
    expect('location' in globalThis).toBe(true);
    expect((globalThis as any).location.pathname).toBe('/testsession');
    await bootApp();
    console.log('SOCKETS', HarnessWebSocket.instances.length);
    expect(true).toBe(true);
  });
});
