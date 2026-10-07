import type { Env as WorkerEnv } from '../../src/worker';

declare module 'cloudflare:workers' {
  interface ProvidedEnv extends WorkerEnv {}
}
