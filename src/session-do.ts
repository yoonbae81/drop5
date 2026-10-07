import { DurableObject } from 'cloudflare:workers';

interface StoredFile {
  id: string;
  name: string;
  size: number;
  contentType: string;
  objectKey?: string;
  uploadedAt: number;
  expiresAt: number;
  reservation?: boolean;
  reservationExpiresAt?: number;
}
interface Client { status: 'approved' | 'pending' | 'rejected'; joinedAt: number; lastSeen: number; userAgent: string }
interface State { createdAt: number; expiresAt: number; clients: Record<string, Client>; hostId: string | null; files: StoredFile[] }
interface Env { FILES: R2Bucket; SESSION_TTL_SECONDS?: string }

export class Session extends DurableObject<Env> {
  private data: State | null = null;
  private serial: Promise<void> = Promise.resolve();

  constructor(state: DurableObjectState, env: Env) { super(state, env); }

  private async load(): Promise<State> {
    if (this.data) return this.data;
    const stored = await this.ctx.storage.get<State>('state');
    const createdAt = stored?.createdAt ?? Date.now();
    const data = stored
      ? { ...stored, expiresAt: stored.expiresAt ?? createdAt + this.sessionTtlMs() }
      : { createdAt, expiresAt: createdAt + this.sessionTtlMs(), clients: {}, hostId: null, files: [] };
    this.data = data;
    return data;
  }
  private async save(): Promise<void> { await this.ctx.storage.put('state', this.data); }
  private async approved(clientId: unknown): Promise<boolean> {
    if (typeof clientId !== 'string') return false;
    const state = await this.load();
    const client = state.clients[clientId];
    return !!client && client.status === 'approved';
  }
  private response(value: unknown, status = 200): Response { return Response.json(value, { status, headers: { 'cache-control': 'no-store' } }); }

  private exclusive<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.serial.then(operation, operation);
    this.serial = result.then(() => undefined, () => undefined);
    return result;
  }

  async fetch(request: Request): Promise<Response> {
    if (new URL(request.url).pathname === '/_ws') return this.websocket(request);
    return this.exclusive(() => this.commandRequest(request));
  }

  private async commandRequest(request: Request): Promise<Response> {
    const input = await request.json().catch(() => ({})) as Record<string, any>;
    let state = await this.load();
    const now = Date.now();
    if (state.expiresAt <= now) {
      await this.purgeSession(state);
      state = await this.load();
    }
    switch (input.op) {
      case 'touch': {
        this.refreshSession(state, now);
        await this.save(); await this.scheduleAlarm();
        return this.response({ success: true });
      }
      case 'join': {
        const id = input.clientId as string;
        if (!state.clients[id]) {
          const hasApproved = Object.values(state.clients).some(client => client.status === 'approved');
          const status = !state.hostId || !hasApproved ? 'approved' : 'pending';
          state.clients[id] = { status, joinedAt: now, lastSeen: now, userAgent: String(input.userAgent ?? '').slice(0, 300) };
          if (!state.hostId && status === 'approved') state.hostId = id;
          await this.save();
          if (status === 'pending') this.broadcast({ type: 'client-joined', client: { clientId: id, joinedAt: now, userAgent: state.clients[id].userAgent } });
        } else state.clients[id].lastSeen = now;
        this.refreshSession(state, now);
        await this.save(); await this.scheduleAlarm();
        return this.response({ success: true, status: state.clients[id].status, host: state.hostId === id, pending_requests: this.pending(state) });
      }
      case 'heartbeat': {
        for (const [id, client] of Object.entries(state.clients)) {
          if (now - client.lastSeen > 300_000) delete state.clients[id];
        }
        if (!state.clients[state.hostId ?? '']) state.hostId = null;
        const client = state.clients[input.clientId];
        if (!client) return this.response({ success: false, error: 'Unknown client', errorKey: 'device_approval_required' }, 403);
        client.lastSeen = now;
        const activeHost = Object.entries(state.clients).find(([, item]) => item.status === 'approved');
        if (!activeHost) {
          await Promise.all(state.files.map(file => file.objectKey ? this.env.FILES.delete(file.objectKey) : Promise.resolve()));
          state.files = [];
          client.status = 'approved';
          state.hostId = input.clientId;
          this.broadcast({ type: 'client-approved', clientId: input.clientId });
        } else if (!state.hostId) state.hostId = activeHost[0];
        this.refreshSession(state, now);
        await this.save(); await this.scheduleAlarm();
        return this.response({ success: true, status: client.status, host: state.hostId === input.clientId, pending_requests: this.pending(state) });
      }
      case 'approve': {
        if (input.clientId !== state.hostId || !await this.approved(input.clientId)) return this.response({ success: false, error: 'Unauthorized', errorKey: 'device_approval_required' }, 403);
        const target = state.clients[input.targetId];
        if (!target) return this.response({ success: false, error: 'Target client not found', errorKey: 'connection_refused' }, 404);
        if (input.decision !== 'approve' && input.decision !== 'reject') return this.response({ success: false, error: 'Invalid decision', errorKey: 'connection_refused' }, 400);
        target.status = input.decision === 'approve' ? 'approved' : 'rejected';
        this.refreshSession(state, now);
        await this.save(); await this.scheduleAlarm();
        this.broadcast({ type: input.decision === 'approve' ? 'client-approved' : 'client-rejected', clientId: input.targetId });
        return this.response({ success: true });
      }
      case 'list': {
        if (!await this.approved(input.clientId)) return this.response({ success: false, error: 'Unauthorized', errorKey: 'device_approval_required', status: 'pending' }, 403);
        if (await this.expireFiles()) return this.response({ success: true, files: [] });
        return this.response({ success: true, files: state.files.filter(file => !file.reservation).map(file => ({ id: file.id, name: file.name, size: file.size, expiresAt: file.expiresAt, uploadedAt: file.uploadedAt })) });
      }
      case 'reserve': {
        const files = input.files as StoredFile[];
        if (await this.expireFiles()) state = await this.load();
        const active = state.files;
        if (active.length + files.length > input.maxFiles) {
          return this.response({
            success: false,
            error: 'File count limit exceeded',
            errorKey: 'file_count_exceeded',
            errorParams: { mode: 'default', limit: input.maxFiles },
          }, 409);
        }
        if (active.reduce((sum, file) => sum + file.size, 0) + files.reduce((sum, file) => sum + file.size, 0) > input.maxBytes) {
          return this.response({
            success: false,
            error: 'Storage limit exceeded',
            errorKey: 'storage_limit_exceeded',
            errorParams: { max_mb: Math.floor(input.maxBytes / (1024 * 1024)) },
          }, 409);
        }
        for (const file of files) { file.uploadedAt = now; file.reservation = true; file.reservationExpiresAt = now + 2 * 60 * 1000; }
        state.files.push(...files);
        this.refreshSession(state, now);
        await this.save();
        await this.scheduleAlarm();
        return this.response({ success: true });
      }
      case 'commit': {
        const replacements = input.files as Array<StoredFile>;
        const reservations = new Set(state.files.filter(file => file.reservation).map(file => file.id));
        if (replacements.some(file => !reservations.has(file.id))) return this.response({ success: false, error: 'Upload reservation expired', errorKey: 'upload_failed' }, 409);
        state.files = state.files.map(file => {
          const replacement = replacements.find(candidate => candidate.id === file.id);
          if (!replacement) return file;
          const committed = { ...replacement, uploadedAt: file.uploadedAt, reservation: false };
          delete committed.reservationExpiresAt;
          return committed;
        });
        this.refreshSession(state, now);
        await this.save(); await this.scheduleAlarm();
        this.broadcast({ type: 'file-uploaded', files: replacements.map(({ id, name, size, expiresAt }) => ({ id, name, size, expiresAt })) });
        return this.response({ success: true });
      }
      case 'release': {
        const ids = new Set(input.ids as string[]); state.files = state.files.filter(file => !ids.has(file.id)); this.refreshSession(state, now); await this.save(); await this.scheduleAlarm(); return this.response({ success: true });
      }
      case 'getFile': {
        if (!await this.approved(input.clientId)) return this.response({ success: false, error: 'Unauthorized', errorKey: 'device_approval_required' }, 403);
        if (await this.expireFiles()) return this.response({ success: false, error: 'File not found', errorKey: 'upload_failed' }, 404);
        const file = state.files.find(item => !item.reservation && (item.id === input.id || item.name === input.name));
        return file ? this.response({ success: true, file }) : this.response({ success: false, error: 'File not found', errorKey: 'upload_failed' }, 404);
      }
      case 'deleteAll': {
        if (!await this.approved(input.clientId)) return this.response({ success: false, error: 'Unauthorized', errorKey: 'device_approval_required' }, 403);
        const files = state.files;
        await Promise.all(files.map(file => file.objectKey ? this.env.FILES.delete(file.objectKey) : Promise.resolve()));
        state.files = []; this.refreshSession(state, now); await this.save(); await this.scheduleAlarm();
        this.broadcast({ type: 'file-deleted' }); return this.response({ success: true });
      }
      default: return this.response({ success: false, error: 'Unknown operation', errorKey: 'upload_failed' }, 400);
    }
  }

  async alarm(): Promise<void> {
    await this.exclusive(async () => {
      const state = await this.load();
      if (state.expiresAt <= Date.now()) await this.purgeSession(state);
      else await this.expireFiles();
    });
  }

  private pending(state: State) {
    return Object.entries(state.clients).filter(([, client]) => client.status === 'pending').map(([clientId, client]) => ({ clientId, joined_at: client.joinedAt, browser: client.userAgent }));
  }
  private sessionTtlMs(): number {
    const seconds = Number(this.env.SESSION_TTL_SECONDS ?? 300);
    return Number.isFinite(seconds) && seconds > 0 ? seconds * 1000 : 300_000;
  }
  private refreshSession(state: State, now = Date.now()): void {
    const fileDeadline = Math.max(...state.files.map(file => file.reservation ? file.reservationExpiresAt ?? file.expiresAt : file.expiresAt), 0);
    state.expiresAt = Math.max(now + this.sessionTtlMs(), fileDeadline);
  }
  private async scheduleAlarm(): Promise<void> {
    const state = await this.load();
    const next = Math.min(state.expiresAt, ...state.files.map(file => file.reservation ? file.reservationExpiresAt ?? file.expiresAt : file.expiresAt));
    if (Number.isFinite(next)) await this.ctx.storage.setAlarm(Math.max(Date.now() + 1000, next));
    else await this.ctx.storage.deleteAlarm();
  }
  private async purgeSession(state: State): Promise<void> {
    await Promise.all(state.files.map(file => file.objectKey ? this.env.FILES.delete(file.objectKey) : Promise.resolve()));
    await this.ctx.storage.deleteAll();
    await this.ctx.storage.deleteAlarm();
    this.data = null;
  }
  private async expireFiles(): Promise<boolean> {
    const state = await this.load(); const now = Date.now();
    const expired = state.files.filter(file => file.reservation ? (file.reservationExpiresAt ?? 0) <= now : file.expiresAt <= now);
    if (expired.length) {
      await Promise.all(expired.map(file => file.objectKey ? this.env.FILES.delete(file.objectKey) : Promise.resolve()));
      state.files = state.files.filter(file => !expired.some(expiredFile => expiredFile.id === file.id));
      this.broadcast({ type: 'file-expired', ids: expired.map(file => file.id) });
      if (!state.files.length) {
        await this.purgeSession(state);
        return true;
      }
    }
    await this.save(); await this.scheduleAlarm();
    return false;
  }
  private async websocket(request: Request): Promise<Response> {
    const clientId = new URL(request.url).searchParams.get('clientId');
    const state = await this.load();
    if (!clientId || !state.clients[clientId] || state.clients[clientId].status === 'rejected') return new Response('Unauthorized', { status: 403 });
    const pair = new WebSocketPair(); const client = pair[0]; const server = pair[1];
    this.ctx.acceptWebSocket(server, [clientId!]);
    server.serializeAttachment({ clientId, connectedAt: Date.now() });
    server.send(JSON.stringify({ type: 'connected' }));
    return new Response(null, { status: 101, webSocket: client });
  }
  webSocketMessage(socket: WebSocket, message: string | ArrayBuffer): void {
    if (typeof message !== 'string') return;
    try { const data = JSON.parse(message); if (data.type === 'ping') socket.send(JSON.stringify({ type: 'pong', at: Date.now() })); } catch { /* Ignore malformed client events. */ }
  }
  webSocketClose(): void {}
  webSocketError(): void {}
  private broadcast(message: unknown): void {
    const payload = JSON.stringify(message);
    const type = (message as { type?: string }).type;
    const state = this.data;
    for (const socket of this.ctx.getWebSockets()) {
      const attachment = socket.deserializeAttachment() as { clientId?: string } | null;
      const clientId = attachment?.clientId;
      const client = clientId ? state?.clients[clientId] : undefined;
      const isHost = clientId === state?.hostId;
      const isTarget = (message as { clientId?: string }).clientId === clientId;
      const visible = type === 'client-joined' ? isHost : type === 'client-approved' || type === 'client-rejected' ? isTarget : client?.status === 'approved';
      if (visible) { try { socket.send(payload); } catch { /* stale socket */ } }
    }
  }
}
