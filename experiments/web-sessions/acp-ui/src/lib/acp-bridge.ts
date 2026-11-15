// Upstream: formulahendry/acp-ui@cd9c3cb src/lib/acp-bridge.ts (MIT), reduced for wicket:
// - no Tauri host, fs handlers, traffic monitor or telemetry: every agent request but
//   `session/request_permission` gets -32601 (wicket's endpoint never sends any);
// - no 60 s timeout on `session/prompt` (upstream rejects any request after 60 s, so a long turn
//   "failed" while the agent carried on); other requests keep it;
// - permission requests queue (upstream kept one at a time and dropped none, but a second one
//   replaced the first's dialog while its resolver was still waiting).
import type { AcpTransport, Unsubscribe } from './transport/types';
import type { PermissionRequest } from './types';
import { escalationOf } from '../../../common/wicket';
import { ref, type Ref } from 'vue';

const JSONRPC_METHOD_NOT_FOUND = -32601;

export class AcpClientBridge {
  private resolvers = new Map<number, { resolve: (r: any) => void; reject: (e: Error) => void }>();
  private nextRequestId = 0;
  private unlisten: Unsubscribe[] = [];
  public permissions: Ref<PermissionRequest[]> = ref([]);
  private permissionResolvers = new Map<string, (r: unknown) => void>();
  public onSessionUpdate: ((n: any) => void) | null = null;
  public onTransportClose: ((reason?: string) => void) | null = null;

  constructor(private transport: AcpTransport) {
    this.unlisten.push(this.transport.onMessage((m) => this.handleMessage(m)));
    this.unlisten.push(
      this.transport.onClose((reason) => {
        const err = new Error(`transport closed: ${reason ?? 'unknown reason'}`);
        for (const r of this.resolvers.values()) r.reject(err);
        this.resolvers.clear();
        this.onTransportClose?.(reason);
      }),
    );
  }

  private handleMessage(message: string): void {
    let parsed: any;
    try {
      parsed = JSON.parse(message);
    } catch {
      return;
    }
    const hasId = 'id' in parsed && parsed.id !== undefined && parsed.id !== null;
    if (hasId && !('method' in parsed)) {
      const r = this.resolvers.get(parsed.id);
      if (!r) return;
      this.resolvers.delete(parsed.id);
      if (parsed.error) r.reject(new Error(parsed.error.message || 'Unknown error'));
      else r.resolve(parsed.result);
    } else if (hasId) {
      void this.handleRequest(parsed.id, parsed.method, parsed.params);
    } else if (parsed.method === 'session/update') {
      this.onSessionUpdate?.(parsed.params);
    }
  }

  private async handleRequest(id: number | string, method: string, params: any): Promise<void> {
    let response: unknown;
    if (method === 'session/request_permission') {
      response = { jsonrpc: '2.0', id, result: await this.requestPermission(id, params) };
    } else {
      response = { jsonrpc: '2.0', id, error: { code: JSONRPC_METHOD_NOT_FOUND, message: `Method not found: ${method}` } };
    }
    await this.transport.send(JSON.stringify(response));
  }

  private sendRequest<T>(method: string, params: unknown, timeoutMs: number | null = 60000): Promise<T> {
    const id = this.nextRequestId++;
    return new Promise((resolve, reject) => {
      this.resolvers.set(id, { resolve, reject });
      this.transport.send(JSON.stringify({ jsonrpc: '2.0', id, method, params: params || {} })).catch((e) => {
        this.resolvers.delete(id);
        reject(e);
      });
      if (timeoutMs !== null) {
        setTimeout(() => {
          if (this.resolvers.delete(id)) reject(new Error(`Request timeout: ${method}`));
        }, timeoutMs);
      }
    });
  }

  initialize(params: unknown) {
    return this.sendRequest<any>('initialize', params);
  }
  newSession(params: unknown) {
    return this.sendRequest<{ sessionId: string }>('session/new', params);
  }
  loadSession(params: unknown) {
    return this.sendRequest<unknown>('session/load', params, null);
  }
  prompt(params: unknown) {
    return this.sendRequest<{ stopReason: string }>('session/prompt', params, null);
  }

  private requestPermission(rpcId: number | string, p: any): Promise<unknown> {
    return new Promise((resolve) => {
      const key = String(rpcId);
      this.permissionResolvers.set(key, resolve);
      this.permissions.value = [
        ...this.permissions.value,
        {
          rpcId,
          sessionId: p.sessionId,
          toolCall: { toolCallId: p.toolCall?.toolCallId, title: p.toolCall?.title ?? '', kind: p.toolCall?.kind ?? 'other', status: 'pending' },
          options: p.options ?? [],
          escalation: escalationOf(p) ?? undefined,
        },
      ];
    });
  }

  /** Answers a queued permission request: an option, or cancelled. */
  answerPermission(rpcId: number | string, optionId: string | null) {
    const key = String(rpcId);
    const resolve = this.permissionResolvers.get(key);
    if (!resolve) return;
    this.permissionResolvers.delete(key);
    this.permissions.value = this.permissions.value.filter((r) => String(r.rpcId) !== key);
    resolve(optionId ? { outcome: { outcome: 'selected', optionId } } : { outcome: { outcome: 'cancelled' } });
  }

  async disconnect() {
    this.unlisten.forEach((u) => u());
    await this.transport.close();
  }
}
