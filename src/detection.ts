import type { Store, Audit } from './store.js';
export interface Detection {
  rule: string;
  severity: string;
  actor: string;
  evidence: number;
  count?: number;
  windowSeconds?: number;
}
export interface DetectionOptions {
  sink?: string | undefined;
  write?: (line: string) => void;
  fetch?: typeof fetch;
}
export class DetectionExport {
  private pending = new Set<Promise<void>>();
  constructor(
    private store: Store,
    private options: DetectionOptions = {},
  ) {
    if (options.sink && options.sink !== 'stdout') {
      const url = new URL(options.sink);
      if (url.protocol !== 'https:' || url.username || url.password || url.hash)
        throw new Error(
          'DETECTION_SINK must be stdout or an HTTPS URL without credentials or fragment',
        );
    }
  }
  emit(d: Detection, evidence: Audit) {
    if (!this.options.sink) return;
    const fail = () =>
      this.store.audit(evidence.tenant, 'system', 'detection.sink.failed', 'error', {
        rule: d.rule,
        evidence: d.evidence,
      });
    if (this.pending.size >= 100) {
      fail();
      return;
    }
    const event = {
      activity_id: 1,
      category_uid: 2,
      class_uid: 2004,
      type_uid: 200401,
      time: Date.parse(evidence.at),
      severity_id: d.severity === 'high' ? 4 : 3,
      metadata: {
        version: '1.4.0',
        product: { name: 'MCP Sentinel', vendor_name: 'MCP Sentinel', version: '1.1.0' },
      },
      finding_info: {
        uid: d.rule + ':' + d.evidence,
        title: d.rule,
        created_time: Date.parse(evidence.at),
      },
      unmapped: {
        tenant: evidence.tenant,
        actor: d.actor,
        evidence_seq: d.evidence,
        ...(d.count ? { count: d.count } : {}),
      },
    };
    const send = async () => {
      try {
        if (this.options.sink === 'stdout')
          (
            this.options.write ??
            ((line) => {
              process.stdout.write(line);
            })
          )(JSON.stringify(event) + '\n');
        else {
          const response = await (this.options.fetch ?? fetch)(this.options.sink!, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(event),
            redirect: 'error',
            signal: AbortSignal.timeout(3000),
          });
          await response.body?.cancel();
          if (!response.ok) throw new Error('Webhook rejected');
        }
      } catch {
        fail();
      }
    };
    const job = send();
    this.pending.add(job);
    void job.finally(() => this.pending.delete(job));
  }
  async flush() {
    await Promise.all(this.pending);
  }
}
