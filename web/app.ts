const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
let token = '';
function node(tag: string, text = '', className = '') {
  const e = document.createElement(tag);
  e.textContent = text;
  e.className = className;
  return e;
}
function notice(message: string, error = false) {
  $('notice').textContent = message;
  $('notice').classList.toggle('error', error);
}
async function api(path: string, method = 'GET', body?: unknown, credential = token) {
  const response = await fetch(path, {
    method,
    headers: {
      authorization: `Bearer ${credential}`,
      ...(body ? { 'content-type': 'application/json' } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error ?? 'request_failed');
  return data;
}
function error(e: unknown) {
  notice(e instanceof Error ? e.message : 'Request failed', true);
}
function value(id: string) {
  return $<HTMLInputElement>(id).value;
}
function cell(row: HTMLElement, text: string, cls = '') {
  const c = node('td', text, cls);
  row.append(c);
  return c;
}

async function refresh() {
  const data = await api('/api/overview');
  for (const key of ['allowed', 'denied']) $(key).textContent = String(data.totals[key]);
  $('pending').textContent = String(data.totals.pending);
  $('signals').textContent = String(data.detections.length);
  $('policy-version').textContent = data.policy.version;
  $('rule-count').textContent = String(data.policy.rules);
  $('policy-hash').textContent = data.policy.hash;
  $('integrity').textContent = data.integrity ? 'Audit chain verified' : 'Integrity failure';
  const body = $('events');
  body.replaceChildren();
  $('events-empty').hidden = data.events.length > 0;
  for (const e of data.events.slice(0, 10)) {
    const row = node('tr');
    cell(row, new Date(e.at).toLocaleTimeString([], { hour12: false }), 'mono');
    const actor = cell(row, '');
    actor.append(node('b', e.actor), node('small', e.action));
    cell(row, e.outcome).append();
    cell(row, `#${e.seq} · ${e.hash.slice(0, 8)}`, 'mono');
    body.append(row);
  }
  const suspensions = $('suspension-list');
  suspensions.replaceChildren();
  if (!data.suspensions.length) suspensions.textContent = 'No active suspensions.';
  for (const s of data.suspensions) {
    const item = node('div', '', 'finding');
    item.append(
      node('p', `${s.subject} suspended until ${new Date(s.expires).toLocaleTimeString()}`),
    );
    const lift = node('button', 'Lift suspension', 'ghost');
    lift.onclick = () =>
      void api('/api/suspensions/lift', 'POST', { subject: s.subject }).then(refresh).catch(error);
    item.append(lift);
    suspensions.append(item);
  }
  const det = $('detections');
  det.replaceChildren();
  det.className = data.detections.length ? '' : 'empty';
  if (!data.detections.length) det.textContent = 'No signals in the current window.';
  for (const d of data.detections.slice(0, 6)) {
    const item = node('div', '', 'finding');
    const top = node('div', '', 'finding-top');
    top.append(node('h3', d.rule.replaceAll('-', ' ')), node('span', d.severity, 'badge high'));
    item.append(
      top,
      node('p', `${d.actor} · ${d.count ? d.count + ' denials' : 'evidence #' + d.evidence}`),
    );
    det.append(item);
  }
  try {
    const { approvals } = await api('/api/approvals');
    const list = $('approval-list');
    list.replaceChildren();
    list.className = approvals.length ? '' : 'empty';
    if (!approvals.length) list.textContent = 'No approval requests in this tenant.';
    for (const a of approvals.slice(0, 6)) {
      const box = node('div', '', 'review-item');
      const top = node('div', '', 'finding-top');
      top.append(node('b', a.request.tool ?? 'Protected request'), node('span', a.status, 'badge'));
      box.append(
        top,
        node('p', `${a.subject} · ${new Date(a.expires).toLocaleTimeString()} expiry`),
        node(
          'p',
          (typeof a.request.args === 'string'
            ? a.request.args
            : JSON.stringify(a.request.args ?? {})) +
            (a.request.argsTruncated ? ' [truncated at 4 KB]' : ''),
          'mono',
        ),
        node('p', a.id, 'mono'),
      );
      if (a.status === 'pending' && a.expires > Date.now()) {
        const actions = node('div', '', 'review-actions');
        for (const approve of [true, false]) {
          const btn = node(
            'button',
            approve ? 'Approve once' : 'Reject',
            approve ? 'primary' : 'ghost',
          );
          btn.onclick = () =>
            void api(`/api/approvals/${a.id}/review`, 'POST', { approve })
              .then(() => {
                notice(
                  approve
                    ? 'Approval granted. The agent can execute this exact request once.'
                    : 'Request rejected.',
                );
                return refresh();
              })
              .catch(error);
          actions.append(btn);
        }
        box.append(actions);
      }
      list.append(box);
    }
  } catch {
    $('approval-list').textContent = 'Operator access is required to review requests.';
  }
}
$('connect').onclick = () => {
  token = value('token');
  void api('/api/me')
    .then((me) => {
      $('status').textContent = `${me.agent} · ${me.role}`;
      notice(`Connected to ${me.tenant}. Decisions and evidence are scoped to this tenant.`);
      return refresh();
    })
    .catch(error);
};
$('refresh').onclick = () => void refresh().catch(error);
$<HTMLSelectElement>('tool').onchange = () => {
  const tool = value('tool');
  $<HTMLTextAreaElement>('arguments').value =
    tool === 'evidence.export'
      ? '{"caseId":"case-demo","format":"json"}'
      : tool === 'cloud.audit.summary'
        ? '{"provider":"aws","records":[{"eventID":"sample-1","eventTime":"2026-01-01T00:00:00Z","eventName":"ListUsers","userIdentity":{"principalId":"synthetic"}}]}'
        : tool === 'admin.delete'
          ? '{}'
          : '{"query":"approval"}';
};
async function submit(approval: boolean) {
  try {
    const tool = value('tool'),
      args = JSON.parse(value('arguments')),
      approvalId = value('approval-id');
    const result = await api(
      approval ? '/api/approvals' : '/api/call',
      'POST',
      { tool, arguments: args, ...(!approval && approvalId ? { approvalId } : {}) },
      value('agent-token'),
    );
    $('output').textContent = JSON.stringify(result, null, 2);
    if (approval) $<HTMLInputElement>('approval-id').value = result.id;
    if (token) await refresh();
  } catch (e) {
    $('output').textContent = e instanceof Error ? e.message : 'Request failed';
    if (token)
      try {
        await refresh();
      } catch {}
  }
}
$('execute').onclick = () => void submit(false);
$('request-approval').onclick = () => void submit(true);
