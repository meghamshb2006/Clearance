import { StatusTag } from './StatusTag.jsx'

function DetailField({ label, value, mono = false }) {
  return (
    <div className="detail-field">
      <span className="field-label">{label}</span>
      <div className={mono ? 'mono' : ''}>{value || '—'}</div>
    </div>
  )
}

function formatTime(value) {
  if (!value) return '—'
  return new Date(value).toLocaleString()
}

export function RequestDetail({ request, onApproveOnce, onApproveOrg, onDeny }) {
  if (!request) {
    return <div className="empty-state">Select a request from the queue.</div>
  }

  const isPending = request.status === 'pending'
  const isConnect = request.method === 'CONNECT'
  const userLabel = request.user_display_name || request.user_id
  const agentLabel = request.agent_display_name || request.agent_id

  return (
    <>
      <div className="status-row">
        <StatusTag status={request.status} />
        <span className="muted">{agentLabel}</span>
      </div>

      {isConnect ? (
        <div className="notice warn">
          <strong>CONNECT tunnel.</strong> Approve once allows a single HTTPS retry. Remember creates an
          org allow for this host (method <span className="mono">*</span>) so later tunnels auto-approve.
        </div>
      ) : null}

      <div className="detail-grid">
        <DetailField label="Destination" value={`${request.host}:${request.port}`} mono />
        <DetailField label="Method" value={request.method} mono />
        <DetailField label="Path" value={request.path || '/'} mono />
        <DetailField label="Scheme" value={request.scheme} mono />
        <DetailField label="User" value={userLabel} />
        <DetailField label="Agent" value={agentLabel} />
        <DetailField label="Requested" value={formatTime(request.requested_at)} mono />
        <DetailField label="Decided by" value={request.decided_by || '—'} mono />
        <DetailField label="Decided at" value={formatTime(request.decided_at)} mono />
        <DetailField label="Rule ref" value={request.rule_id || '—'} mono />
        <DetailField label="Notes" value={request.error_message || '—'} />
      </div>

      <details className="audit-tech">
        <summary>Technical identifiers</summary>
        <dl className="audit-facts">
          <div className="audit-facts-wide">
            <dt>Request id</dt>
            <dd className="mono">{request.id}</dd>
          </div>
          <div className="audit-facts-wide">
            <dt>User id</dt>
            <dd className="mono">{request.user_id}</dd>
          </div>
          <div className="audit-facts-wide">
            <dt>Agent id</dt>
            <dd className="mono">{request.agent_id}</dd>
          </div>
          <div className="audit-facts-wide">
            <dt>Org id</dt>
            <dd className="mono">{request.org_id}</dd>
          </div>
        </dl>
      </details>

      <div className="detail-actions">
        <button type="button" className="primary" disabled={!isPending} onClick={onApproveOnce}>
          Approve once
        </button>
        <button type="button" disabled={!isPending} onClick={onApproveOrg}>
          Remember for org
        </button>
        <button type="button" className="danger" disabled={!isPending} onClick={onDeny}>
          Deny
        </button>
      </div>

      {isPending ? (
        <p className="muted">
          Approve once grants a single retry. Remember creates a persistent allow rule for this host.
        </p>
      ) : (
        <p className="muted">This request is closed.</p>
      )}
    </>
  )
}
