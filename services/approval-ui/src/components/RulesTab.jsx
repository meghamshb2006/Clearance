import { useCallback, useEffect, useMemo, useState } from 'react'
import { ApiError, createRule, listRules, revokeRule } from '../api/client.js'

const EMPTY_FORM = {
  effect: 'allow',
  host: '',
  port: '443',
  method: '*',
  path_prefix: '/',
}

function formatTime(value) {
  if (!value) return '—'
  return new Date(value).toLocaleString()
}

function ruleSummary(rule) {
  const effect = rule.effect === 'deny' ? 'Block' : 'Allow'
  const method = rule.method === '*' ? 'any method' : rule.method
  const path = !rule.path_prefix || rule.path_prefix === '/' ? 'any path' : `paths under ${rule.path_prefix}`
  return `${effect} ${method} to ${rule.host}:${rule.port} (${path}).`
}

function EffectBadge({ effect }) {
  const isAllow = effect === 'allow'
  return (
    <span className={`rule-effect ${isAllow ? 'allow' : 'deny'}`}>{isAllow ? 'Allow' : 'Deny'}</span>
  )
}

export function RulesTab({ onStatus, onAuthRequired, refreshToken, active }) {
  const [rules, setRules] = useState([])
  const [form, setForm] = useState(EMPTY_FORM)
  const [saving, setSaving] = useState(false)
  const [effectFilter, setEffectFilter] = useState('')
  const [selectedId, setSelectedId] = useState('')
  const [composerOpen, setComposerOpen] = useState(false)

  const loadRules = useCallback(async () => {
    try {
      const items = await listRules()
      setRules(items)
      setSelectedId((prev) => {
        if (prev && items.some((item) => item.id === prev)) return prev
        return items[0]?.id || ''
      })
      onStatus(`${items.length} policy rule(s)`, 'ok')
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onAuthRequired()
      }
      onStatus(err.message || 'Failed to load rules', 'error')
    }
  }, [onAuthRequired, onStatus])

  useEffect(() => {
    if (active) {
      loadRules()
    }
  }, [active, loadRules, refreshToken])

  const counts = useMemo(() => {
    let allow = 0
    let deny = 0
    for (const rule of rules) {
      if (rule.effect === 'deny') deny += 1
      else allow += 1
    }
    return { total: rules.length, allow, deny }
  }, [rules])

  const filtered = useMemo(() => {
    if (!effectFilter) return rules
    return rules.filter((rule) => rule.effect === effectFilter)
  }, [rules, effectFilter])

  const selected = filtered.find((rule) => rule.id === selectedId) || filtered[0] || null

  useEffect(() => {
    if (selected && selected.id !== selectedId) {
      setSelectedId(selected.id)
    }
  }, [selected, selectedId])

  function updateField(key, value) {
    setForm((prev) => ({ ...prev, [key]: value }))
  }

  const preview = useMemo(() => {
    const host = form.host.trim().toLowerCase() || 'host.example'
    const port = form.port || '443'
    return ruleSummary({
      effect: form.effect,
      host,
      port: Number(port) || 443,
      method: form.method || '*',
      path_prefix: form.path_prefix || '/',
    })
  }, [form])

  async function handleCreate(event) {
    event.preventDefault()
    const host = form.host.trim().toLowerCase()
    if (!host) {
      onStatus('Host is required', 'error')
      return
    }
    const port = Number(form.port)
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      onStatus('Port must be between 1 and 65535', 'error')
      return
    }

    setSaving(true)
    try {
      const created = await createRule({
        scope: 'org',
        effect: form.effect,
        host,
        port,
        method: form.method.trim() || '*',
        path_prefix: form.path_prefix.trim() || '/',
      })
      setForm(EMPTY_FORM)
      setComposerOpen(false)
      await loadRules()
      if (created?.id) setSelectedId(created.id)
      onStatus(`Policy created for ${host}:${port}`, 'ok')
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onAuthRequired()
      }
      onStatus(err.message || 'Failed to create rule', 'error')
    } finally {
      setSaving(false)
    }
  }

  async function handleRevoke(ruleId) {
    const confirmed = window.confirm('Revoke this policy? Matching traffic will need approval again.')
    if (!confirmed) return
    try {
      await revokeRule(ruleId)
      await loadRules()
      onStatus('Policy revoked.', 'ok')
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onAuthRequired()
      }
      onStatus(err.message, 'error')
    }
  }

  return (
    <>
      <div className="stat-row">
        <div className="stat-box">
          <div className="stat-label">Policies</div>
          <div className="stat-value">{counts.total}</div>
        </div>
        <div className="stat-box">
          <div className="stat-label">Allow</div>
          <div className="stat-value">{counts.allow}</div>
        </div>
        <div className="stat-box">
          <div className="stat-label">Deny</div>
          <div className="stat-value">{counts.deny}</div>
        </div>
      </div>

      <div className="filter-row">
        <label className="field-label" htmlFor="rules-effect-filter">
          Show
        </label>
        <select
          id="rules-effect-filter"
          value={effectFilter}
          onChange={(e) => setEffectFilter(e.target.value)}
        >
          <option value="">All policies</option>
          <option value="allow">Allow only</option>
          <option value="deny">Deny only</option>
        </select>
        <span className="spacer" />
        <button
          type="button"
          className={composerOpen ? 'ghost' : 'primary'}
          onClick={() => setComposerOpen((open) => !open)}
        >
          {composerOpen ? 'Close composer' : 'New policy'}
        </button>
      </div>

      {composerOpen ? (
        <section className="panel rules-composer">
          <div className="panel-head">New org policy</div>
          <div className="panel-body">
            <form onSubmit={handleCreate}>
              <div className="rules-effect-toggle" role="group" aria-label="Policy effect">
                <button
                  type="button"
                  className={form.effect === 'allow' ? 'active allow' : ''}
                  onClick={() => updateField('effect', 'allow')}
                >
                  Allow
                  <span>Auto-approve matching egress</span>
                </button>
                <button
                  type="button"
                  className={form.effect === 'deny' ? 'active deny' : ''}
                  onClick={() => updateField('effect', 'deny')}
                >
                  Deny
                  <span>Block matching egress</span>
                </button>
              </div>

              <div className="rules-composer-grid">
                <div className="rules-field rules-field-wide">
                  <label className="field-label" htmlFor="rule-host">
                    Destination host
                  </label>
                  <input
                    id="rule-host"
                    type="text"
                    placeholder="api.github.com"
                    value={form.host}
                    onChange={(e) => updateField('host', e.target.value)}
                    required
                    autoFocus
                  />
                </div>
                <div className="rules-field">
                  <label className="field-label" htmlFor="rule-port">
                    Port
                  </label>
                  <input
                    id="rule-port"
                    type="number"
                    min="1"
                    max="65535"
                    value={form.port}
                    onChange={(e) => updateField('port', e.target.value)}
                  />
                </div>
                <div className="rules-field">
                  <label className="field-label" htmlFor="rule-method">
                    Method
                  </label>
                  <select
                    id="rule-method"
                    value={form.method}
                    onChange={(e) => updateField('method', e.target.value)}
                  >
                    <option value="*">Any (*)</option>
                    <option value="GET">GET</option>
                    <option value="POST">POST</option>
                    <option value="PUT">PUT</option>
                    <option value="PATCH">PATCH</option>
                    <option value="DELETE">DELETE</option>
                    <option value="HEAD">HEAD</option>
                  </select>
                </div>
                <div className="rules-field">
                  <label className="field-label" htmlFor="rule-path">
                    Path prefix
                  </label>
                  <input
                    id="rule-path"
                    type="text"
                    placeholder="/"
                    value={form.path_prefix}
                    onChange={(e) => updateField('path_prefix', e.target.value)}
                  />
                </div>
              </div>

              <div className="rules-preview">
                <span className="field-label">Preview</span>
                <p>{preview}</p>
                <p className="muted">
                  Prefer method <span className="mono">*</span> so HTTPS CONNECT tunnels match. Exact
                  CONNECT allow rules are not supported.
                </p>
              </div>

              <div className="rules-composer-actions">
                <button type="button" className="ghost" onClick={() => setComposerOpen(false)}>
                  Cancel
                </button>
                <button type="submit" className="primary" disabled={saving}>
                  {saving ? 'Saving…' : 'Save policy'}
                </button>
              </div>
            </form>
          </div>
        </section>
      ) : null}

      <div className="split-layout">
        <section className="panel">
          <div className="panel-head">Policy registry</div>
          <div className="panel-body panel-flush">
            {filtered.length === 0 ? (
              <div className="empty-state">
                {rules.length === 0
                  ? 'No standing policies yet. Create one or use Inbox → Remember for org.'
                  : 'No policies match this filter.'}
              </div>
            ) : (
              <div className="data-table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Policy</th>
                      <th>Destination</th>
                      <th>Match</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map((rule) => (
                      <tr
                        key={rule.id}
                        className={`clickable ${rule.id === selected?.id ? 'selected' : ''}`}
                        onClick={() => setSelectedId(rule.id)}
                      >
                        <td>
                          <EffectBadge effect={rule.effect} />
                        </td>
                        <td>
                          <div className="mono">
                            {rule.host}:{rule.port}
                          </div>
                        </td>
                        <td>
                          <div className="mono">
                            {rule.method} {rule.path_prefix || '/'}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </section>

        <section className="panel">
          <div className="panel-head">Policy detail</div>
          <div className="panel-body">
            {!selected ? (
              <div className="empty-state">Select a policy to review or revoke it.</div>
            ) : (
              <div className="rule-detail">
                <div className="rule-detail-hero">
                  <EffectBadge effect={selected.effect} />
                  <h2 className="rule-detail-title">
                    {selected.host}:{selected.port}
                  </h2>
                  <p className="rule-detail-copy">{ruleSummary(selected)}</p>
                </div>

                <dl className="audit-facts">
                  <div>
                    <dt>Method</dt>
                    <dd className="mono">{selected.method}</dd>
                  </div>
                  <div>
                    <dt>Path prefix</dt>
                    <dd className="mono">{selected.path_prefix || '/'}</dd>
                  </div>
                  <div>
                    <dt>Scope</dt>
                    <dd>Organization</dd>
                  </div>
                  <div>
                    <dt>Created</dt>
                    <dd>{formatTime(selected.created_at)}</dd>
                  </div>
                </dl>

                <details className="audit-tech">
                  <summary>Technical identifiers</summary>
                  <dl className="audit-facts">
                    <div className="audit-facts-wide">
                      <dt>Rule id</dt>
                      <dd className="mono">{selected.id}</dd>
                    </div>
                    {selected.created_by ? (
                      <div className="audit-facts-wide">
                        <dt>Created by</dt>
                        <dd className="mono">{selected.created_by}</dd>
                      </div>
                    ) : null}
                  </dl>
                </details>

                <div className="detail-actions">
                  <button type="button" className="danger" onClick={() => handleRevoke(selected.id)}>
                    Revoke policy
                  </button>
                </div>
              </div>
            )}
          </div>
        </section>
      </div>
    </>
  )
}
