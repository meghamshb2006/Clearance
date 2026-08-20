import { useCallback, useEffect, useMemo, useState } from 'react'
import { ApiError, listAudit } from '../api/client.js'

function toneForEvent(eventType) {
  switch (eventType) {
    case 'egress_pending':
      return 'pending'
    case 'egress_auto_approved':
    case 'egress_approved_once':
    case 'egress_approved_once_consumed':
    case 'egress_approved_org_rule':
    case 'policy_rule_created':
      return 'approved'
    case 'egress_denied':
    case 'policy_rule_revoked':
      return 'denied'
    default:
      return 'default'
  }
}

function categoryForEvent(eventType) {
  if (String(eventType).startsWith('policy_')) return 'policy'
  if (
    eventType === 'egress_approved_once' ||
    eventType === 'egress_approved_org_rule' ||
    eventType === 'egress_denied'
  ) {
    return 'decision'
  }
  if (String(eventType).startsWith('egress_')) return 'egress'
  return 'other'
}

function formatTime(value) {
  if (!value) return '—'
  return new Date(value).toLocaleString()
}

function metaString(metadata, key) {
  const value = metadata?.[key]
  if (value === null || value === undefined || value === '') return ''
  return String(value)
}

function EventTone({ event }) {
  const label = event.title || event.event_type
  return <span className={`status-tag ${toneForEvent(event.event_type)}`}>{label}</span>
}

function AuditDetail({ event }) {
  if (!event) {
    return <div className="empty-state">Select an event to inspect the compliance record.</div>
  }

  const host = metaString(event.metadata, 'host')
  const method = metaString(event.metadata, 'method')
  const path = metaString(event.metadata, 'path') || metaString(event.metadata, 'path_prefix')
  const port = metaString(event.metadata, 'port')
  const effect = metaString(event.metadata, 'effect')
  const feedback = metaString(event.metadata, 'feedback') || metaString(event.metadata, 'error_message')
  const decision = metaString(event.metadata, 'decision')

  return (
    <div className="audit-detail">
      <div className="audit-detail-hero">
        <EventTone event={event} />
        <h2 className="audit-detail-title">{event.title || event.event_type}</h2>
        <p className="audit-detail-copy">{event.description}</p>
      </div>

      <div className="audit-section">
        <div className="panel-subhead">What happened</div>
        <dl className="audit-facts">
          <div>
            <dt>When</dt>
            <dd>{formatTime(event.created_at)}</dd>
          </div>
          <div>
            <dt>Actor</dt>
            <dd>{event.actor_name || (event.actor_id ? 'Operator' : 'System')}</dd>
          </div>
          <div>
            <dt>Category</dt>
            <dd>{categoryForEvent(event.event_type)}</dd>
          </div>
          {decision ? (
            <div>
              <dt>Decision</dt>
              <dd>{decision}</dd>
            </div>
          ) : null}
          {effect ? (
            <div>
              <dt>Rule effect</dt>
              <dd>{effect}</dd>
            </div>
          ) : null}
          {feedback ? (
            <div className="audit-facts-wide">
              <dt>Reason</dt>
              <dd>{feedback}</dd>
            </div>
          ) : null}
        </dl>
      </div>

      {(host || event.subject) && (
        <div className="audit-section">
          <div className="panel-subhead">Destination</div>
          <dl className="audit-facts">
            {event.subject ? (
              <div className="audit-facts-wide">
                <dt>Subject</dt>
                <dd className="mono">{event.subject}</dd>
              </div>
            ) : null}
            {method ? (
              <div>
                <dt>Method</dt>
                <dd className="mono">{method}</dd>
              </div>
            ) : null}
            {host ? (
              <div>
                <dt>Host</dt>
                <dd className="mono">
                  {host}
                  {port ? `:${port}` : ''}
                </dd>
              </div>
            ) : null}
            {path ? (
              <div>
                <dt>Path</dt>
                <dd className="mono">{path}</dd>
              </div>
            ) : null}
          </dl>
        </div>
      )}

      <details className="audit-tech">
        <summary>Technical identifiers</summary>
        <dl className="audit-facts">
          <div className="audit-facts-wide">
            <dt>Event id</dt>
            <dd className="mono">{event.id}</dd>
          </div>
          <div className="audit-facts-wide">
            <dt>Event type</dt>
            <dd className="mono">{event.event_type}</dd>
          </div>
          {event.egress_request_id ? (
            <div className="audit-facts-wide">
              <dt>Request id</dt>
              <dd className="mono">{event.egress_request_id}</dd>
            </div>
          ) : null}
          {event.actor_id ? (
            <div className="audit-facts-wide">
              <dt>Actor id</dt>
              <dd className="mono">{event.actor_id}</dd>
            </div>
          ) : null}
          {metaString(event.metadata, 'rule_id') ? (
            <div className="audit-facts-wide">
              <dt>Rule id</dt>
              <dd className="mono">{metaString(event.metadata, 'rule_id')}</dd>
            </div>
          ) : null}
        </dl>
      </details>
    </div>
  )
}

export function AuditTab({ onStatus, onAuthRequired, refreshToken, active }) {
  const [events, setEvents] = useState([])
  const [selectedId, setSelectedId] = useState('')
  const [typeFilter, setTypeFilter] = useState('')
  const [categoryFilter, setCategoryFilter] = useState('')

  const loadAudit = useCallback(async () => {
    try {
      const items = await listAudit()
      setEvents(items)
      setSelectedId((prev) => {
        if (prev && items.some((item) => item.id === prev)) return prev
        return items[0]?.id || ''
      })
      onStatus(`${items.length} audit event(s)`, 'ok')
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onAuthRequired()
      }
      onStatus(err.message || 'Failed to load audit log', 'error')
    }
  }, [onAuthRequired, onStatus])

  useEffect(() => {
    if (active) {
      loadAudit()
    }
  }, [active, loadAudit, refreshToken])

  const counts = useMemo(() => {
    const next = { total: events.length, approved: 0, denied: 0, pending: 0, policy: 0 }
    for (const event of events) {
      const tone = toneForEvent(event.event_type)
      if (tone === 'approved') next.approved += 1
      else if (tone === 'denied') next.denied += 1
      else if (tone === 'pending') next.pending += 1
      if (categoryForEvent(event.event_type) === 'policy') next.policy += 1
    }
    return next
  }, [events])

  const typeOptions = useMemo(() => {
    const map = new Map()
    for (const event of events) {
      if (!map.has(event.event_type)) {
        map.set(event.event_type, event.title || event.event_type)
      }
    }
    return [...map.entries()].sort((a, b) => a[1].localeCompare(b[1]))
  }, [events])

  const filtered = useMemo(() => {
    return events.filter((event) => {
      if (typeFilter && event.event_type !== typeFilter) return false
      if (categoryFilter && categoryForEvent(event.event_type) !== categoryFilter) return false
      return true
    })
  }, [events, typeFilter, categoryFilter])

  const selected = filtered.find((event) => event.id === selectedId) || filtered[0] || null

  useEffect(() => {
    if (selected && selected.id !== selectedId) {
      setSelectedId(selected.id)
    }
  }, [selected, selectedId])

  return (
    <>
      <div className="stat-row">
        <div className="stat-box">
          <div className="stat-label">Events</div>
          <div className="stat-value">{counts.total}</div>
        </div>
        <div className="stat-box">
          <div className="stat-label">Allowed</div>
          <div className="stat-value">{counts.approved}</div>
        </div>
        <div className="stat-box">
          <div className="stat-label">Denied</div>
          <div className="stat-value">{counts.denied}</div>
        </div>
        <div className="stat-box">
          <div className="stat-label">Pending</div>
          <div className="stat-value">{counts.pending}</div>
        </div>
        <div className="stat-box">
          <div className="stat-label">Policy changes</div>
          <div className="stat-value">{counts.policy}</div>
        </div>
      </div>

      <div className="filter-row">
        <label className="field-label" htmlFor="audit-category">
          Category
        </label>
        <select
          id="audit-category"
          value={categoryFilter}
          onChange={(event) => setCategoryFilter(event.target.value)}
        >
          <option value="">All</option>
          <option value="egress">Egress</option>
          <option value="decision">Decisions</option>
          <option value="policy">Policy</option>
          <option value="other">Other</option>
        </select>
        <label className="field-label" htmlFor="audit-type">
          Event
        </label>
        <select id="audit-type" value={typeFilter} onChange={(event) => setTypeFilter(event.target.value)}>
          <option value="">All types</option>
          {typeOptions.map(([type, title]) => (
            <option key={type} value={type}>
              {title}
            </option>
          ))}
        </select>
        <button
          type="button"
          className="ghost"
          onClick={() => {
            setCategoryFilter('')
            setTypeFilter('')
          }}
        >
          Reset
        </button>
        <span className="spacer" />
        <span className="muted">
          Showing {filtered.length} of latest {events.length}
        </span>
      </div>

      <div className="split-layout">
        <section className="panel">
          <div className="panel-head">Audit trail</div>
          <div className="panel-body panel-flush">
            {filtered.length === 0 ? (
              <div className="empty-state">No events match the current filters.</div>
            ) : (
              <div className="data-table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>When</th>
                      <th>Action</th>
                      <th>Subject</th>
                      <th>Actor</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map((event) => (
                      <tr
                        key={event.id}
                        className={`clickable ${event.id === selected?.id ? 'selected' : ''}`}
                        onClick={() => setSelectedId(event.id)}
                      >
                        <td className="mono nowrap">{formatTime(event.created_at)}</td>
                        <td>
                          <EventTone event={event} />
                          <div className="muted audit-row-desc">{event.description}</div>
                        </td>
                        <td className="mono">{event.subject || '—'}</td>
                        <td>{event.actor_name || (event.actor_id ? 'Operator' : 'System')}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </section>

        <section className="panel">
          <div className="panel-head">Event record</div>
          <div className="panel-body">
            <AuditDetail event={selected} />
          </div>
        </section>
      </div>
    </>
  )
}
