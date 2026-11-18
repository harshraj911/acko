import { ArrowLeft, ArrowRight, Pencil, Play, Shield, Wifi, WifiOff } from 'lucide-react'
import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { Badge, Button, DataTable, EmptyState, ErrorState, Field, Input, LoadingBlock, Modal, PriorityBadge, Select, SeverityBadge, StatusBadge } from '../../components/ui/Primitives'
import { useApi } from '../../hooks/useApi'
import { api } from '../../services/api'
import type { Dependency, Service } from '../../types/api'
import { useApp } from '../shell/AppContext'
import { maxPriority, timeAgo } from './ServiceRegistryPage'

export function ServiceDetailPage() {
  const { serviceId } = useParams()
  const id = Number(serviceId)
  const navigate = useNavigate()
  const { notify } = useApp()
  const { data: service, error, loading, reload } = useApi(() => api.service(id), [id])
  const { data: dependencies, loading: dependenciesLoading, reload: reloadDependencies } = useApi(() => api.dependencies(id), [id])
  const { data: findingPage, reload: reloadFindings } = useApi(() => api.serviceFindings(id), [id])
  const { data: scans } = useApi(() => api.scans(new URLSearchParams({ service_id: String(id), limit: '20' })), [id])
  const [editOpen, setEditOpen] = useState(false)
  const [scanBusy, setScanBusy] = useState(false)

  const scan = async () => {
    setScanBusy(true)
    try {
      const result = await api.startScan(id)
      if ('scan_id' in result) navigate(`/scan?scan=${result.scan_id}`)
    } catch (reason) { notify(reason instanceof Error ? reason.message : 'Scan could not start', 'error') }
    finally { setScanBusy(false) }
  }

  const findings = findingPage?.items || []
  const highest = maxPriority(findings.filter((finding) => finding.status !== 'Resolved' && finding.status !== 'resolved'))
  const dependenciesData = dependencies?.items || []
  const columns = [
    { key: 'package', label: 'PACKAGE / CHAIN', render: (item: Dependency) => <div className="dependency-name-cell"><b className="font-mono">{item.name}</b><small>{item.chain.length > 1 ? item.chain.join('  /  ') : item.direct ? 'Declared directly in manifest' : 'Parent relationship unavailable'}</small></div> },
    { key: 'version', label: 'INSTALLED', render: (item: Dependency) => item.resolved ? <span className="font-mono version-value">{item.version}</span> : <span className="unresolved-version"><span>UNRESOLVED</span><small>{item.specifier}</small></span> },
    { key: 'scope', label: 'SCOPE', render: (item: Dependency) => <div className="scope-badges"><Badge tone={item.direct ? 'direct' : 'transitive'}>{item.direct ? 'DIRECT' : 'TRANSITIVE'}</Badge>{item.dev_only && <Badge tone="dev">DEV ONLY</Badge>}</div> },
    { key: 'manifest', label: 'SOURCE', render: (item: Dependency) => <span className="font-mono manifest-label">{item.manifest_file}</span> },
  ]

  if (loading) return <div className="page-pad"><LoadingBlock rows={7} /></div>
  if (error || !service) return <div className="page-pad"><ErrorState message={error || 'Service not found'} retry={reload} /></div>

  return <div className="page-pad service-detail-page">
    <Link to="/services" className="back-link"><ArrowLeft size={14} /> SERVICE REGISTRY</Link>
    <div className="detail-hero"><div className="detail-hero-main"><span className="eyebrow">SERVICE / {service.id.toString().padStart(3, '0')} · {service.ecosystem.toUpperCase()}</span><h1>{service.name}</h1><p>{service.description}</p><div className="detail-pills"><Badge tone={`tier-${service.tier}`}>{`TIER 0${service.tier}`}</Badge><Badge tone={service.internet_facing ? 'high' : 'neutral'}>{service.internet_facing ? <><Wifi size={12} /> INTERNET-FACING</> : <><WifiOff size={12} /> INTERNAL</>}</Badge><span className="detail-owner">OWNER / <b>{service.owner}</b></span></div></div><div className="detail-risk"><span className="eyebrow">CURRENT RISK</span><PriorityBadge priority={highest} /><div className="detail-risk-count">{findings.filter((finding) => !['resolved', 'Resolved'].includes(finding.status)).length.toString().padStart(2, '0')}<small>ACTIVE FINDINGS</small></div><div className="detail-actions"><Button variant="outline" onClick={() => setEditOpen(true)}><Pencil size={14} /> EDIT METADATA</Button><Button onClick={scan} disabled={scanBusy}><Play size={14} /> {scanBusy ? 'QUEUED' : 'SCAN SERVICE'}</Button></div></div></div>

    <div className="service-snapshot"><div><span>DEPENDENCIES</span><b>{dependenciesLoading ? '—' : dependencies?.total ?? 0}</b></div><div><span>VULNERABILITIES</span><b className="text-signal">{findings.filter((finding) => !['resolved', 'Resolved'].includes(finding.status)).length}</b></div><div><span>LAST SCAN</span><b className="snapshot-date">{scans?.items.find((scan) => scan.status === 'completed')?.completed_at ? timeAgo(scans.items.find((scan) => scan.status === 'completed')!.completed_at!) : 'NEVER'}</b></div><div><span>SCAN COVERAGE</span><b>{dependenciesData.length ? `${dependenciesData.filter((dep) => dep.resolved).length}/${dependenciesData.length}` : '—'}</b></div></div>

    <section className="detail-section"><div className="section-heading compact-heading"><div><span className="eyebrow">SNAPSHOT / LATEST COMPLETED SCAN</span><h2>Dependency inventory</h2></div><span className="section-aside">DIRECT + TRANSITIVE · DEV SCOPE VISIBLE</span></div>{dependenciesLoading ? <LoadingBlock rows={5} /> : dependenciesData.length ? <div className="registry-table-panel"><DataTable columns={columns} rows={dependenciesData} rowKey={(item) => item.package_path} empty="No dependency records." /></div> : <EmptyState title="No scan snapshot" detail="Run a service scan to populate its dependency inventory." action={<Button onClick={scan}><Play size={14} /> SCAN SERVICE</Button>} />}</section>

    <section className="detail-section"><div className="section-heading compact-heading"><div><span className="eyebrow">MATCHED EXPOSURES / {findings.length}</span><h2>Findings</h2></div><Link className="text-link" to={`/findings?service_id=${id}`}>OPEN FINDINGS MANAGEMENT <ArrowRight size={13} /></Link></div>{findings.length ? <div className="finding-cards">{findings.map((finding) => <div className="finding-row-card" key={finding.id}><span className="finding-row-mark"><Shield size={16} /></span><span className="finding-row-main"><b>{finding.package_name} <span className="font-mono">/ {finding.advisory_id}</span></b><small>{finding.summary} · <span className="font-mono">{finding.installed_version}</span>{finding.dev_only ? ' · DEV ONLY' : ''}</small></span><SeverityBadge severity={finding.source_severity} /><PriorityBadge priority={finding.priority} /><StatusBadge status={finding.status} /></div>)}</div> : <EmptyState title="No findings for this service" detail="Vulnerability matches from completed scans appear here." />}</section>

    <EditServiceModal open={editOpen} service={service} onClose={() => setEditOpen(false)} onSaved={() => { setEditOpen(false); reload(); reloadDependencies(); reloadFindings(); notify('Service metadata updated.') }} />
  </div>
}

function EditServiceModal({ open, service, onClose, onSaved }: { open: boolean; service: Service; onClose: () => void; onSaved: () => void }) {
  const [owner, setOwner] = useState(service.owner)
  const [description, setDescription] = useState(service.description)
  const [tier, setTier] = useState(String(service.tier))
  const [internet, setInternet] = useState(service.internet_facing)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const save = async (event: React.FormEvent) => {
    event.preventDefault(); setBusy(true); setMessage('')
    try { await api.updateService(service.id, { owner, description, tier: Number(tier), internet_facing: internet }); onSaved() }
    catch (reason) { setMessage(reason instanceof Error ? reason.message : 'Could not save metadata') }
    finally { setBusy(false) }
  }
  return <Modal open={open} onClose={onClose} title={`Edit ${service.name}`} eyebrow="SERVICE METADATA"><form className="service-form" onSubmit={save}><Field label="Owning team"><Input value={owner} onChange={(event) => setOwner(event.target.value)} required /></Field><Field label="Description"><Input value={description} onChange={(event) => setDescription(event.target.value)} /></Field><Field label="Business criticality"><Select value={tier} onChange={(event) => setTier(event.target.value)}><option value="1">Tier 1 / Critical</option><option value="2">Tier 2 / High</option><option value="3">Tier 3 / Standard</option></Select></Field><label className="check-field"><input type="checkbox" checked={internet} onChange={(event) => setInternet(event.target.checked)} /> Internet-facing</label>{message && <p className="form-error">{message}</p>}<div className="modal-actions"><Button variant="quiet" type="button" onClick={onClose}>Cancel</Button><Button disabled={busy}>{busy ? 'SAVING...' : 'SAVE CHANGES'}</Button></div></form></Modal>
}
