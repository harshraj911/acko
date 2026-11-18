import { ArrowDownUp, ArrowRight, Globe2, Plus, Search, ServerCog, Wifi, WifiOff } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Badge, Button, DataTable, EmptyState, ErrorState, Field, Input, LoadingBlock, Modal, Select } from '../../components/ui/Primitives'
import { useApi } from '../../hooks/useApi'
import { api } from '../../services/api'
import type { Finding, Service } from '../../types/api'
import { useApp } from '../shell/AppContext'

type RegistryRow = Service & { dependency_count: number | null; vulnerable_count: number; last_scanned: string | null; risk: string }
const TIER_LABEL: Record<number, string> = { 1: 'TIER 01 / CRITICAL', 2: 'TIER 02 / HIGH', 3: 'TIER 03 / STANDARD' }

export function ServiceRegistryPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [search, setSearch] = useState(searchParams.get('search') || '')
  const [ecosystem, setEcosystem] = useState('all')
  const [risk, setRisk] = useState('all')
  const [registerOpen, setRegisterOpen] = useState(false)
  const [sort, setSort] = useState('name')
  const { notify } = useApp()
  const params = new URLSearchParams({ limit: '100', sort })
  if (search) params.set('search', search)
  if (ecosystem !== 'all') params.set('ecosystem', ecosystem)
  if (risk !== 'all') params.set('risk', risk)
  const { data, error, loading, reload } = useApi(() => api.services(params), [search, ecosystem, risk, sort])
  const { data: findingsPage } = useApi(() => api.findings(new URLSearchParams({ limit: '500' })), [])
  const { data: scansPage } = useApi(() => api.scans(new URLSearchParams({ limit: '500' })), [])

  useEffect(() => {
    const incoming = searchParams.get('search')
    if (incoming !== null && incoming !== search) setSearch(incoming)
    // Apply navigated search once on route entry.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams])

  const rows = useMemo(() => {
    const findings = findingsPage?.items || []
    const scans = scansPage?.items || []
    return (data?.items || []).map((service) => {
      const serviceFindings = findings.filter((finding) => finding.service_id === service.id && finding.status !== 'resolved' && !finding.withdrawn)
      const latest = scans.find((scan) => scan.service_id === service.id && scan.status === 'completed')
      const dependencies = latest?.package_count ?? null
      return {
        ...service,
        dependency_count: dependencies,
        vulnerable_count: serviceFindings.length,
        last_scanned: latest?.completed_at || null,
        risk: maxPriority(serviceFindings),
      } satisfies RegistryRow
    })
  }, [data, findingsPage, scansPage])

  const submitSearch = (value: string) => {
    setSearch(value)
    const next = new URLSearchParams(searchParams)
    value ? next.set('search', value) : next.delete('search')
    setSearchParams(next, { replace: true })
  }

  const register = async (payload: Partial<Service>) => {
    try {
      await api.createService(payload)
      notify(`Service ${payload.name} registered.`)
      setRegisterOpen(false)
      reload()
    } catch (reason) {
      notify(reason instanceof Error ? reason.message : 'Service registration failed', 'error')
    }
  }

  const columns = [
    { key: 'name', label: 'SERVICE / OWNER', render: (row: RegistryRow) => <Link to={`/services/${row.id}`} className="service-name-cell"><span className="service-glyph"><ServerCog size={17} /></span><span><b>{row.name}</b><small>{row.owner} · {row.description}</small></span></Link> },
    { key: 'ecosystem', label: 'ECOSYSTEM', render: (row: RegistryRow) => <Badge tone={row.ecosystem.toLowerCase()} mono>{row.ecosystem === 'PyPI' ? 'PYTHON' : row.ecosystem.toUpperCase()}</Badge> },
    { key: 'tier', label: 'CRITICALITY', render: (row: RegistryRow) => <span className={`tier-value tier-${row.tier}`}>{TIER_LABEL[row.tier] || `TIER ${row.tier}`}</span> },
    { key: 'internet', label: 'EXPOSURE', render: (row: RegistryRow) => <span className={`exposure ${row.internet_facing ? 'exposed' : ''}`}>{row.internet_facing ? <Wifi size={14} /> : <WifiOff size={14} />}{row.internet_facing ? 'INTERNET' : 'INTERNAL'}</span> },
    { key: 'dependencies', label: 'PACKAGES', render: (row: RegistryRow) => <span className="numeric-cell">{row.dependency_count === null ? <span className="unresolved-count">UNSCANNED</span> : row.dependency_count.toString().padStart(2, '0')}</span> },
    { key: 'vulnerabilities', label: 'FINDINGS', render: (row: RegistryRow) => <span className={`finding-count ${row.vulnerable_count ? 'finding-count-hot' : ''}`}>{row.vulnerable_count.toString().padStart(2, '0')}</span> },
    { key: 'risk', label: 'RISK', render: (row: RegistryRow) => <span className={`risk-level risk-${row.risk.toLowerCase()}`}><i />{row.risk.toUpperCase()}</span> },
    { key: 'scanned', label: 'LAST SCAN', render: (row: RegistryRow) => <span className="last-scan-cell">{row.last_scanned ? timeAgo(row.last_scanned) : 'NEVER'}</span> },
    { key: 'open', label: '', className: 'action-col', render: (row: RegistryRow) => <Link className="table-arrow" to={`/services/${row.id}`} aria-label={`View ${row.name}`}><ArrowRight size={16} /></Link> },
  ]

  return <div className="page-pad registry-page">
    <div className="page-title-row"><div><span className="eyebrow">INVENTORY / 08 REGISTERED</span><h1>Service registry</h1><p className="page-intro">A living index of software systems, ownership, exposure and operational risk.</p></div><Button onClick={() => setRegisterOpen(true)}><Plus size={15} /> REGISTER SERVICE</Button></div>
    <div className="registry-toolbar"><label className="registry-search"><Search size={16} /><Input placeholder="Search services, owners, descriptions..." value={search} onChange={(event) => submitSearch(event.target.value)} /></label><Select value={ecosystem} onChange={(event) => setEcosystem(event.target.value)}><option value="all">All ecosystems</option><option value="npm">npm</option><option value="PyPI">Python / PyPI</option></Select><Select value={risk} onChange={(event) => setRisk(event.target.value)}><option value="all">All risk levels</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>None</option></Select><Button variant="outline" onClick={() => setSort((value) => value === 'name' ? 'tier' : 'name')}><ArrowDownUp size={14} /> SORT: {sort.toUpperCase()}</Button><span className="registry-total">{data?.total ?? '—'} SERVICES</span></div>
    <div className="registry-table-panel">{loading ? <LoadingBlock rows={8} /> : error ? <ErrorState message={error} retry={reload} /> : rows.length ? <DataTable columns={columns} rows={rows} rowKey={(row) => row.id} /> : <EmptyState title="No services match" detail="Try a broader search or clear your filters." action={<Button variant="outline" onClick={() => { setSearch(''); setEcosystem('all'); setRisk('all') }}>CLEAR FILTERS</Button>} />}</div>
    <div className="registry-foot"><span><Globe2 size={13} /> Inventory metadata is sourced from registered service descriptors.</span><span>READ-ONLY SOURCE / LOCAL DATABASE MIRROR</span></div>
    <RegisterServiceModal open={registerOpen} onClose={() => setRegisterOpen(false)} onSubmit={register} />
  </div>
}

function RegisterServiceModal({ open, onClose, onSubmit }: { open: boolean; onClose: () => void; onSubmit: (data: Partial<Service>) => void }) {
  const [name, setName] = useState('')
  const [owner, setOwner] = useState('')
  const [description, setDescription] = useState('')
  const [tier, setTier] = useState('3')
  const [ecosystem, setEcosystem] = useState('npm')
  const [internet, setInternet] = useState(false)
  const [rootPath, setRootPath] = useState('')
  return <Modal open={open} onClose={onClose} title="Register a service" eyebrow="SERVICE INVENTORY">
    <form className="service-form" onSubmit={(event) => { event.preventDefault(); onSubmit({ name, owner, description, tier: Number(tier), ecosystem, internet_facing: internet, root_path: rootPath || null }) }}>
      <Field label="Service name"><Input required value={name} onChange={(event) => setName(event.target.value)} placeholder="policy-api" /></Field>
      <div className="form-split"><Field label="Owning team"><Input required value={owner} onChange={(event) => setOwner(event.target.value)} placeholder="Platform" /></Field><Field label="Criticality"><Select value={tier} onChange={(event) => setTier(event.target.value)}><option value="1">Tier 1 / Critical</option><option value="2">Tier 2 / High</option><option value="3">Tier 3 / Standard</option></Select></Field></div>
      <div className="form-split"><Field label="Ecosystem"><Select value={ecosystem} onChange={(event) => setEcosystem(event.target.value)}><option value="npm">npm</option><option value="PyPI">Python / PyPI</option></Select></Field><Field label="Manifest root"><Input value={rootPath} onChange={(event) => setRootPath(event.target.value)} placeholder="Absolute path to service files" /></Field></div>
      <Field label="Description"><Input value={description} onChange={(event) => setDescription(event.target.value)} placeholder="What does this service do?" /></Field>
      <label className="check-field"><input type="checkbox" checked={internet} onChange={(event) => setInternet(event.target.checked)} /><span>Internet-facing service</span></label>
      <div className="modal-actions"><Button variant="quiet" type="button" onClick={onClose}>Cancel</Button><Button type="submit">REGISTER SERVICE <ArrowRight size={14} /></Button></div>
    </form>
  </Modal>
}

export function maxPriority(findings: Finding[]) {
  const order = ['None', 'Low', 'Medium', 'High', 'Critical']
  return findings.reduce((highest, finding) => order.indexOf(finding.priority) > order.indexOf(highest) ? finding.priority : highest, 'None')
}

export function timeAgo(value: string) {
  const minutes = Math.floor((Date.now() - new Date(value).getTime()) / 60000)
  if (minutes < 1) return 'just now'
  if (minutes < 60) return `${minutes}m ago`
  if (minutes < 1440) return `${Math.floor(minutes / 60)}h ago`
  return `${Math.floor(minutes / 1440)}d ago`
}
