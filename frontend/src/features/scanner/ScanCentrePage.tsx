import { AlertTriangle, CheckCircle2, FileCode2, LoaderCircle, Play, Radio, RotateCw, ScanLine, Shield } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Button, DataTable, EmptyState, ErrorState, LoadingBlock, Select } from '../../components/ui/Primitives'
import { useApi } from '../../hooks/useApi'
import { api, apiUrl } from '../../services/api'
import type { Scan, Service } from '../../types/api'
import { useApp } from '../shell/AppContext'
import { timeAgo } from '../services/ServiceRegistryPage'

type Progress = {
  scan_id?: number
  batch_id?: number
  service_id?: number
  current_service?: string | null
  current_file?: string | null
  packages_inspected?: number
  vulnerabilities_discovered?: number
  progress_percent?: number
  elapsed_seconds?: number
  status?: string
  error?: string | null
  completed_services?: number
  total_services?: number
  scans?: { scan_id: number; service_id: number; packages_inspected: number; vulnerabilities_discovered: number; status: string }[]
}

export function ScanCentrePage() {
  const [params, setParams] = useSearchParams()
  const requestedBatch = Number(params.get('batch')) || null
  const requestedScan = Number(params.get('scan')) || null
  const [scope, setScope] = useState(requestedScan ? 'one' : 'all')
  const [serviceId, setServiceId] = useState('')
  const [scanId, setScanId] = useState<number | null>(requestedScan)
  const [batchId, setBatchId] = useState<number | null>(requestedBatch)
  const [progress, setProgress] = useState<Progress | null>(null)
  const [starting, setStarting] = useState(false)
  const [streamState, setStreamState] = useState<'connecting' | 'live' | 'polling' | 'idle'>('idle')
  const { notify } = useApp()
  const serviceResult = useApi(() => api.services(new URLSearchParams({ limit: '100' })), [])
  const scansResult = useApi(() => api.scans(new URLSearchParams({ limit: '100' })), [scanId, batchId])
  const services = serviceResult.data?.items || []
  const scans = scansResult.data?.items || []
  const activeScan = scans.find((scan) => scan.id === scanId)
  const percent = Math.max(0, Math.min(100, progress?.progress_percent ?? activeScan?.progress_percent ?? 0))

  useEffect(() => {
    if (!scanId && !batchId) return
    let source: EventSource | null = null
    let polling = false
    const eventUrl = batchId ? `${apiUrl}/api/scan-batches/${batchId}/events` : `${apiUrl}/api/scans/${scanId}/events`
    setStreamState('connecting')
    try {
      source = new EventSource(eventUrl)
      source.onopen = () => { setStreamState('live'); polling = false }
      source.addEventListener('progress', (event) => {
        try { setProgress(JSON.parse((event as MessageEvent).data) as Progress) } catch { /* ignore malformed transient event */ }
      })
      source.onerror = () => { setStreamState('polling'); source?.close(); source = null; polling = true }
    } catch { polling = true; setStreamState('polling') }
    let disposed = false
    const poll = async () => {
      if (disposed || !polling) return
      try {
        const value = batchId ? await api.batchProgress(batchId) : await api.scanProgress(scanId!)
        setProgress(value as Progress)
        if (['completed', 'failed'].includes(String(value.status))) {
          polling = false
          scansResult.reload()
        } else window.setTimeout(poll, 1300)
      } catch { if (!disposed) window.setTimeout(poll, 2500) }
    }
    const fallbackTimer = window.setTimeout(() => { if (polling) void poll() }, 0)
    return () => { disposed = true; window.clearTimeout(fallbackTimer); source?.close() }
  }, [scanId, batchId])

  useEffect(() => {
    if (progress?.status && ['completed', 'failed'].includes(progress.status)) scansResult.reload()
  }, [progress?.status])

  const start = async () => {
    if (scope === 'one' && !serviceId) { notify('Choose a service before starting a single-service scan.', 'info'); return }
    setStarting(true)
    setProgress(null)
    try {
      if (scope === 'all') {
        const response = await api.startScan()
        if ('batch_id' in response) { setBatchId(response.batch_id); setScanId(response.scan_ids[0] || null); setParams({ batch: String(response.batch_id) }) }
      } else {
        const response = await api.startScan(Number(serviceId))
        if ('scan_id' in response) { setScanId(response.scan_id); setBatchId(null); setParams({ scan: String(response.scan_id) }) }
      }
      setStreamState('connecting')
      notify(scope === 'all' ? 'Full inventory scan queued.' : 'Service scan queued.')
      scansResult.reload()
    } catch (reason) { notify(reason instanceof Error ? reason.message : 'Scan could not start', 'error') }
    finally { setStarting(false) }
  }

  const columns = [
    { key: 'service', label: 'SERVICE', render: (scan: Scan) => <span className="font-mono">{serviceName(services, scan.service_id)}</span> },
    { key: 'started', label: 'STARTED', render: (scan: Scan) => <span>{timeAgo(scan.started_at)}</span> },
    { key: 'status', label: 'STATUS', render: (scan: Scan) => <span className={`scan-history-status scan-${scan.status}`}><i />{scan.status.toUpperCase()}</span> },
    { key: 'packages', label: 'PACKAGES', render: (scan: Scan) => <span className="font-mono">{scan.package_count}</span> },
    { key: 'findings', label: 'MATCHES', render: (scan: Scan) => <span className="font-mono">{scan.vulnerable_count}</span> },
    { key: 'duration', label: 'DURATION', render: (scan: Scan) => <span className="font-mono">{scan.duration_seconds?.toFixed(2) ?? '—'}s</span> },
  ]

  return <div className="page-pad scan-centre-page">
    <div className="page-title-row"><div><span className="eyebrow">OPERATIONS / SCAN COMMAND</span><h1>Scan command centre</h1><p className="page-intro">Inspect the registered software estate from its original manifests and lockfiles.</p></div><span className={`stream-indicator stream-${streamState}`}><Radio size={14} /> {streamState === 'live' ? 'EVENT STREAM LIVE' : streamState === 'polling' ? 'POLLING FALLBACK' : streamState === 'connecting' ? 'CONNECTING' : 'READY'}</span></div>

    <section className="scan-control-panel"><div className="scan-control-copy"><span className="eyebrow">SCAN SCOPE</span><h2>Start a real dependency scan</h2><p>Package counts, findings and timings are produced by the backend scanner as it reads service manifests.</p></div><div className="scan-control-form"><Select value={scope} onChange={(event) => setScope(event.target.value)}><option value="all">All registered services</option><option value="one">Single service</option></Select>{scope === 'one' && <Select value={serviceId} onChange={(event) => setServiceId(event.target.value)}><option value="">Choose service...</option>{services.map((service) => <option key={service.id} value={service.id}>{service.name}</option>)}</Select>}<Button onClick={start} disabled={starting}><Play size={14} /> {starting ? 'QUEUEING...' : scope === 'all' ? 'SCAN ALL SERVICES' : 'SCAN SERVICE'}</Button></div></section>

    {(scanId || batchId) && <section className="scan-live-panel"><div className="scan-live-heading"><div><span className="eyebrow">LIVE EXECUTION / {batchId ? `BATCH ${String(batchId).padStart(4, '0')}` : `SCAN ${String(scanId).padStart(4, '0')}`}</span><h2>{progress?.current_service || serviceName(services, progress?.service_id || activeScan?.service_id || 0)}</h2></div><div className={`scan-live-state ${progress?.status === 'failed' ? 'state-failed' : progress?.status === 'completed' ? 'state-complete' : ''}`}>{progress?.status === 'completed' ? <CheckCircle2 size={16} /> : progress?.status === 'failed' ? <AlertTriangle size={16} /> : <LoaderCircle size={16} className="spin" />}{(progress?.status || activeScan?.status || 'queued').toUpperCase()}</div></div>
      <div className="scan-progress-track"><div style={{ width: `${percent}%` }} /></div><div className="scan-progress-caption"><span>{percent.toFixed(0)}% COMPLETE</span><span>{progress?.elapsed_seconds?.toFixed(1) || activeScan?.duration_seconds?.toFixed(1) || '0.0'}s ELAPSED</span></div>
      {batchId && progress?.total_services && <div className="batch-progress-copy">SERVICE {Math.min((progress.completed_services || 0) + (progress.status === 'running' ? 1 : 0), progress.total_services)} OF {progress.total_services}</div>}
      <div className="scan-live-stats"><LiveStat icon={<FileCode2 size={15} />} label="FILE BEING PROCESSED" value={progress?.current_file || activeScan?.current_file || 'Waiting for scanner'} mono /><LiveStat icon={<ScanLine size={15} />} label="PACKAGES INSPECTED" value={String(progress?.packages_inspected ?? activeScan?.packages_inspected ?? 0)} /><LiveStat icon={<Shield size={15} />} label="VULNERABILITIES FOUND" value={String(progress?.vulnerabilities_discovered ?? activeScan?.vulnerabilities_discovered ?? 0)} accent /></div>
      {progress?.status === 'failed' && <div className="scan-error"><AlertTriangle size={15} /> {progress.error || activeScan?.error || 'The scan failed.'}</div>}
      {batchId && progress?.scans && <div className="batch-scan-list">{progress.scans.map((item) => <span key={item.scan_id}><i className={item.status === 'completed' ? 'done' : 'failed'} />{serviceName(services, item.service_id)}<b>{item.packages_inspected}</b></span>)}</div>}
    </section>}

    <section className="scan-history-section"><div className="section-heading compact-heading"><div><span className="eyebrow">AUDIT TRAIL / PERSISTED SESSIONS</span><h2>Scan history</h2></div><Button variant="quiet" onClick={() => scansResult.reload()}><RotateCw size={14} /> REFRESH</Button></div>{scansResult.loading ? <LoadingBlock rows={5} /> : scansResult.error ? <ErrorState message={scansResult.error} retry={scansResult.reload} /> : scans.length ? <div className="registry-table-panel"><DataTable columns={columns} rows={scans} rowKey={(scan) => scan.id} /></div> : <EmptyState title="No scan history" detail="Completed scanner sessions will be recorded here." />}</section>
  </div>
}

function LiveStat({ icon, label, value, mono = false, accent = false }: { icon: React.ReactNode; label: string; value: string; mono?: boolean; accent?: boolean }) {
  return <div className="live-stat"><span>{icon}{label}</span><b className={`${mono ? 'font-mono' : ''} ${accent ? 'text-signal' : ''}`}>{value}</b></div>
}
function serviceName(services: Service[], id: number) { return services.find((service) => service.id === id)?.name || `service/${id}` }
