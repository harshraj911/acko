import { AnimatePresence, motion } from 'framer-motion'
import { AlertTriangle, Check, ChevronDown, LoaderCircle, X } from 'lucide-react'
import { useEffect, useState, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes } from 'react'

export function Button({ className = '', variant = 'solid', children, ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'solid' | 'outline' | 'quiet' | 'danger' }) {
  return <button className={`button button-${variant} ${className}`} {...props}>{children}</button>
}

export function Badge({ children, tone = 'neutral', mono = false }: { children: ReactNode; tone?: string; mono?: boolean }) {
  return <span className={`badge badge-${tone.toLowerCase().replaceAll(' ', '-')} ${mono ? 'font-mono' : ''}`}>{children}</span>
}

export function SeverityBadge({ severity }: { severity?: string | null }) {
  const value = severity?.toUpperCase() || 'UNKNOWN'
  return <Badge tone={value === 'MODERATE' ? 'medium' : value}>{value === 'MODERATE' ? 'MEDIUM' : value}</Badge>
}

export function PriorityBadge({ priority }: { priority: string }) {
  return <Badge tone={`priority-${priority.toLowerCase()}`}>{priority.toUpperCase()}</Badge>
}

export function StatusBadge({ status }: { status: string }) {
  return <Badge tone={`status-${status.toLowerCase().replaceAll(' ', '-')}`}>{status.toUpperCase()}</Badge>
}

export function Input(props: InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={`input ${props.className || ''}`} />
}

export function Select({ children, ...props }: SelectHTMLAttributes<HTMLSelectElement>) {
  return <div className="select-wrap"><select {...props} className={`input select ${props.className || ''}`}>{children}</select><ChevronDown size={15} /></div>
}

export function DataTable<T>({ columns, rows, rowKey, empty = 'No records to display' }: {
  columns: { key: string; label: string; render: (row: T) => ReactNode; className?: string }[]
  rows: T[]
  rowKey: (row: T) => string | number
  empty?: string
}) {
  if (!rows.length) return <EmptyState title="Nothing here yet" detail={empty} />
  return <div className="table-wrap"><table className="data-table"><thead><tr>{columns.map((column) => <th className={column.className} key={column.key}>{column.label}</th>)}</tr></thead><tbody>{rows.map((row) => <tr key={rowKey(row)}>{columns.map((column) => <td className={column.className} key={column.key}>{column.render(row)}</td>)}</tr>)}</tbody></table></div>
}

export function Tabs({ items, active, onChange }: { items: { id: string; label: string }[]; active: string; onChange: (id: string) => void }) {
  return <div className="tabs" role="tablist">{items.map((item) => <button role="tab" aria-selected={active === item.id} onClick={() => onChange(item.id)} className={`tab ${active === item.id ? 'tab-active' : ''}`} key={item.id}>{item.label}</button>)}</div>
}

export function Skeleton({ className = '' }: { className?: string }) { return <div className={`skeleton ${className}`} /> }

export function LoadingBlock({ rows = 4 }: { rows?: number }) {
  return <div className="loading-block" aria-label="Loading"><Skeleton className="skeleton-title" />{Array.from({ length: rows }, (_, index) => <Skeleton className="skeleton-row" key={index} />)}</div>
}

export function EmptyState({ title, detail, action }: { title: string; detail: string; action?: ReactNode }) {
  return <div className="empty-state"><span className="empty-cross">/ / /</span><h3>{title}</h3><p>{detail}</p>{action}</div>
}

export function ErrorState({ message, retry }: { message: string; retry: () => void }) {
  return <div className="error-state"><AlertTriangle size={20} /><div><strong>Data unavailable</strong><p>{message}</p></div><Button variant="outline" onClick={retry}>Retry</Button></div>
}

export function Modal({ open, title, eyebrow, onClose, children, wide = false }: { open: boolean; title: string; eyebrow?: string; onClose: () => void; children: ReactNode; wide?: boolean }) {
  return <AnimatePresence>{open && <motion.div className="modal-scrim" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}>
    <motion.section className={`modal ${wide ? 'modal-wide' : ''}`} role="dialog" aria-modal="true" aria-labelledby="modal-title" initial={{ opacity: 0, y: 18, scale: .985 }} animate={{ opacity: 1, y: 0, scale: 1 }} exit={{ opacity: 0, y: 10 }} transition={{ duration: .18 }}>
      <header className="modal-head">{eyebrow && <span className="eyebrow">{eyebrow}</span>}<h2 id="modal-title">{title}</h2><button className="icon-button" aria-label="Close dialog" onClick={onClose}><X size={18} /></button></header>
      {children}
    </motion.section>
  </motion.div>}</AnimatePresence>
}

export function ConfirmDialog({ open, title, detail, confirmLabel = 'Confirm', busy = false, onConfirm, onCancel }: {
  open: boolean; title: string; detail: string; confirmLabel?: string; busy?: boolean; onConfirm: () => void; onCancel: () => void
}) {
  return <Modal open={open} title={title} eyebrow="CONFIRM ACTION" onClose={onCancel}>
    <div className="confirm-body"><div className="confirm-mark"><AlertTriangle size={20} /></div><p>{detail}</p><div className="modal-actions"><Button variant="quiet" onClick={onCancel}>Cancel</Button><Button variant="danger" onClick={onConfirm} disabled={busy}>{busy && <LoaderCircle className="spin" size={15} />}{confirmLabel}</Button></div></div>
  </Modal>
}

export function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return <label className="field"><span className="field-label">{label}</span>{children}{hint && <span className="field-hint">{hint}</span>}</label>
}

export function Counter({ value, label, index = 0, accent = false }: { value: number; label: string; index?: number; accent?: boolean }) {
  const [display, setDisplay] = useState(0)
  useEffect(() => {
    const start = performance.now()
    const duration = 650
    let frame = 0
    const tick = (now: number) => {
      const progress = Math.min(1, (now - start) / duration)
      setDisplay(Math.round(value * (1 - Math.pow(1 - progress, 4))))
      if (progress < 1) frame = requestAnimationFrame(tick)
    }
    frame = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(frame)
  }, [value])
  return <div className={`counter ${accent ? 'counter-accent' : ''}`} style={{ animationDelay: `${index * 70}ms` }}><div className="counter-value">{display.toLocaleString()}</div><div className="counter-label">{label}</div></div>
}

export function TinySignal({ active = false }: { active?: boolean }) { return <span className={`tiny-signal ${active ? 'tiny-signal-active' : ''}`}><Check size={9} /></span> }
