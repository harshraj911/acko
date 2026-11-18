export function Logo({ compact = false }: { compact?: boolean }) {
  return <div className={`brand-lockup ${compact ? 'brand-compact' : ''}`}>
    <svg className="brand-mark" viewBox="0 0 44 48" aria-hidden="true">
      <path d="M22 2.5 40 9v13.2c0 11.2-7.3 18.5-18 23.3C11.3 40.7 4 33.4 4 22.2V9L22 2.5Z" fill="none" stroke="currentColor" strokeWidth="2.4" />
      <path d="m12 17 9.8-5.5 10 5.7v11.4l-10 5.7-9.8-5.7V17Z" fill="none" stroke="currentColor" strokeWidth="1.6" opacity=".8" />
      <path d="M14.8 19.8 22 24l7.2-4.2M22 24v8.1M14.8 19.8v8.3M29.2 19.8v8.3" fill="none" stroke="currentColor" strokeWidth="1.6" />
      <circle cx="14.8" cy="19.8" r="2.2" fill="currentColor" /><circle cx="29.2" cy="19.8" r="2.2" fill="currentColor" /><circle cx="22" cy="24" r="2.2" fill="currentColor" /><circle cx="22" cy="32.1" r="2.2" fill="currentColor" />
    </svg>
    {!compact && <span className="brand-copy"><strong>DEPENDENCY WATCH</strong><small>SOFTWARE SUPPLY CHAIN INTELLIGENCE</small></span>}
  </div>
}
