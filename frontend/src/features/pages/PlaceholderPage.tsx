import { ArrowUpRight, Construction } from 'lucide-react'
import { Link } from 'react-router-dom'

export function PlaceholderPage({ title, index, description }: { title: string; index: string; description: string }) {
  return <div className="page-pad placeholder-page"><span className="eyebrow">MODULE / {index} · PLANNED</span><h1>{title}</h1><div className="placeholder-rule" /><div className="placeholder-message"><Construction size={20} /><div><b>Built in the next step</b><p>{description}</p><span>This view does not contain placeholder metrics or fabricated records.</span></div></div><Link to="/" className="text-link">RETURN TO OVERVIEW <ArrowUpRight size={13} /></Link></div>
}
