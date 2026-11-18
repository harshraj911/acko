import { motion } from 'framer-motion'

const nodes = [
  { x: 36, y: 25, r: 4, hot: false }, { x: 62, y: 15, r: 3, hot: false }, { x: 78, y: 32, r: 5, hot: true },
  { x: 51, y: 45, r: 4, hot: false }, { x: 25, y: 57, r: 3, hot: true }, { x: 72, y: 69, r: 4, hot: false },
  { x: 42, y: 81, r: 3, hot: false }, { x: 88, y: 52, r: 3, hot: true }, { x: 14, y: 39, r: 2, hot: false },
]
const edges = [[0,1],[0,3],[0,8],[1,2],[1,3],[2,3],[2,7],[2,5],[3,4],[3,5],[4,6],[4,8],[5,6],[5,7],[7,8]]

export function Wireframe() {
  return <div className="wireframe" aria-hidden="true">
    <div className="wireframe-rings"><i /><i /><i /></div>
    <svg viewBox="0 0 100 100" className="wireframe-svg" preserveAspectRatio="xMidYMid meet">
      <defs><linearGradient id="edge-glow" x1="0" x2="1"><stop stopColor="#e50932" stopOpacity=".12" /><stop offset=".55" stopColor="#e50932" stopOpacity=".78" /><stop offset="1" stopColor="#a90052" stopOpacity=".24" /></linearGradient><filter id="node-glow"><feGaussianBlur stdDeviation="1.4" result="blur" /><feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge></filter></defs>
      {edges.map(([a,b], index) => <motion.line key={`e-${index}`} x1={nodes[a].x} y1={nodes[a].y} x2={nodes[b].x} y2={nodes[b].y} stroke="url(#edge-glow)" strokeWidth=".34" initial={{ pathLength: 0, opacity: 0 }} animate={{ pathLength: 1, opacity: [.25,.82,.42] }} transition={{ duration: 1.8, delay: index * .045, repeat: Infinity, repeatType: 'mirror', repeatDelay: 1.8 }} />)}
      {nodes.map((node, index) => <motion.g key={`n-${index}`} filter={node.hot ? 'url(#node-glow)' : undefined} initial={{ opacity: 0, scale: .6 }} animate={{ opacity: [0.6, 1, .68], scale: [1, 1.14, 1] }} transition={{ duration: 3 + (index % 3), delay: index * .14, repeat: Infinity, repeatType: 'mirror' }} style={{ transformOrigin: `${node.x}px ${node.y}px` }}><circle cx={node.x} cy={node.y} r={node.r + 2} fill="none" stroke={node.hot ? '#e50932' : '#777'} strokeOpacity=".28" strokeWidth=".35" /><circle cx={node.x} cy={node.y} r={node.r} fill={node.hot ? '#e50932' : '#d8d8d8'} /></motion.g>)}
    </svg>
    <div className="wireframe-label wireframe-label-top">LIVE / DEPENDENCY TOPOLOGY</div>
    <div className="wireframe-label wireframe-label-bottom"><span>NODE MAP</span><span>0x7F.24</span></div>
  </div>
}
