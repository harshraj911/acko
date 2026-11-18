import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'

type Toast = { id: number; message: string; kind: 'success' | 'error' | 'info' }
type ContextValue = { notify: (message: string, kind?: Toast['kind']) => void }
const Context = createContext<ContextValue>({ notify: () => undefined })

export function AppProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])
  const notify = (message: string, kind: Toast['kind'] = 'success') => {
    const id = Date.now() + Math.random()
    setToasts((items) => [...items, { id, message, kind }])
    window.setTimeout(() => setToasts((items) => items.filter((item) => item.id !== id)), 4200)
  }
  useEffect(() => {
    const listener = (event: Event) => {
      const detail = (event as CustomEvent<{ message: string; kind?: Toast['kind'] }>).detail
      if (detail?.message) notify(detail.message, detail.kind || 'info')
    }
    window.addEventListener('dw-toast', listener)
    return () => window.removeEventListener('dw-toast', listener)
  })
  return <Context.Provider value={{ notify }}>
    {children}
    <div className="toast-stack" aria-live="polite">
      {toasts.map((toast) => <div className={`toast toast-${toast.kind}`} key={toast.id}>{toast.message}</div>)}
    </div>
  </Context.Provider>
}

export const useApp = () => useContext(Context)
