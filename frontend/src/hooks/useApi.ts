import { useCallback, useEffect, useState } from 'react'

export function useApi<T>(loader: () => Promise<T>, deps: readonly unknown[] = []) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [reloadKey, setReloadKey] = useState(0)
  const reload = useCallback(() => setReloadKey((key) => key + 1), [])

  useEffect(() => {
    let alive = true
    setLoading(true)
    loader().then((value) => {
      if (alive) { setData(value); setError(null) }
    }).catch((reason: unknown) => {
      if (alive) setError(reason instanceof Error ? reason.message : 'Request failed')
    }).finally(() => { if (alive) setLoading(false) })
    return () => { alive = false }
    // loader is recreated by callers; explicit deps keep request lifetimes intentional.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, reloadKey])

  return { data, error, loading, reload, setData }
}
