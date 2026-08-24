import { useCallback, useEffect, useRef, useState } from "react"

export interface ListResource<T> {
  data: T[]
  loading: boolean
  error: Error | null
  reload(): Promise<void>
}

/**
 * Loads a list from an abortable loader and exposes it to the caller.
 * Each reload aborts the previous in-flight request and stamps a
 * monotonically increasing request id; responses are only committed when
 * they are still the latest request, so stale responses can never
 * overwrite fresher data.
 */
export function useListResource<T>(loader: (signal: AbortSignal) => Promise<T[]>): ListResource<T> {
  const [state, setState] = useState({ data: [] as T[], loading: true, error: null as Error | null })
  const requestID = useRef(0)
  const controller = useRef<AbortController | null>(null)

  const reload = useCallback(async () => {
    const id = ++requestID.current
    controller.current?.abort()
    const next = new AbortController()
    controller.current = next
    setState((current) => ({ ...current, loading: true, error: null }))
    try {
      const data = await loader(next.signal)
      if (id === requestID.current) setState({ data, loading: false, error: null })
    } catch (error) {
      if (!next.signal.aborted && id === requestID.current) {
        setState((current) => ({ ...current, loading: false, error: error as Error }))
      }
    }
  }, [loader])

  useEffect(() => {
    void reload()
    return () => controller.current?.abort()
  }, [reload])

  return { ...state, reload }
}
