// Memory only. Nothing here is serialized to storage, caches or URLs. The
// bearer cookie remains HttpOnly; this module holds only CSRF and reset epochs.
import { useSyncExternalStore } from 'react'

let epoch = 0
const resets = new Set<() => void>()
const subscribeSecurity = (listener: () => void) => { resets.add(listener); return () => { resets.delete(listener) } }
export const useSecurityEpoch = () => useSyncExternalStore(subscribeSecurity, securityEpoch)
let csrf = ''
let controller = new AbortController()
export const securitySignal = () => controller.signal
const denied = new Set<(status: number) => void>()
export const securityEpoch = () => epoch
export const csrfHeader = () => csrf
export const setCSRF = (value: string) => { csrf = value }
export function invalidateSecurity() { epoch++; controller.abort(); controller = new AbortController(); for (const listener of resets) listener() }
export function rejectStale(generation: number) {
  if (generation !== epoch) throw new DOMException('Security state changed; request cancelled', 'AbortError')
}
export function securityDenied(status: number) {
  if (status !== 401 && status !== 423) return
  invalidateSecurity()
  if (status === 401) csrf = ''
  for (const listener of denied) listener(status)
}
export function onSecurityDenied(listener: (status: number) => void) {
  denied.add(listener)
  return () => { denied.delete(listener) }
}
