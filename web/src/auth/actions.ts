// Explicit management actions, matching the server allowlist; never transport.
export function sensitiveAction(method: string, path: string): string | undefined {
 if (method === 'GET' && path === '/api/v1/data/export') return 'export'
 if (method === 'POST' && path === '/api/v1/data/import') return 'import'
 if (method === 'POST' && path === '/api/v1/key-pairs') return 'key_mutation'
 if (/^\/api\/v1\/key-pairs\/[^/?#%]+$/.test(path)) {
  if (method === 'GET') return 'key_reveal'
  if (method === 'PUT' || method === 'DELETE') return 'key_mutation'
 }
 if (method === 'POST') {
  if (path === '/api/v1/auth/clients/approve') return 'client_approve'
  if (path === '/api/v1/auth/clients/revoke') return 'client_revoke'
  if (path === '/api/v1/auth/passkeys/begin' || path === '/api/v1/auth/passkeys/key') return 'passkey_add'
  if (path === '/api/v1/auth/passkeys/remove') return 'passkey_remove'
  if (path === '/api/v1/auth/recovery/rotation/key') return 'recovery_rotate'
 }
 return undefined
}
