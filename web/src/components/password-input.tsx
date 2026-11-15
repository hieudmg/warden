import { useState, type ComponentProps } from 'react'
import { Input } from './ui/input'
import { Button } from './ui/button'

/** Reveal is local to this mounted field; closing a form removes it. */
export function PasswordInput({ label, ...props }: Omit<ComponentProps<typeof Input>, 'type'> & { label: string }) {
  const [revealed, setRevealed] = useState(false)
  return <div className="flex gap-2">
    <Input {...props} type={revealed ? 'text' : 'password'} autoComplete="off" />
    <Button type="button" variant="outline" aria-label={`${revealed ? 'Hide' : 'Reveal'} ${label.toLowerCase()}`} aria-pressed={revealed} onClick={() => setRevealed(value => !value)}>
      {revealed ? 'Hide' : 'Reveal'}
    </Button>
  </div>
}
