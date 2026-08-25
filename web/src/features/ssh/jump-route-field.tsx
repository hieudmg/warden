import { useState } from "react"
import { ArrowDown, ArrowUp, Trash2 } from "lucide-react"

import type { SSHConnection } from "@/api/types"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { SSHProfileCombobox } from "@/components/ssh-profile-combobox"
import {
  jumpCandidates,
  jumpLabel,
  jumpOptionLabel,
  moveJump,
} from "./jump-route"

export interface JumpRouteFieldProps {
  /** Visible route entries in order, preserved verbatim (duplicates included). */
  value: readonly number[]
  /** Called with the next route whenever the user explicitly changes it. */
  onChange: (next: number[]) => void
  /** Existing SSH profiles backing the Add options and labels. */
  profiles: readonly SSHConnection[]
  /** The profile being edited; excluded from Add and marked as self. */
  editingID?: number
}

/**
 * Ordered relationship editor for `jump_connection_ids`. Every stored entry
 * keeps its position unless the user explicitly moves or removes it.
 * Accessible names carry the visible label plus the entry index so duplicate
 * labels remain distinguishable.
 */
export function JumpRouteField({
  value,
  onChange,
  profiles,
  editingID,
}: JumpRouteFieldProps) {
  const [pendingAdd, setPendingAdd] = useState("")
  const candidates = jumpCandidates(profiles, value, editingID)

  return (
    <div className="space-y-2">
      <ul className="space-y-1.5">
        {value.map((id, index) => {
          const label = jumpLabel(id, profiles, editingID)
          const isSelf = id === editingID
          const isMissing = !isSelf && !profiles.some(profile => profile.id === id)
          return (
            <li key={`${id}:${index}`} className="flex items-center gap-1.5">
              <span className="min-w-0 flex-1 truncate text-sm">{label}</span>
              {isSelf && <Badge variant="secondary">(current connection)</Badge>}
              {isMissing && <Badge variant="outline">Missing SSH #{id}</Badge>}
              <Button
                type="button"
                variant="ghost"
                size="icon"
                aria-label={`Move ${label} ${index} up`}
                disabled={index === 0}
                onClick={() => onChange(moveJump(value, index, index - 1))}
              >
                <ArrowUp aria-hidden="true" />
              </Button>
              <Button
                type="button"
                variant="ghost"
                size="icon"
                aria-label={`Move ${label} ${index} down`}
                disabled={index === value.length - 1}
                onClick={() => onChange(moveJump(value, index, index + 1))}
              >
                <ArrowDown aria-hidden="true" />
              </Button>
              <Button
                type="button"
                variant="ghost"
                size="icon"
                aria-label={`Remove ${label} ${index}`}
                onClick={() => onChange(value.filter((_, i) => i !== index))}
              >
                <Trash2 aria-hidden="true" />
              </Button>
            </li>
          )
        })}
      </ul>
      <SSHProfileCombobox
        aria-label="Add SSH profile to jump route"
        value={pendingAdd}
        options={candidates.map(profile => ({
          value: String(profile.id),
          label: jumpOptionLabel(profile),
        }))}
        placeholder="Add"
        searchPlaceholder="Search SSH profiles"
        emptyLabel="No SSH profiles found."
        disabled={candidates.length === 0}
        onValueChange={selected => {
          setPendingAdd("")
          onChange([...value, Number(selected)])
        }}
      />
    </div>
  )
}
