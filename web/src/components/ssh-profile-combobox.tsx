import { Button } from "@/components/ui/button"
import {
  Combobox,
  ComboboxContent,
  ComboboxEmpty,
  ComboboxInput,
  ComboboxItem,
  ComboboxList,
  ComboboxTrigger,
  ComboboxValue,
} from "@/components/ui/combobox"

export interface SSHProfileOption {
  value: string
  label: string
}

export interface SSHProfileComboboxProps {
  id?: string
  "aria-label"?: string
  value: string
  options: readonly SSHProfileOption[]
  placeholder: string
  searchPlaceholder: string
  emptyLabel: string
  disabled?: boolean
  onValueChange: (value: string) => void
}

/** Searchable single-value SSH profile picker built with shadcn Combobox. */
export function SSHProfileCombobox({
  id,
  value,
  options,
  placeholder,
  searchPlaceholder,
  emptyLabel,
  disabled = false,
  onValueChange,
  ...props
}: SSHProfileComboboxProps) {
  const selected = options.find(option => option.value === value) ?? null

  return (
    <Combobox
      items={options}
      value={selected}
      onValueChange={(option: SSHProfileOption | null) => {
        if (option) onValueChange(option.value)
      }}
    >
      <ComboboxTrigger
        render={
          <Button
            id={id}
            type="button"
            variant="outline"
            role="combobox"
            disabled={disabled}
            className="w-full justify-between font-normal"
            {...props}
          />
        }
      >
        <ComboboxValue>
          {(option: SSHProfileOption | null) => option?.label ?? placeholder}
        </ComboboxValue>
      </ComboboxTrigger>
      <ComboboxContent>
        <ComboboxInput showTrigger={false} placeholder={searchPlaceholder} />
        <ComboboxEmpty>{emptyLabel}</ComboboxEmpty>
        <ComboboxList>
          {(option: SSHProfileOption) => (
            <ComboboxItem key={option.value} value={option}>
              {option.label}
            </ComboboxItem>
          )}
        </ComboboxList>
      </ComboboxContent>
    </Combobox>
  )
}
