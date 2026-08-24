import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"

interface ResourceErrorProps {
  error: Error
  onRetry: () => void
  label: string
}

/** Module-level load error with a Retry action. */
export function ResourceError({ error, onRetry, label }: ResourceErrorProps) {
  return (
    <Alert variant="destructive">
      <AlertTitle>Unable to load {label}</AlertTitle>
      <AlertDescription>{error.message}</AlertDescription>
      <Button type="button" variant="outline" onClick={onRetry}>
        Retry
      </Button>
    </Alert>
  )
}
