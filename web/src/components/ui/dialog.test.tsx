import { render, screen } from "@testing-library/react"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"

function TallDialog() {
  return (
    <Dialog open>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Tall modal</DialogTitle>
          <DialogDescription>Scrollable body contract</DialogDescription>
        </DialogHeader>
        <div data-testid="tall-body">
          {Array.from({ length: 30 }, (_, i) => (
            <div key={i}>Field {i}</div>
          ))}
        </div>
        <DialogFooter>
          <button type="button">Cancel</button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

test("dialog content caps its height to the dynamic viewport", () => {
  render(<TallDialog />)
  const content = document.querySelector('[data-slot="dialog-content"]')
  expect(content).not.toBeNull()
  expect(content!.className).toContain("max-h-[calc(100dvh-2rem)]")
})

test("dialog content hosts a flex-1 scrollable body wrapping the children", () => {
  render(<TallDialog />)
  const body = screen.getByTestId("tall-body")
  // The children live inside an inner scroll container with flex-1 + overflow-y-auto.
  expect(body.closest(".overflow-y-auto")).not.toBeNull()
  expect(body.closest(".flex-1")).not.toBeNull()
})

test("dialog keeps its close button outside the scroll area", () => {
  render(<TallDialog />)
  const closeButton = screen.getByRole("button", { name: "Close" })
  expect(closeButton).toBeInTheDocument()
  expect(closeButton).toHaveClass("top-2", "right-2")
  expect(closeButton.closest(".overflow-y-auto")).toBeNull()
})
