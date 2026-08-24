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
  // sm:max-w-sm (24rem) was bumped to sm:max-w-xl (36rem) so wider forms fit.
  expect(content!.className).toContain("sm:max-w-xl")
  expect(content!.className).not.toContain("sm:max-w-sm")
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

test("header is pinned and does not scroll with the body", () => {
  render(<TallDialog />)
  const header = document.querySelector('[data-slot="dialog-header"]')
  const body = document.querySelector('[data-slot="dialog-body"]')
  const footer = document.querySelector('[data-slot="dialog-footer"]')
  expect(header).not.toBeNull()
  expect(header!.className).toContain("flex-none")
  expect(header!.className).toContain("border-b")
  // DOM order: header before body before footer.
  const slots = Array.from(
    document.querySelectorAll(
      '[data-slot="dialog-header"], [data-slot="dialog-body"], [data-slot="dialog-footer"]',
    ),
  )
  expect(slots.indexOf(header!)).toBeLessThan(slots.indexOf(body!))
  expect(slots.indexOf(footer!)).toBeGreaterThan(slots.indexOf(body!))
})

test("footer is pinned and does not scroll with the body", () => {
  render(<TallDialog />)
  const footer = document.querySelector('[data-slot="dialog-footer"]')
  expect(footer).not.toBeNull()
  expect(footer!.className).toContain("flex-none")
  expect(footer!.className).toContain("border-t")
})

test("body is the only scrollable region", () => {
  render(<TallDialog />)
  const body = document.querySelector('[data-slot="dialog-body"]')
  const headerRegion = document.querySelector('[data-slot="dialog-header-region"]')
  const footerRegion = document.querySelector('[data-slot="dialog-footer-region"]')
  expect(body).not.toBeNull()
  expect(body!.className).toContain("flex-1")
  expect(body!.className).toContain("overflow-y-auto")
  expect(headerRegion).not.toBeNull()
  expect(footerRegion).not.toBeNull()
  expect(headerRegion!.className).not.toContain("overflow-y-auto")
  expect(footerRegion!.className).not.toContain("overflow-y-auto")
})

test("content without header or footer still wraps children in a scrollable body", () => {
  render(
    <Dialog open>
      <DialogContent>
        <div data-testid="plain-child">Just content</div>
      </DialogContent>
    </Dialog>,
  )
  const body = document.querySelector('[data-slot="dialog-body"]')
  expect(body).not.toBeNull()
  expect(body!.className).toContain("overflow-y-auto")
  expect(screen.getByTestId("plain-child").closest('[data-slot="dialog-body"]')).not.toBeNull()
  expect(document.querySelector('[data-slot="dialog-header-region"]')).toBeNull()
  expect(document.querySelector('[data-slot="dialog-footer-region"]')).toBeNull()
})
