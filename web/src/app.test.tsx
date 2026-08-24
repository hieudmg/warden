import { render, screen } from "@testing-library/react"
import { App } from "./app"

test("renders the light Warden shell", () => {
  render(<App />)
  expect(screen.getByRole("heading", { name: "Warden Hub" })).toBeInTheDocument()
  expect(document.documentElement).not.toHaveClass("dark")
})
