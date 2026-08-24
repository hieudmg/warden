import { act, render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { describe, expect, test, vi } from "vitest"
import { useListResource } from "./use-list-resource"

interface HarnessProps {
  loader: (signal: AbortSignal) => Promise<string[]>
}

function Harness({ loader }: HarnessProps) {
  const resource = useListResource(loader)
  return (
    <div>
      <span data-testid="state">
        {String(resource.loading)}|{JSON.stringify(resource.data)}|{resource.error?.message ?? ""}
      </span>
      <button type="button" onClick={() => void resource.reload()}>
        reload
      </button>
    </div>
  )
}

describe("useListResource", () => {
  test("loads on mount and exposes data/loading/error", async () => {
    const loader = vi.fn().mockResolvedValue(["a", "b"])
    render(<Harness loader={loader} />)

    expect(loader).toHaveBeenCalledTimes(1)
    expect(screen.getByTestId("state").textContent).toBe("true|[]|")

    await waitFor(() => {
      expect(screen.getByTestId("state").textContent).toBe("false|[\"a\",\"b\"]|")
    })
  })

  test("ignores a stale response that resolves after reload", async () => {
    let resolveFirst!: (value: string[]) => void
    let resolveSecond!: (value: string[]) => void
    const loader = vi
      .fn()
      .mockImplementationOnce(
        () =>
          new Promise<string[]>((resolve) => {
            resolveFirst = resolve
          }),
      )
      .mockImplementationOnce(
        () =>
          new Promise<string[]>((resolve) => {
            resolveSecond = resolve
          }),
      )

    const user = userEvent.setup()
    render(<Harness loader={loader} />)
    expect(loader).toHaveBeenCalledTimes(1)

    await user.click(screen.getByRole("button", { name: "reload" }))
    expect(loader).toHaveBeenCalledTimes(2)

    // The newer request resolves first with fresh data.
    await act(async () => {
      resolveSecond(["fresh"])
    })
    await waitFor(() => {
      expect(screen.getByTestId("state").textContent).toBe('false|["fresh"]|')
    })

    // The stale (older) request resolves afterwards; its data must be dropped.
    await act(async () => {
      resolveFirst(["stale"])
    })
    expect(screen.getByTestId("state").textContent).toBe('false|["fresh"]|')
  })

  test("surfaces errors from the loader", async () => {
    const loader = vi.fn().mockRejectedValue(new Error("boom"))
    render(<Harness loader={loader} />)

    await waitFor(() => {
      expect(screen.getByTestId("state").textContent).toBe("false|[]|boom")
    })
  })

  test("aborts the in-flight request on unmount", () => {
    const captured: AbortSignal[] = []
    const loader = vi.fn((signal: AbortSignal) => {
      captured.push(signal)
      return new Promise<string[]>(() => {})
    })

    const { unmount } = render(<Harness loader={loader} />)
    expect(captured).toHaveLength(1)
    expect(captured[0].aborted).toBe(false)

    unmount()
    expect(captured[0].aborted).toBe(true)
  })
})
