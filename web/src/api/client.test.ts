import { afterEach, describe, expect, test, vi } from "vitest"
import { api, ApiError } from "./client"
import type { KeyPairRequest, SSHConnectionRequest } from "./types"

afterEach(() => {
  vi.unstubAllGlobals()
})

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  })
}

describe("api client", () => {
  test("decodes stable JSON error envelopes", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse({ code: "conflict", message: "name exists" }, 409),
      ),
    )
    await expect(api.listSSH()).rejects.toMatchObject({
      name: "ApiError",
      code: "conflict",
      message: "name exists",
      status: 409,
    })
  })

  test("throws ApiError with http_<status> for unstructured failures", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("boom", { status: 502 })),
    )
    await expect(api.listSSH()).rejects.toMatchObject({
      name: "ApiError",
      code: "http_502",
      status: 502,
    })
  })

  test("sets the JSON content type only when a body is present", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse([]))
    vi.stubGlobal("fetch", fetchMock)

    await api.listSSH()
    const listCall = fetchMock.mock.calls[0]
    expect(listCall[0]).toBe("/api/v1/ssh-connections")
    expect(listCall[1]?.headers.get("Content-Type")).toBeNull()
    expect(listCall[1]?.body).toBeUndefined()

    const payload: SSHConnectionRequest = {
      name: "jump",
      host: "10.0.0.1",
      port: 22,
      username: "root",
      password: null,
      private_key: null,
      private_key_passphrase: null,
      proxy_host: "",
      proxy_port: 0,
      proxy_username: "",
      proxy_password: null,
      jump_connection_ids: "[]",
      default_dir: "",
      group_id: 0,
    }
    fetchMock.mockResolvedValueOnce(jsonResponse({ id: 1 }))
    await api.createSSH(payload)
    const createCall = fetchMock.mock.calls[1]
    expect(createCall[0]).toBe("/api/v1/ssh-connections")
    expect(createCall[1]?.method).toBe("POST")
    expect(createCall[1]?.headers.get("Content-Type")).toBe("application/json")
    expect(JSON.parse(createCall[1]?.body as string)).toEqual(payload)
  })

  test("resolves undefined for 204 responses", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: 204 })))
    await expect(api.deleteSSH(7)).resolves.toBeUndefined()
    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/ssh-connections/7")
  })

  test("propagates abort signals to fetch", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse([]))
    vi.stubGlobal("fetch", fetchMock)
    const controller = new AbortController()
    void api.listSSH(controller.signal)
    expect(fetchMock.mock.calls[0][1]?.signal).toBe(controller.signal)
  })

  test("encodes the project name in the reports path", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse([])))
    await api.listReports("a/b c")
    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/projects/a%2Fb%20c/reports")
  })

  test("ApiError exposes stable properties", () => {
    const error = new ApiError("conflict", "name exists", 409)
    expect(error).toBeInstanceOf(Error)
    expect(error.name).toBe("ApiError")
    expect(error.code).toBe("conflict")
    expect(error.message).toBe("name exists")
    expect(error.status).toBe(409)
  })

  test("lists key pairs from the metadata-only endpoint", async () => {
    const pairs = [
      {
        id: 1,
        name: "prod",
        has_public_key: true,
        has_private_key: true,
        has_private_key_passphrase: false,
        created_at: "2026-08-26T00:00:00Z",
        updated_at: "2026-08-26T00:00:00Z",
      },
    ]
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(pairs)))
    const result = await api.listKeyPairs()
    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/key-pairs")
    expect(result).toEqual(pairs)
  })

  test("GET key pair returns the vault with raw material", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse({
          id: 1,
          name: "prod",
          public_key: "PUBLIC-KEY-MATERIAL",
          private_key: "PRIVATE-KEY-MATERIAL",
          private_key_passphrase: "PHRASE-MATERIAL",
          created_at: "2026-08-26T00:00:00Z",
          updated_at: "2026-08-26T00:00:00Z",
        }),
      ),
    )
    const vault = await api.getKeyPair(1)
    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/key-pairs/1")
    expect(vault.id).toBe(1)
    expect(vault.name).toBe("prod")
    expect(vault.public_key).toBe("PUBLIC-KEY-MATERIAL")
    expect(vault.private_key).toBe("PRIVATE-KEY-MATERIAL")
    expect(vault.private_key_passphrase).toBe("PHRASE-MATERIAL")
  })

  test("creates a key pair with nullable secret fields", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(
        jsonResponse(
          {
            id: 1,
            name: "prod",
            has_public_key: true,
            has_private_key: false,
            has_private_key_passphrase: false,
            created_at: "2026-08-26T00:00:00Z",
            updated_at: "2026-08-26T00:00:00Z",
          },
          201,
        ),
      )
    vi.stubGlobal("fetch", fetchMock)
    const payload: KeyPairRequest = {
      name: "prod",
      public_key: "PUBLIC-KEY-MATERIAL",
      private_key: null,
      private_key_passphrase: null,
    }
    await api.createKeyPair(payload)
    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/key-pairs")
    expect(fetchMock.mock.calls[0][1]?.method).toBe("POST")
    expect(JSON.parse(fetchMock.mock.calls[0][1]?.body as string)).toEqual(payload)
  })

  test("updates a key pair with an explicit empty clear value", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(
        jsonResponse({
          id: 1,
          name: "prod",
          has_public_key: true,
          has_private_key: false,
          has_private_key_passphrase: false,
          created_at: "2026-08-26T00:00:00Z",
          updated_at: "2026-08-26T00:00:00Z",
        }),
      )
    vi.stubGlobal("fetch", fetchMock)
    const payload: KeyPairRequest = {
      name: "prod",
      public_key: null,
      private_key: "",
      private_key_passphrase: null,
    }
    await api.updateKeyPair(1, payload)
    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/key-pairs/1")
    expect(fetchMock.mock.calls[0][1]?.method).toBe("PUT")
    expect(JSON.parse(fetchMock.mock.calls[0][1]?.body as string)).toEqual(payload)
  })

  test("deletes a key pair via 204", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: 204 })))
    await expect(api.deleteKeyPair(3)).resolves.toBeUndefined()
    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/key-pairs/3")
    expect(vi.mocked(fetch).mock.calls[0][1]?.method).toBe("DELETE")
  })

  test("lists key-pair dependents", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(jsonResponse({ ssh: [{ id: 2, name: "jump-a" }], db: [] })),
    )
    const dependents = await api.keyPairDependents(1)
    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/key-pairs/1/dependents")
    expect(dependents).toEqual({ ssh: [{ id: 2, name: "jump-a" }], db: [] })
  })

  test("surfaces ApiError on a duplicate key-pair name", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          { code: "conflict", message: "a key pair with that name already exists" },
          409,
        ),
      ),
    )
    await expect(
      api.createKeyPair({ name: "dup", public_key: null, private_key: null, private_key_passphrase: null }),
    ).rejects.toMatchObject({ name: "ApiError", code: "conflict", status: 409 })
  })
})
