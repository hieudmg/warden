# shadcn 4.19.0 stylesheet provenance

This directory retains only the unmodified stylesheet previously imported from
`shadcn/tailwind.css`. It is not a maintained library fork and contains no CLI,
MCP server, component generator or package-execution mechanism.

- Upstream: [shadcn-ui/ui](https://github.com/shadcn-ui/ui), package
  [shadcn@4.19.0](https://www.npmjs.com/package/shadcn/v/4.19.0).
- Published source archive:
  <https://registry.npmjs.org/shadcn/-/shadcn-4.19.0.tgz>.
- Archive integrity (SHA-512, base64):
  `EQF6R+CUXTsEP2BpyhxrUEAFesrtFD1POvVOf5jM+wkgtA4kG1EW1+1Wlmi9LqiprSL681JJXBcS0u8WkVVVyQ==`.
- `tailwind.css`: exact bytes of `package/dist/tailwind.css`, 16041 bytes,
  SHA-256 `bc7d83425702955b4cb67cb14ede9d603f9d912376d57a2d81d661094d2a782a`.
- `LICENSE.md`: exact upstream MIT license, copyright (c) 2023 shadcn,
  1063 bytes, SHA-256
  `1564074e13439397221ffd522e2e504d56561994a23d371aa5e3ad43e4f5423f`.

Both files were compared with the published archive and its recorded integrity
before removing the project-local package. Keep the full notice in
[LICENSE.md](LICENSE.md) with this stylesheet. It is not public domain.

The application imports this CSS directly. The directory is excluded from
Tailwind class-source discovery so provenance/license prose does not generate
application utilities. Existing generated UI components and their Base UI/Radix
runtime dependencies remain unchanged. Future component-authoring tooling is a
separate owner choice; do not restore the removed package implicitly.
