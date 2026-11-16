# Resumable server setup and account authentication

## Goal and approved constraints

User-approved new PR: all init file defaults under ~/.warden; persist every submitted non-secret setup answer, including invalid/incomplete drafts, before setup success; reload drafts and reprompt with saved defaults. Explicit custom paths remain supported. Never persist plaintext passwords in answer JSON or show password defaults.

Init selects account (username/password, default) or existing passkey authentication. No unauthenticated mode. Account creation occurs on the existing temporary HTTPS setup plane. Account login also unlocks a password-protected vault, with no plaintext disk key fallback. Preserve HTTPS, CLI/API authentication, recovery, fresh verification for sensitive actions, session/vault lifecycle protections, and existing installations. Existing passkey installations stay passkey; adding a new default must not reinterpret legacy missing auth fields. Never reset existing data or silently convert an initialized installation. No live deployment, migration, merging or release publication.

## Execution

Repository /var/www/code/go/warden, branch hieudmg/resumable-account-setup, base origin/main (606abb8). Sequential writers only. Preserve unrelated untracked mise.toml and scripts/ci/__pycache__/. Parent owns authority, security design, acceptance, Git publication. Workers own assigned cohesive outcomes and test-first execution; independent read-only security review follows stable changes. Escalate consequential unresolved credential/recovery or compatibility changes.

## Task 1: Resumable setup answers

- Implement ~/.warden config/database/TLS-path defaults; keep init/serve consistent and explicit custom paths working. Do not silently migrate old /etc configurations or overwrite initialized installation config.
- Save each submitted non-secret answer; saved invalid/incomplete configs must remain editable on retry without being accepted by serve. Distinguish draft loading from validated runtime loading. Reprompt all applicable fields with saved defaults; keep non-prompted settings intact.
- Preserve private permissions, safe file replacement, storage refusal, concurrency/ownership safeguards and malformed/legacy config protection. Persist answers even when later validation or setup fails, without changing initialized identities/data.
- Focused failing tests before implementation for drafts/retry, validation failure, storage refusal, private save/update, defaults, mode-dependent fields, malformed/legacy config, explicit paths, concurrent conflicts as applicable. Update relevant help/config/init docs. Do not implement auth-mode selection yet; task 2 owns it.
- Checks: affected config and warden-server tests; inspect actual filesystem/serialized draft round trips. Report exact RED/GREEN commands, results, limitations.
- [x] Implement and verify locally. Historical evidence: [Task 1 report](../reports/2026-11-16-resumable-setup-task1.md). Independent immutable review later **BLOCKED** custom-path legacy omitted-DB semantics, canonical JSON alias handling, and config-publication durability. Focused corrections/regressions are integrated in Task2 below; parent re-review remains separate.

## Task 2: Account authentication end-to-end

- Inspect current setup/install/session/fresh-action/recovery/vault contracts before design. Add explicit account/passkey choice to init and persisted configuration; account default for new init only; missing legacy fields mean passkey.
- Implement full account journey: temporary terminal-password-gated HTTPS setup, owner username/password creation and confirmation, password-protected DEK plus existing high-entropy offline recovery, atomic commit, username/password login and vault unlock after restart, logout/global lock, fresh password verification for existing sensitive grants, password recovery/replacement preserving same DEK and revoking old sessions/client authorizations. Existing passkey journey and CLI/API audience isolation remain unchanged.
- Select evidence-supported standard password derivation using installed official library/source documentation; no custom cryptography or plaintext disk keys. Password attacks/expensive work require bounded request size/admission/rate protections; wrong username/password responses must not disclose sensitive identity details. Passwords/derived secrets must not enter logs/config answers or persistent plaintext. Retain CSRF/origin/cookie protections and protected delivery leases.
- Browser UI must branch by configured mode, never invoke WebAuthn/PRF in account mode, support account fresh verification and recovery. No account/password controls that merely pretend success or leave required journeys unavailable. Apply modest setup-page usability polish: clear steps, spacing, helpful validation, and an understandable account/passkey choice; no broad redesign.
- TDD for focused crypto/schema/setup/runtime/frontend acceptance, preserving legacy passkey tests. Exercise representative producer-to-consumer payloads, signed-in sensitive actions, authenticated CLI approval, restart, lock/logout and recovery. Add HTTPS composed account lifecycle coverage alongside existing passkey lifecycle.
- Update docs and release version 0.23.0 -> 0.24.0 (minor additive account capability), synchronized three version fields, without unrelated lock/dependency changes. No breaking legacy format changes without owner approval.
- [x] Implement and verify locally. [Task2 evidence and self-review](../reports/2026-11-16-resumable-setup-task2.md) records actual RED/GREEN, Task1 BLOCK corrections, full Go/race/vet/web/build and production-binary account/passkey lifecycles, private account/passkey browser artifacts, exact skips and remaining checks. New account mode uses fixed Argon2id 64 MiB×3p4, explicit password envelope/random credential ID, no mode conversion, no TOTP and no password caching. Parent/independent review is pending. One strict passkey browser run retained a lock-transition aborted passkey-list request; preceding/following standalone runs passed without weakening the gate, but flake cause/elimination is unproven and remains an explicit parent-review risk.

## Final acceptance and publication

- Inspect diffs; independent read-only security review, fix validated findings and re-review affected scope.
- Full Go suite, affected Go race checks, go vet, web tests, production build/distribution tests and production-path account HTTPS/browser lifecycle as feasible in isolated fixtures. State any unverified real browser/trust/native boundaries explicitly; no live certificates/trust manipulation.
- Recheck latest approved base/version, stage intended paths only via NUL pathspec file, commit/push/open PR against main. No merge/tag/release. PR summary includes 0.23.0 -> 0.24.0 minor rationale, test evidence and genuine limitations.
