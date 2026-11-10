<!-- Copyright (c) Cratis. All rights reserved. -->
<!-- Licensed under the MIT license. See LICENSE file in the project root for full license information. -->

# Arc MCP authorization vector artifact changelog

## 1.0.0

- Package the 48 signed-off MCP authorization cases without changing vector bytes.
- Assign stable case IDs in the manifest, with zero-based indexes and SHA-256 bindings.
- Record the MCP authorization revision, contract version, and vector file hash.
- Lock case-ID/hash bindings and vector-file hashes in an independently reviewed
  `baselines/v1.0.0.json`; validate and package the versioned baseline history.
- Enforce released-baseline immutability against `vectors/arc-mcp-authorization/v<version>`
  tags in Build CI and before packaging, with a base-revision check on pull requests.

Artifact versions use SemVer independently of the contract version. Additive cases
increment the minor version; meaning changes, removals, or incompatible schema changes
increment the major version; documentation and packaging corrections increment the patch
version. Never reassign an existing case ID to different behavior. Every artifact bump
updates this changelog, the manifest, and the contract document together, and adds a
new independently approved `baselines/v<version>.json`. Released baselines are immutable:
never edit or regenerate one. Retain all older baseline files and matching changelog
headings. IDs are never reassigned; changing a case requires a new ID or a version bump,
and a bump never permits giving an existing ID different meaning. Any ID or hash change
without a bump fails the current baseline check. The release tag is the trust anchor:
released baseline bytes and the manifest/vector content hashes for that version must
match the tagged revision. Untagged baselines pass with an unreleased notice; v1.0.0 is
anchored by its first release tag after the next train merges. Pull requests also preserve
all baselines already on the base revision; changed manifest/vector content requires a
new version and a new baseline, never regeneration of an old baseline.
