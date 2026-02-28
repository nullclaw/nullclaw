# vendored sqlite3 package

This directory vendors the Zig `sqlite3` build package and SQLite 3.51.0
amalgamation sources used by nullclaw.

Why vendored:
- avoid runtime nested zip downloads during `zig build`
- make builds deterministic across environments where Zig zip temp handling fails
  (see issue #142)
- integrity is enforced by SHA-256 verification in the root `build.zig` when SQLite is enabled

Contents:
- `build.zig` and `build.zig.zon` based on `allyourcodebase/sqlite3` and patched to library-only mode for nullclaw
- `sqlite3.c`, `sqlite3.h`, `sqlite3ext.h` from SQLite 3.51.0 amalgamation

Upstream references:
- Zig wrapper: https://github.com/allyourcodebase/sqlite3
- SQLite source: https://sqlite.org/2025/sqlite-amalgamation-3510000.zip
