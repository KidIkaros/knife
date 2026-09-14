# Terminal-first stabilization

Knife consists of one Rust package: deterministic core analysis, CLI, TUI and
MCP. The TUI is the primary interactive surface. All front ends reuse the engine;
complete query parity is still stabilization work.

## Current checkpoint

- Desktop GUI workspace members and GUI-only dependencies removed.
- Shared typed addresses, navigation, references and analyst annotations.
- Monochrome TUI, forward/back navigation, catalog filtering and pane controls.
- ELF header/program-header/section-header inspection in the core and CLI.
- Reproducible README terminal animation and MP4 via scripts/record-demo.ps1.
- Background `:reload` that rereads the target from disk, preserving the
  session on failure and following content identity for annotations.
- Explicit goto address modes: `off:`/`file:` file offsets, `va:` static VAs.
- Inspection of targets with no recovered functions, and a resize notice
  instead of clipped fragments below a 24x6 terminal.

## Next work

1. Expose ELF headers and segments through TUI views using the shared API.
2. Improve scrollable help and CLI/MCP query parity.

Decompiler and inferred-type views remain experimental. New capabilities should
be small, independently testable changes rather than another architecture rewrite.

## Validation

```powershell
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked
cargo test --locked --features record --lib tui::record
cargo build --locked --release --bin knife
```

Use synthetic PE/ELF/Mach-O fixtures and deterministic terminal render tests.
Passing these gates does not establish a complete vulnerability audit or replace
interactive cross-platform testing.
