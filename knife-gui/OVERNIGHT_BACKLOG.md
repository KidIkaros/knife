# knife-gui overnight backlog

Autonomous improvement queue. Rules: one small focused commit per item, all gates
green before commit, authored bl4ckr0ss3 only (no AI attribution), static-only,
commit locally (do not push). Reuse existing backend data; avoid risky reknife
API changes.

## Queue (top = next)
- [ ] Copy actions: copy current address / function name to clipboard (keyboard + menu).
- [ ] Deeper IOCTL decode in the driver view: break CTL_CODE into device / function /
      method / access, shown per handler.
- [ ] Whole-program call graph: expose graphs::call_graph and add a navigable view.
- [ ] Bookmarks: mark/unmark an address (IDA marks), persisted per binary, list panel.
- [ ] Findings report export: write the ranked findings to a markdown file.
- [ ] Section entropy in the detail panel (spot packed/encrypted regions).
- [ ] Hex/data inspector at a selected address.

## Done
- [x] Finding navigation indicator: show "⚑ i/N" in the status bar while cycling
      findings with . / , so position is visible. (uses existing findings state)
      — done: sb-finding span keyed off pickedFinding, accent-colored.
- [x] Findings count badge on the attack-surface rail icon.
      — done: .count pill bottom-right of the rail button, 99+ capped, hidden at zero.

## Notes
- Gates: cd knife-gui && npx tsc --noEmit; cd .. && cargo build -p knife-gui;
  cargo fmt --all --check; cargo clippy -p knife-gui -- -D warnings;
  cargo test -p reknife (only if reknife changed).
