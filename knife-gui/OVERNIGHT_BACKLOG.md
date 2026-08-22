# knife-gui overnight backlog

Autonomous improvement queue. Rules: one small focused commit per item, all gates
green before commit, authored bl4ckr0ss3 only (no AI attribution), static-only,
commit locally (do not push). Reuse existing backend data; avoid risky reknife
API changes.

## Queue (top = next)
(none — append new items below)

## Done
- [x] Finding navigation indicator: show "⚑ i/N" in the status bar while cycling
      findings with . / , so position is visible. (uses existing findings state)
      — done: sb-finding span keyed off pickedFinding, accent-colored.
- [x] Findings count badge on the attack-surface rail icon.
      — done: .count pill bottom-right of the rail button, 99+ capped, hidden at zero.
- [x] Copy actions: copy current address / function name to clipboard (keyboard + menu).
      — done: y copies selected/current address, Y copies function name; both also in
      the pseudocode context menu, with a copied toast.
- [x] Deeper IOCTL decode in the driver view: break CTL_CODE into device / function /
      method / access, shown per handler.
      — done: all four fields were already in the DTO; the row now shows
      dev/fn/method/access and tooltips the CTL_CODE() form.
- [x] Whole-program call graph: expose graphs::call_graph and add a navigable view.
      — done as a rooted closure: new call_graph command (graphs::call_graph with
      roots={current fn}, refused past 96 nodes) + a calls tab reusing the graph
      view; cards open the function on double-click.
- [x] Bookmarks: mark/unmark an address (IDA marks), persisted per binary, list panel.
      — done: m toggles a mark at the selected/current address; JSON sidecar in
      app-data keyed by target path (window furniture, kept out of reknife's db);
      listed in the facts panel, click jumps, ✕ removes.
- [x] Findings report export: write the ranked findings to a markdown file.
      — done: export_findings command writes the pane's ranked list (grade,
      pattern, api, function, address, reachability, explanation) via a save
      dialog; "export" action in the attack-surface panel head.
- [x] Section entropy in the detail panel (spot packed/encrypted regions).
      — done: mini entropy bar per section row, amber past 6.5 and red with a
      "compressed, encrypted, or packed?" hint past 7.2 of 8.
- [x] Hex/data inspector at a selected address.
      — done: h toggles a floating card at the selected/current address;
      new hex_dump command maps the vaddr through sections and formats
      16-byte rows with an ascii gutter; ‹ › page by 64 bytes, Esc closes.

## New items
- [x] Reachability proof inline: show the actual call chain from an entry point
      or export to a picked finding in the evidence pane (paths_to already
      accepts the sink address).
      — done: a "proof" row walks up to 3 chains from entry/exports to the sink
      on pick; hops are clickable, absence says so plainly.
- [x] Severity filter chips (H/M/L) on the attack-surface list.
      — done: toggleable H/M/L chips in the panel head; display-only, cycling
      and the statusbar position still walk the full ranked list.
- [ ] Severity filter chips (H/M/L) on the attack-surface list.
- [x] Driver view: primitives deep-link to pseudocode, not just the listing.
      — done: a "p" chip on each primitive row opens the first call site's
      function and lands on its pseudocode tab (decompile stays lazy).
- [x] Strings list: reference counts and jump-to-xref.
      — done: clicking a string's ref count opens its function and pins the
      xref pane to the literal (@ addr shown in the pane head); any navigation
      unpins. Row click still jumps as before.
- [x] Remember the last-used graph/calls tab per session restore.
      — done: knife.tab persisted on change and restored when the last target
      reopens; lazy fetches (pseudocode, call closure) fire as usual.

## Notes
- Gates: cd knife-gui && npx tsc --noEmit; cd .. && cargo build -p knife-gui;
  cargo fmt --all --check; cargo clippy -p knife-gui -- -D warnings;
  cargo test -p reknife (only if reknife changed).
