import { useMemo, useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import type { BookmarkRow, FactRow } from "../api";

type Item =
  | { type: "head"; text: string }
  | { type: "mark"; row: BookmarkRow }
  | { type: "row"; row: FactRow };

const GROUPS: Array<[FactRow["kind"], string]> = [
  ["prototype", "PROTOTYPES"],
  ["structure", "STRUCTURES"],
  ["binding", "BINDINGS"],
  ["variable", "VARIABLES"],
];

/**
 * Everything you have told this database: prototypes, structure layouts, type
 * bindings and renamed variables — plus the bookmarks you have pinned.
 *
 * This is the inventory of work that is *not* derived from the bytes. The rest
 * of the window can be recomputed from the file at any time; none of this can,
 * which is the reason to be able to see it in one place.
 */
export function FactsList({
  rows,
  marks,
  onJump,
  onUnmark,
}: {
  rows: FactRow[];
  marks: BookmarkRow[];
  onJump: (addr: string) => void;
  onUnmark: (addr: string) => void;
}) {
  const items = useMemo<Item[]>(() => {
    const out: Item[] = [];
    if (marks.length) {
      out.push({ type: "head", text: `BOOKMARKS (${marks.length})` });
      for (const m of [...marks].sort((a, b) => (a.addr > b.addr ? 1 : -1)))
        out.push({ type: "mark", row: m });
    }
    for (const [kind, title] of GROUPS) {
      const group = rows.filter((r) => r.kind === kind);
      if (!group.length) continue;
      out.push({ type: "head", text: `${title} (${group.length})` });
      for (const row of group) out.push({ type: "row", row });
    }
    return out;
  }, [rows, marks]);

  const parentRef = useRef<HTMLDivElement>(null);
  const v = useVirtualizer({
    count: items.length,
    getScrollElement: () => parentRef.current,
    estimateSize: (i) => (items[i].type === "head" ? 24 : 22),
    overscan: 16,
  });

  if (!rows.length && !marks.length) {
    return (
      <div className="list">
        <div className="empty-hint">
          nothing recorded yet
          <br />
          <span>bind a type, set a prototype, or press m to pin an address</span>
        </div>
      </div>
    );
  }

  return (
    <div className="list" ref={parentRef}>
      <div style={{ height: v.getTotalSize(), position: "relative" }}>
        {v.getVirtualItems().map((item) => {
          const it = items[item.index];
          const style = {
            position: "absolute" as const,
            top: 0,
            left: 0,
            right: 0,
            height: item.size,
            transform: `translateY(${item.start}px)`,
          };
          if (it.type === "head") {
            return (
              <div key={item.index} style={style} className="sym-module">
                {it.text}
              </div>
            );
          }
          if (it.type === "mark") {
            return (
              <div
                key={item.index}
                style={style}
                className="fn-row"
                title={`${it.row.label ? it.row.label + "  " : ""}${it.row.addr}`}
                onClick={() => onJump(it.row.addr)}
              >
                <span className="nm mark-flag">⚑</span>
                <span className="nm">{it.row.label || it.row.addr}</span>
                <span
                  className="fact-detail"
                  onClick={(e) => {
                    e.stopPropagation();
                    onUnmark(it.row.addr);
                  }}
                  title="remove bookmark"
                >
                  ✕
                </span>
              </div>
            );
          }
          const r = it.row;
          return (
            <div
              key={item.index}
              style={style}
              className={"fn-row" + (r.addr ? "" : " dim")}
              title={`${r.name}  ${r.detail}`}
              onClick={() => r.addr && onJump(r.addr)}
            >
              <span className="nm">{r.name}</span>
              <span className="fact-detail">{r.detail}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
