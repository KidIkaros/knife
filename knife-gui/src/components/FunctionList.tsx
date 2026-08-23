import { useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import type { FnRow } from "../api";

// A large image recovers tens of thousands of functions, so the list is
// virtualized: only the visible rows exist in the DOM.
export function FunctionList({
  rows,
  current,
  risk,
  filter,
  onPick,
}: {
  rows: FnRow[];
  current: string | null;
  /// Function name -> highest finding severity it contains (3/2/1).
  risk: Map<string, number>;
  /// The query behind `rows`, so an empty result can say what did not match.
  filter?: string;
  onPick: (addr: string) => void;
}) {
  const parentRef = useRef<HTMLDivElement>(null);
  const v = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 22,
    overscan: 24,
  });

  // A filter that matches nothing used to leave the pane blank, which reads as a
  // broken window rather than an answer.
  if (!rows.length) {
    return (
      <div className="list">
        <div className="empty-hint">
          {filter ? `no function matches "${filter}"` : "no functions recovered"}
          <br />
          <span>{filter ? "clear the filter to see them all" : "the image may be data only"}</span>
        </div>
      </div>
    );
  }

  return (
    <div className="list" ref={parentRef}>
      <div style={{ height: v.getTotalSize(), position: "relative" }}>
        {v.getVirtualItems().map((item) => {
          const f = rows[item.index];
          return (
            <div
              key={f.addr}
              className={"fn-row" + (f.addr === current ? " sel" : "")}
              style={{
                position: "absolute",
                top: 0,
                left: 0,
                right: 0,
                height: item.size,
                transform: `translateY(${item.start}px)`,
              }}
              onClick={() => onPick(f.addr)}
              title={`${f.name}  ${f.blocks} blocks  ${f.size} bytes`}
            >
              <span className="addr">{f.addr.replace("0x", "")}</span>
              {(() => {
                const sev = risk.get(f.name);
                return sev ? (
                  <span
                    className={"risk-dot s" + Math.min(sev, 3)}
                    title={
                      sev >= 3 ? "contains a high-risk finding" : "contains a finding"
                    }
                  />
                ) : (
                  <span className="risk-dot none" />
                );
              })()}
              <span className={"nm" + (f.named ? " named" : "")}>{f.name}</span>
              <span className="refs">{f.incoming}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
