import { forwardRef, useEffect, useImperativeHandle, useMemo, useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import type { Finding, IrLine, Line } from "../api";

/// What the parent can ask the listing to do. Scrolling has to go through the
/// virtualizer: off-screen lines are not in the document, so the old
/// `querySelector(...).scrollIntoView()` would silently do nothing.
export interface CodeViewHandle {
  scrollToLine: (index: number) => void;
}

// The centre pane: disassembly or decompiled pseudocode. A single click selects
// a line (so a note, or a type binding, can be attached to it); clicking an
// underlined operand, or double-clicking, follows the call or branch.
//
// Virtualized, because this is the longest list in the app: a large recovered
// function runs to thousands of lines and an instruction row is half a dozen
// elements, so drawing all of them cost tens of thousands of nodes and froze the
// window on open. Only what is on screen exists. Heights are measured rather
// than assumed — a disassembly row is one unwrapped line, but a pseudocode line
// wraps, so the two do not share a fixed height.
export const CodeView = forwardRef<
  CodeViewHandle,
  {
    tab: "disasm" | "pseudo";
    lines: Line[];
    ir: IrLine[];
    selected: string | null;
    irSelected: number | null;
    /// Line indices matching the find query, and which one is current.
    hits: number[];
    currentHit: number | null;
    /// Instruction address -> the audit finding at that call site, so a dangerous
    /// call is visible while reading, not only in the attack-surface list.
    findingAt: Map<string, Finding>;
    /// Instruction address -> kernel primitive at that call site (driver targets).
    /// A finding takes precedence, so this only marks primitives the audit did not
    /// already flag: MmMapIoSpace, __readmsr, token swaps and friends.
    primAt: Map<string, { api: string; severity: number }>;
    /// The picked finding's data flow: the instructions its dangerous argument
    /// came through, and the call it reaches. Marking these is what turns the
    /// audit's sentence about provenance into something you can read off the
    /// listing.
    trailAt: Map<string, "step" | "sink">;
    onSelect: (addr: string) => void;
    onSelectIr: (index: number) => void;
    onFollow: (selector: string) => void;
    onLineMenu: (index: number, at: { x: number; y: number }) => void;
    onFinding: (f: Finding) => void;
    onPrimitive: () => void;
    /// Called as the view approaches the last line, for a listing that continues
    /// past what has been fetched — the linear sweep reads on from here.
    onEndReached?: () => void;
  }
>(function CodeView(
  {
    tab,
    lines,
    ir,
    selected,
    irSelected,
    hits,
    currentHit,
    findingAt,
    primAt,
    trailAt,
    onSelect,
    onSelectIr,
    onFollow,
    onLineMenu,
    onFinding,
    onPrimitive,
    onEndReached,
  },
  ref,
) {
  const parentRef = useRef<HTMLDivElement>(null);
  const count = tab === "pseudo" ? ir.length : lines.length;

  const v = useVirtualizer({
    count,
    getScrollElement: () => parentRef.current,
    // 13px type at 1.5 line-height; `measureElement` corrects it per row.
    estimateSize: () => 20,
    overscan: 30,
  });

  useImperativeHandle(
    ref,
    () => ({
      scrollToLine: (index: number) => {
        if (index >= 0 && index < count) v.scrollToIndex(index, { align: "center" });
      },
    }),
    [v, count],
  );

  // A set, not a scan: this is consulted once per visible row, and `hits`
  // changes only when the find query does.
  const hitSet = useMemo(() => new Set(hits), [hits]);
  const hitClass = (i: number) =>
    hitSet.has(i) ? (currentHit === i ? " hit cur" : " hit") : "";

  // The linear view prefixes each address with its segment and pads it to the
  // pointer width, the way a disassembler does: `.text:0000000140001000`. The
  // width is whatever the widest address in the window needs — 16 hex digits
  // once any address runs past 32 bits, 8 otherwise — computed once here rather
  // than per row. Lines without a segment (the function and pseudocode views)
  // keep the bare address they always showed.
  const padWidth = useMemo(() => {
    for (const l of lines) {
      const a = (l as { addr?: string }).addr;
      if (a && a.replace(/^0x/, "").replace(/^0+/, "").length > 8) return 16;
    }
    return 8;
  }, [lines]);
  const gutterAddr = (addr: string, seg?: string) => {
    const bare = addr.replace(/^0x/, "");
    return seg ? `${seg}:${bare.padStart(padWidth, "0")}` : bare;
  };

  const row = (i: number) => {
    if (tab === "pseudo") {
      const l = ir[i];
      if (!l) return null;
      // Right-click is where the workbench lives: bind a type, name a field,
      // rename a variable, set the prototype. Selecting the line first is what
      // lets the keyboard equivalents (t / e / l / p) know what they act on.
      return (
        <div
          className={
            "ir" + (l.label ? " label" : "") + (irSelected === i ? " sel" : "") + hitClass(i)
          }
          onClick={() => onSelectIr(i)}
          onContextMenu={(e) => {
            e.preventDefault();
            onSelectIr(i);
            onLineMenu(i, { x: e.clientX, y: e.clientY });
          }}
        >
          {l.text || " "}
        </div>
      );
    }

    const l = lines[i];
    if (!l) return null;
    if (l.kind === "label") {
      return (
        <div className={"ln" + hitClass(i)}>
          <span className="gutter" />
          <span className="label">{l.text}</span>
        </div>
      );
    }
    if (l.kind === "section") {
      return (
        <div className={"ln section-band " + (l.code === "code" ? "is-code" : "is-data")}>
          <span className="sb-name">{l.name}</span>
          <span className="sb-meta">
            {l.code}
            {l.perms ? ` · ${l.perms}` : ""} · {l.range} · {l.size}
          </span>
        </div>
      );
    }
    if (l.kind === "sub") {
      return (
        <div className="ln sub-banner" onClick={() => onSelect(l.addr)}>
          <span className="sub-name">{l.name}</span>
          <span className="sub-meta">{l.meta}</span>
        </div>
      );
    }
    if (l.kind === "data") {
      return (
        <div className={"ln" + hitClass(i)}>
          <span className={"gutter" + (l.seg ? " seg" : "")}>{gutterAddr(l.addr, l.seg)}</span>
          <span className="ops">{l.text}</span>
        </div>
      );
    }
    const finding = findingAt.get(l.addr);
    const prim = finding ? undefined : primAt.get(l.addr);
    const flow = trailAt.get(l.addr);
    return (
      <div
        className={
          "ln selectable" +
          (l.addr === selected ? " sel" : "") +
          hitClass(i) +
          (finding ? " danger s" + Math.min(finding.severity, 3) : "") +
          (prim ? " kprim" : "") +
          (flow ? " taint " + flow : "")
        }
        onClick={() => onSelect(l.addr)}
        onDoubleClick={() => l.target && onFollow(l.target)}
      >
        <span className={"gutter" + (l.seg ? " seg" : "")}>
          {flow && (
            <i
              className="flowmark"
              title={
                flow === "sink"
                  ? "the dangerous call this data reaches"
                  : "the tainted argument passes through here"
              }
            >
              {flow === "sink" ? "▼" : "│"}
            </i>
          )}
          {gutterAddr(l.addr, l.seg)}
        </span>
        <span className="mnem">{l.mnemonic}</span>
        {l.target ? (
          <span className="ops">
            <span
              className="target"
              onClick={(e) => {
                e.stopPropagation();
                onFollow(l.target!);
              }}
            >
              {l.operands}
            </span>
          </span>
        ) : (
          <span className="ops">{l.operands}</span>
        )}
        {l.annot && <span className={"annot " + l.annot.kind}>; {l.annot.text}</span>}
        {finding && (
          <span
            className="danger-flag"
            title={`${finding.pattern}: ${finding.detail}`}
            onClick={(e) => {
              e.stopPropagation();
              onFinding(finding);
            }}
          >
            {finding.severity >= 3 ? "⚑ high" : finding.severity >= 2 ? "⚑ med" : "⚑"}
          </span>
        )}
        {prim && (
          <span
            className="kprim-flag"
            title={`kernel primitive: ${prim.api}`}
            onClick={(e) => {
              e.stopPropagation();
              onPrimitive();
            }}
          >
            ⎈ {prim.api}
          </span>
        )}
      </div>
    );
  };

  const items = v.getVirtualItems();
  // Ask for more once the end is in sight rather than at it, so the next window
  // is usually there before the scroll arrives.
  const lastShown = items.length ? items[items.length - 1].index : 0;
  useEffect(() => {
    if (onEndReached && count > 0 && lastShown >= count - 12) onEndReached();
  }, [onEndReached, lastShown, count]);

  return (
    <div className="code" ref={parentRef}>
      <div style={{ height: v.getTotalSize(), position: "relative" }}>
        {items.map((item) => (
          <div
            key={item.key}
            data-index={item.index}
            ref={v.measureElement}
            // `max-content` with a 100% floor: a row has to reach the full width
            // of the pane so a selected or tainted line is highlighted all the
            // way across, and has to grow past it when the instruction is longer
            // than the pane, so the highlight follows the text rather than
            // stopping at the fold when the listing is scrolled sideways.
            style={{
              position: "absolute",
              top: 0,
              left: 0,
              minWidth: "100%",
              width: "max-content",
              transform: `translateY(${item.start}px)`,
            }}
          >
            {row(item.index)}
          </div>
        ))}
      </div>
    </div>
  );
});
