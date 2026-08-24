import { useMemo, useRef, useState } from "react";
import type { Overview, OverviewBucket } from "../api";

// The navigator band: a full-width, always-on overview of the entire image.
// Each column is one bucket the backend sampled — coloured by entropy, striped
// by section (code vs data), and marked where audit findings land. A caret
// tracks where you are; clicking seeks there. It is IDA's navigator bar, plus
// knife's security signal.

// Entropy ramp, tuned to the same thresholds the detail panel uses for its
// per-section bars so the two read the same: calm below 6.5, amber past 6.5,
// red past 7.2 (of 8) — the packed/encrypted band.
function entColor(e: number): string {
  if (e >= 7.2) return "var(--critical)";
  if (e >= 6.5) return "var(--amber)";
  if (e >= 5.0) return "var(--mint)";
  if (e >= 3.0) return "#2f6f57";
  return "#262121";
}

function sevColor(s: number): string {
  return s >= 3 ? "var(--critical)" : s === 2 ? "var(--amber)" : "var(--mint)";
}

/// A contiguous run of buckets in the same section, for the label row, the
/// code/data stripe, and the boundary separators.
interface Run {
  start: number;
  end: number; // exclusive
  name: string | null;
  code: boolean;
}

function runsOf(buckets: OverviewBucket[]): Run[] {
  const runs: Run[] = [];
  for (let i = 0; i < buckets.length; i++) {
    const b = buckets[i];
    const last = runs[runs.length - 1];
    if (last && last.name === b.section && last.code === b.code) {
      last.end = i + 1;
    } else {
      runs.push({ start: i, end: i + 1, name: b.section, code: b.code });
    }
  }
  return runs;
}

export function NavigatorBand({
  overview,
  current,
  orientation = "horizontal",
  onSeek,
}: {
  overview: Overview | null;
  /// Current/selected virtual address (hex), so the caret tracks navigation.
  current: string | null;
  /// Which way the file runs. Vertical is a column down the right edge, where
  /// the strip gets the window's height instead of its width.
  orientation?: "horizontal" | "vertical";
  /// Seek to a virtual address — the parent opens the function or falls back to
  /// the hex inspector for a data region.
  onSeek: (va: string) => void;
}) {
  const ref = useRef<SVGSVGElement>(null);
  const [hover, setHover] = useState<number | null>(null);
  const vert = orientation === "vertical";

  // The shapes below are described in "along the file" and "across the strip"
  // terms, and these two turn that into x/y. One set of rectangles then serves
  // both orientations, instead of the whole picture being written twice.
  const box = (along: number, cross: number, alongLen: number, crossLen: number) =>
    vert
      ? { x: cross, y: along, width: crossLen, height: alongLen }
      : { x: along, y: cross, width: alongLen, height: crossLen };
  const rule = (along: number) =>
    vert
      ? { x1: 0, x2: 100, y1: along, y2: along }
      : { x1: along, x2: along, y1: 0, y2: 100 };

  const buckets = overview?.buckets ?? [];
  const n = buckets.length;
  const runs = useMemo(() => runsOf(buckets), [buckets]);

  // The caret bucket: the last mapped bucket whose address is at or before the
  // current one. BigInt compare — a kernel address exceeds JS's safe integer.
  const caret = useMemo(() => {
    if (!current || n === 0) return null;
    let cur: bigint;
    try {
      cur = BigInt(current);
    } catch {
      return null;
    }
    let best: number | null = null;
    for (let i = 0; i < n; i++) {
      const va = buckets[i].va;
      if (!va) continue;
      let v: bigint;
      try {
        v = BigInt(va);
      } catch {
        continue;
      }
      if (v <= cur) best = i;
      else break;
    }
    return best;
  }, [current, buckets, n]);

  if (!overview || n === 0) return null;

  const idxAt = (e: { clientX: number; clientY: number }): number => {
    const rect = ref.current!.getBoundingClientRect();
    const r = vert
      ? (e.clientY - rect.top) / rect.height
      : (e.clientX - rect.left) / rect.width;
    return Math.min(n - 1, Math.max(0, Math.floor(r * n)));
  };

  // Seek to the clicked bucket, or the nearest mapped one if the click lands on
  // an unmapped stretch (headers, padding, overlay).
  const seek = (i: number) => {
    for (let d = 0; d < n; d++) {
      const a = buckets[i + d];
      if (a?.va) return onSeek(a.va);
      const b = buckets[i - d];
      if (b?.va) return onSeek(b.va);
    }
  };

  const caretW = Math.max(1, n / 240);
  const hb = hover !== null ? buckets[hover] : null;
  const kb = (off: number) => (off / 1024).toFixed(off >= 1024 * 1024 ? 0 : 1);

  return (
    <div className={"navband" + (vert ? " vertical" : "")}>
      {/* Captions only where there is width for them. A column is too narrow to
          hold a section name, and the tooltip already gives it on hover.
          Every run is a tile in one flex row, so the captions tile the width
          exactly and each centres over its own section. (Absolute positioning
          let a skipped run leave the others floating, which read as misplaced.)
          A run too narrow to hold its name keeps its space but shows nothing. */}
      {!vert && (
        <div className="navband-labels">
          {runs.map((run, i) => {
            const w = ((run.end - run.start) / n) * 100;
            return (
              <span
                key={i}
                className={"navband-label" + (run.code ? " code" : "")}
                style={{ flex: `0 0 ${w}%` }}
                title={run.name ?? undefined}
              >
                {w >= 3.5 && run.name ? run.name : ""}
              </span>
            );
          })}
        </div>
      )}

      <svg
        ref={ref}
        className="navband-track"
        viewBox={vert ? `0 0 100 ${n}` : `0 0 ${n} 100`}
        preserveAspectRatio="none"
        onMouseMove={(e) => setHover(idxAt(e))}
        onMouseLeave={() => setHover(null)}
        onClick={(e) => seek(idxAt(e))}
      >
        {/* entropy body */}
        {buckets.map((b, i) => (
          <rect key={i} {...box(i, 8, 1.02, 92)} fill={entColor(b.entropy)} />
        ))}

        {/* code/data stripe down the leading edge */}
        {runs.map((run, i) => (
          <rect
            key={i}
            {...box(run.start, 0, run.end - run.start, 7)}
            fill={run.name ? (run.code ? "var(--accent)" : "var(--faint)") : "#201c1c"}
            opacity={run.code ? 0.85 : 0.5}
          />
        ))}

        {/* findings heat lane along the far edge */}
        {buckets.map((b, i) =>
          b.findings > 0 ? (
            <rect key={i} {...box(i, 80, 1.4, 20)} fill={sevColor(b.max_sev)} />
          ) : null,
        )}

        {/* section boundaries */}
        {runs.slice(1).map((run, i) => (
          <line
            key={i}
            {...rule(run.start)}
            stroke="var(--border)"
            strokeWidth={1}
            vectorEffect="non-scaling-stroke"
          />
        ))}

        {/* entry point tick */}
        {overview.entry !== null && (
          <line
            {...rule(overview.entry + 0.5)}
            stroke="var(--mint)"
            strokeWidth={1.5}
            strokeDasharray="2 2"
            vectorEffect="non-scaling-stroke"
          />
        )}

        {/* current-position caret */}
        {caret !== null && (
          <rect {...box(caret, 0, caretW, 100)} className="navband-caret" />
        )}
      </svg>

      {hb && (
        <div
          className="navband-tip"
          style={
            vert
              ? { top: `${Math.min(92, (hover! / n) * 100)}%`, right: "100%" }
              : { left: `${Math.min(88, (hover! / n) * 100)}%` }
          }
        >
          <b>{hb.section ?? "unmapped"}</b>
          {hb.code ? " · code" : hb.section ? " · data" : ""} · {kb(hb.off)} KB
          <br />
          entropy {hb.entropy.toFixed(2)}
          {hb.findings > 0 && ` · ${hb.findings} finding${hb.findings === 1 ? "" : "s"}`}
          {hb.va && <span className="navband-tip-va"> · {hb.va}</span>}
        </div>
      )}
    </div>
  );
}
