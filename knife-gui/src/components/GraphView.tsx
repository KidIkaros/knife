import { useEffect, useMemo, useRef, useState } from "react";
import type { Cfg, CfgNode } from "../api";

// Card geometry, in graph units. Blocks are laid out top-down in layers, the
// way a control-flow graph is read.
const HEAD_H = 20;
const LINE_H = 14;
const PAD_Y = 8;
const PAD_X = 10;
const GAP_X = 44;
const GAP_Y = 56;
// Font sizes must match `.block .bline` / `.bhead` in the stylesheet: the widths
// below are computed from them rather than measured.
const BODY_PX = 10.5;
const HEAD_PX = 11;
// The face is monospace, so a glyph is a fixed fraction of the size and a line's
// width is arithmetic. Measuring would mean a canvas or a layout pass per card.
const CHAR_W = 0.6;
// A card never grows past this, however long one operand runs; past it a line is
// cut. Without a ceiling a single pathological instruction stretches its whole
// layer and pushes everything else off screen.
const MAX_W = 900;
// Purely a backstop against a degenerate block emitting thousands of text nodes.
// A real basic block is nowhere near this, so nothing is normally truncated.
const MAX_LINES = 200;
// Wrap a layer wider than this many cards into a grid (call closures fan wide).
const MAX_ROW = 6;

interface Placed {
  node: CfgNode;
  x: number;
  y: number;
  w: number;
  h: number;
}

/// How the line reads, as one string — what its width is measured against.
function lineText(l: CfgNode["insns"][number]): string {
  if (l.kind === "insn") {
    const annot = l.annot ? `  ; ${l.annot.text}` : "";
    return `${l.mnemonic.padEnd(7)} ${l.operands}${annot}`;
  }
  return l.text;
}

function cardHeight(n: CfgNode) {
  return HEAD_H + Math.min(n.insns.length, MAX_LINES) * LINE_H + PAD_Y;
}

/// Wide enough for its own widest line and no wider. The header carries the
/// address and the block's size at a larger size than the body, so both are
/// measured and the larger wins.
function cardWidth(n: CfgNode) {
  let body = 0;
  for (let i = 0; i < n.insns.length && i < MAX_LINES; i++) {
    body = Math.max(body, lineText(n.insns[i]).length);
  }
  const head = n.addr.length + `${n.count}i · ${n.bytes}b`.length + 4;
  const px = Math.max(body * BODY_PX, head * HEAD_PX) * CHAR_W;
  return Math.min(MAX_W, Math.max(120, Math.round(px) + PAD_X * 2));
}

/**
 * Place blocks in top-down layers.
 *
 * The layer is the *longest* forward distance from the entry, not the shortest.
 * That distinction matters: with shortest-path layering, a block reachable both
 * directly from the entry and by falling through its sibling lands in the same
 * layer as that sibling, and the edge between them is drawn sideways — through
 * the card, as it turns out. Taking the longest path guarantees every forward
 * edge descends at least one layer, so control genuinely reads downward and no
 * edge has to cross a block to arrive.
 *
 * Back edges are excluded from the walk (a loop would otherwise push its own
 * target down forever) and drawn afterwards as returns. Blocks nothing reaches
 * — exception handlers, code the recovery could not attribute — go in a final
 * layer of their own rather than being dropped.
 */
function layout(cfg: Cfg) {
  const byId = new Map(cfg.nodes.map((n) => [n.id, n]));
  const forward = new Map<string, string[]>();
  const indeg = new Map<string, number>();
  for (const n of cfg.nodes) indeg.set(n.id, 0);
  for (const e of cfg.edges) {
    if (e.back || !byId.has(e.from) || !byId.has(e.to)) continue;
    if (!forward.has(e.from)) forward.set(e.from, []);
    forward.get(e.from)!.push(e.to);
    indeg.set(e.to, (indeg.get(e.to) ?? 0) + 1);
  }

  // Longest-path layering over the acyclic part, by Kahn's topological order.
  const layer = new Map<string, number>();
  const queue: string[] = [];
  for (const n of cfg.nodes) {
    if ((indeg.get(n.id) ?? 0) === 0) {
      layer.set(n.id, 0);
      queue.push(n.id);
    }
  }
  const remaining = new Map(indeg);
  while (queue.length) {
    const id = queue.shift()!;
    const d = layer.get(id) ?? 0;
    for (const next of forward.get(id) ?? []) {
      layer.set(next, Math.max(layer.get(next) ?? 0, d + 1));
      const left = (remaining.get(next) ?? 1) - 1;
      remaining.set(next, left);
      if (left === 0) queue.push(next);
    }
  }
  // Anything the topological pass could not settle (a cycle the back-edge flag
  // did not cover) still needs a home.
  const deepest = Math.max(-1, ...[...layer.values()]);
  for (const n of cfg.nodes) if (!layer.has(n.id)) layer.set(n.id, deepest + 1);

  // Group by layer, ordered by address so the picture is stable across runs.
  const layers = new Map<number, CfgNode[]>();
  for (const n of cfg.nodes) {
    const d = layer.get(n.id)!;
    if (!layers.has(d)) layers.set(d, []);
    layers.get(d)!.push(n);
  }
  for (const row of layers.values()) row.sort((a, b) => (a.addr < b.addr ? -1 : 1));

  const placed = new Map<string, Placed>();
  let y = 0;
  let width = 0;
  for (const d of [...layers.keys()].sort((a, b) => a - b)) {
    const row = layers.get(d)!;
    // A control-flow layer is a handful of blocks and lays out as one row. A
    // call closure, though, can drop dozens of functions into a single layer,
    // which as one row becomes an unreadable horizontal smear. Wrap a wide
    // layer into a near-square grid instead; narrow layers are unchanged, so
    // ordinary CFGs look exactly as before.
    const cols = row.length > MAX_ROW ? Math.ceil(Math.sqrt(row.length)) : row.length;
    const cellH = Math.max(...row.map(cardHeight));
    // Cards are as wide as their contents, so a row is laid out by walking a
    // cursor rather than by multiplying a fixed pitch. Each sub-row is measured
    // first so it can be centred on its own width.
    const subRows = Math.ceil(row.length / cols);
    for (let sub = 0; sub < subRows; sub++) {
      const slice = row.slice(sub * cols, sub * cols + cols);
      const widths = slice.map(cardWidth);
      const rowW = widths.reduce((a, b) => a + b, 0) + Math.max(0, slice.length - 1) * GAP_X;
      width = Math.max(width, rowW);
      let x = -rowW / 2;
      slice.forEach((n, i) => {
        placed.set(n.id, {
          node: n,
          x,
          y: y + sub * (cellH + GAP_Y),
          w: widths[i],
          h: cardHeight(n),
        });
        x += widths[i] + GAP_X;
      });
    }
    y += subRows * (cellH + GAP_Y) + GAP_Y;
  }
  return { placed, width: width + 80, height: y };
}

const EDGE_COLOR: Record<string, string> = {
  true: "var(--mint)",
  false: "var(--critical)",
  flow: "var(--faint)",
  // call-graph edges: the whole point of that picture, so they read strongly
  call: "var(--mint)",
};

export function GraphView({
  cfg,
  onOpenBlock,
  onExport,
}: {
  cfg: Cfg | null;
  onOpenBlock: (addr: string) => void;
  /** Offered when set: write the graph out as Graphviz. */
  onExport?: () => void;
}) {
  const wrap = useRef<HTMLDivElement>(null);
  const [view, setView] = useState({ x: 0, y: 0, k: 1 });
  const drag = useRef<{ x: number; y: number; vx: number; vy: number } | null>(null);
  const [sel, setSel] = useState<string | null>(null);

  const model = useMemo(() => (cfg ? layout(cfg) : null), [cfg]);

  // Which edges leave each node and which arrive at it, in the order their ports
  // should sit left to right. Outgoing edges are ordered by where they are
  // going and incoming ones by where they came from, so two edges never swap
  // sides and cross each other at the card itself.
  const ports = useMemo(() => {
    const out = new Map<string, number[]>();
    const inn = new Map<string, number[]>();
    if (!cfg || !model) return { out, in: inn };
    const add = (m: Map<string, number[]>, key: string, i: number) => {
      const list = m.get(key);
      if (list) list.push(i);
      else m.set(key, [i]);
    };
    cfg.edges.forEach((e, i) => {
      if (!model.placed.has(e.from) || !model.placed.has(e.to)) return;
      add(out, e.from, i);
      add(inn, e.to, i);
    });
    const centre = (id: string) => {
      const p = model.placed.get(id)!;
      return p.x + p.w / 2;
    };
    for (const list of out.values()) {
      list.sort((x, y) => centre(cfg.edges[x].to) - centre(cfg.edges[y].to));
    }
    for (const list of inn.values()) {
      list.sort((x, y) => centre(cfg.edges[x].from) - centre(cfg.edges[y].from));
    }
    return { out, in: inn };
  }, [cfg, model]);

  // Frame the graph whenever a new function is shown.
  const fit = useMemo(
    () => () => {
      if (!model || !wrap.current) return;
      const box = wrap.current.getBoundingClientRect();
      const k = Math.min(1, Math.min(box.width / model.width, box.height / (model.height + 40)) * 0.92);
      setView({ x: box.width / 2, y: 24, k: Math.max(0.12, k) });
    },
    [model],
  );
  useEffect(() => {
    fit();
  }, [fit]);

  // Wheel-zoom via a native, non-passive listener. React registers onWheel as
  // passive, so its preventDefault is ignored and the wheel scrolls the pane
  // instead of zooming; attaching directly lets preventDefault take. Re-attaches
  // when the graph mounts (model goes from null to set).
  useEffect(() => {
    const el = wrap.current;
    if (!el) return;
    const handler = (e: WheelEvent) => {
      e.preventDefault();
      const box = el.getBoundingClientRect();
      const mx = e.clientX - box.left;
      const my = e.clientY - box.top;
      setView((v) => {
        const k = Math.min(3, Math.max(0.08, v.k * (e.deltaY < 0 ? 1.12 : 1 / 1.12)));
        // Keep the point under the cursor fixed while zooming.
        return { k, x: mx - ((mx - v.x) * k) / v.k, y: my - ((my - v.y) * k) / v.k };
      });
    };
    el.addEventListener("wheel", handler, { passive: false });
    return () => el.removeEventListener("wheel", handler);
  }, [model]);

  if (!cfg || !model) {
    return <div className="graph-empty">no function open</div>;
  }

  return (
    <div className="graph-wrap" ref={wrap}>
      <div className="graph-tools">
        <button onClick={() => setView((v) => ({ ...v, k: Math.min(3, v.k * 1.2) }))} title="Zoom in">
          +
        </button>
        <button onClick={() => setView((v) => ({ ...v, k: Math.max(0.08, v.k / 1.2) }))} title="Zoom out">
          −
        </button>
        <button onClick={fit} title="Fit">
          ⤢
        </button>
        {onExport && (
          <button onClick={onExport} title="Export as Graphviz (.dot)">
            dot
          </button>
        )}
        <span className="zoom">{Math.round(view.k * 100)}%</span>
      </div>

      <svg
        className="graph"
        onMouseDown={(e) => {
          drag.current = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y };
        }}
        onMouseMove={(e) => {
          if (!drag.current) return;
          const d = drag.current;
          setView((v) => ({ ...v, x: d.vx + (e.clientX - d.x), y: d.vy + (e.clientY - d.y) }));
        }}
        onMouseUp={() => (drag.current = null)}
        onMouseLeave={() => (drag.current = null)}
      >
        <defs>
          {["true", "false", "flow", "back", "call"].map((k) => (
            <marker
              key={k}
              id={`arrow-${k}`}
              viewBox="0 0 10 10"
              refX="9"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" fill={k === "back" ? "var(--amber)" : EDGE_COLOR[k]} />
            </marker>
          ))}
        </defs>

        <g transform={`translate(${view.x},${view.y}) scale(${view.k})`}>
          {cfg.edges.map((e, i) => {
            const a = model.placed.get(e.from);
            const b = model.placed.get(e.to);
            if (!a || !b) return null;
            const color = e.back ? "var(--amber)" : EDGE_COLOR[e.kind] ?? "var(--faint)";
            // Leave and arrive at the edge's own port rather than the middle of
            // the card. Every edge used to start and end at one point, so a
            // block with two successors showed them departing from the same
            // place and a block with several predecessors had them all converge
            // on one — which says nothing about which branch is which.
            const out = ports.out.get(e.from);
            const inp = ports.in.get(e.to);
            const oi = out ? out.indexOf(i) : -1;
            const ii = inp ? inp.indexOf(i) : -1;
            const x1 = a.x + (out && oi >= 0 ? (a.w * (oi + 1)) / (out.length + 1) : a.w / 2);
            const y1 = a.y + a.h;
            const x2 = b.x + (inp && ii >= 0 ? (b.w * (ii + 1)) / (inp.length + 1) : b.w / 2);
            const y2 = b.y;
            // A back edge loops out to the side so it never hides under the
            // forward path it returns along. A forward edge that skips layers
            // bows outward by the same logic — otherwise it would cross every
            // card in between.
            const skips = Math.abs(b.y - (a.y + a.h)) > GAP_Y * 1.5;
            const bow = skips ? (x2 >= x1 ? 1 : -1) * (Math.max(a.w, b.w) / 2 + GAP_X) : 0;
            const loop = Math.max(a.w, b.w) / 2 + 120;
            const d = e.back
              ? `M ${x1} ${y1} C ${x1 + loop} ${y1 + 30}, ${x2 + loop} ${y2 - 30}, ${x2} ${y2}`
              : `M ${x1} ${y1} C ${x1 + bow} ${y1 + GAP_Y / 2}, ${x2 + bow} ${y2 - GAP_Y / 2}, ${x2} ${y2}`;
            return (
              <path
                key={i}
                d={d}
                className="edge"
                stroke={color}
                strokeDasharray={e.back ? "5 4" : undefined}
                markerEnd={`url(#arrow-${e.back ? "back" : e.kind})`}
              />
            );
          })}

          {[...model.placed.values()].map((p) => (
            <g
              key={p.node.id}
              transform={`translate(${p.x},${p.y})`}
              className={
                "block" + (p.node.kind === "entry" ? " entry" : "") + (sel === p.node.id ? " sel" : "")
              }
              onClick={() => setSel(p.node.id)}
              onDoubleClick={() => onOpenBlock(p.node.addr)}
            >
              <rect width={p.w} height={p.h} rx="7" />
              <text className="bhead" x="10" y="14">
                {p.node.kind === "entry"
                  ? "entry · "
                  : p.node.kind === "import"
                    ? "imp · "
                    : ""}
                {p.node.addr.replace("0x", "")}
              </text>
              <text className="bmeta" x={p.w - 10} y="14" textAnchor="end">
                {p.node.count}i · {p.node.bytes}b
              </text>
              {p.node.insns.slice(0, MAX_LINES).map((l, i) => {
                const y = HEAD_H + 11 + i * LINE_H;
                if (l.kind !== "insn") {
                  return (
                    <text key={i} className="bline" x={PAD_X} y={y}>
                      {l.text}
                    </text>
                  );
                }
                // The same runs the listing uses, so the two views read alike.
                // `xml:space` keeps the padding that lines the operands up.
                return (
                  <text key={i} className="bline" x={PAD_X} y={y} xmlSpace="preserve">
                    <tspan className="g-mnem">{l.mnemonic.padEnd(7)}</tspan>
                    <tspan className={l.target ? "g-target" : "g-ops"}>
                      {" "}
                      {l.operands}
                    </tspan>
                    {l.annot && (
                      <tspan className={"g-annot " + l.annot.kind}> ; {l.annot.text}</tspan>
                    )}
                  </text>
                );
              })}
              {p.node.insns.length > MAX_LINES && (
                <text className="bmore" x="10" y={HEAD_H + 11 + MAX_LINES * LINE_H}>
                  +{p.node.insns.length - MAX_LINES} more
                </text>
              )}
            </g>
          ))}
        </g>
      </svg>
    </div>
  );
}
