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
// The column a routed edge reserves when it passes through a layer.
const LANE_W = 12;
// How much a corner is rounded where an edge turns.
const BEND = 6;
// Wrap a layer wider than this many cards into a grid (call closures fan wide).
const MAX_ROW = 6;

/// A path through the given points, turning at right angles with the corners
/// eased off. Consecutive points on the same line are dropped first, so a
/// straight run stays one segment and no corner is drawn where there is no turn.
function orthPath(pts: Array<{ x: number; y: number }>): string {
  const p = pts.filter((q, i) => i === 0 || q.x !== pts[i - 1].x || q.y !== pts[i - 1].y);
  for (let i = 1; i < p.length - 1; ) {
    const a = p[i - 1];
    const b = p[i];
    const c = p[i + 1];
    if ((a.x === b.x && b.x === c.x) || (a.y === b.y && b.y === c.y)) p.splice(i, 1);
    else i++;
  }
  if (p.length < 2) return "";
  let d = `M ${p[0].x} ${p[0].y}`;
  for (let i = 1; i < p.length - 1; i++) {
    const prev = p[i - 1];
    const cur = p[i];
    const next = p[i + 1];
    const r1 = Math.min(BEND, Math.hypot(cur.x - prev.x, cur.y - prev.y) / 2);
    const r2 = Math.min(BEND, Math.hypot(next.x - cur.x, next.y - cur.y) / 2);
    const inX = cur.x + Math.sign(prev.x - cur.x) * r1;
    const inY = cur.y + Math.sign(prev.y - cur.y) * r1;
    const outX = cur.x + Math.sign(next.x - cur.x) * r2;
    const outY = cur.y + Math.sign(next.y - cur.y) * r2;
    d += ` L ${inX} ${inY} Q ${cur.x} ${cur.y} ${outX} ${outY}`;
  }
  const last = p[p.length - 1];
  d += ` L ${last.x} ${last.y}`;
  return d;
}

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
/// A place in the grid: a real block, or a stand-in an edge passes through.
///
/// Long edges get stand-ins in every layer they cross. Without them a card and
/// an edge are not competing for the same space — the edge simply flies over the
/// row and lands wherever it likes, which is how a graph turns into a knot. A
/// stand-in occupies a slot like anything else, so the row opens a gap for the
/// edge and the edge runs straight down it.
interface Slot {
  id: string;
  node: CfgNode | null;
  layer: number;
  x: number;
  w: number;
  y: number;
  h: number;
}

/// Order each layer so that as few edges cross as possible.
///
/// Sorting by address, which is what this did, is stable but meaningless: two
/// blocks that branch to the same place can sit at opposite ends of their row
/// and drag their edges across everything in between. The barycentre heuristic
/// instead puts each slot near the average position of what it connects to, and
/// sweeping down then up a few times settles it. It is not optimal — minimising
/// crossings exactly is NP-hard — but it is what every layered graph drawer
/// uses, and the difference is the difference between a diagram and a knot.
function order(layers: string[][], pred: Map<string, string[]>, succ: Map<string, string[]>) {
  const pos = new Map<string, number>();
  const index = () => layers.forEach((row) => row.forEach((id, i) => pos.set(id, i)));
  index();
  const mean = (ids: string[]) => {
    const known = ids.map((id) => pos.get(id)).filter((p): p is number => p !== undefined);
    return known.length ? known.reduce((a, b) => a + b, 0) / known.length : null;
  };
  for (let pass = 0; pass < 4; pass++) {
    const down = pass % 2 === 0;
    const seq = down
      ? layers.map((_, i) => i).slice(1)
      : layers.map((_, i) => i).slice(0, -1).reverse();
    for (const li of seq) {
      const row = layers[li];
      const key = new Map<string, number>();
      const was = new Map<string, number>();
      row.forEach((id, i) => {
        const m = mean((down ? pred.get(id) : succ.get(id)) ?? []);
        // A slot with nothing on that side keeps where it is, rather than
        // being swept to one end by a default.
        key.set(id, m ?? i);
        was.set(id, i);
      });
      // The tiebreak reads the order as it was before the sort began; asking the
      // array while it is being sorted would be both quadratic and unstable.
      row.sort((a, b) => key.get(a)! - key.get(b)! || was.get(a)! - was.get(b)!);
      index();
    }
  }
}

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

  // Every edge that crosses more than one layer gets a stand-in in each layer
  // between, so it reserves a column of its own instead of flying over the row.
  const rows: string[][] = [];
  const depth = Math.max(0, ...[...layer.values()]);
  for (let d = 0; d <= depth; d++) rows.push([]);
  for (const n of cfg.nodes) rows[layer.get(n.id)!].push(n.id);
  for (const row of rows) row.sort((a, b) => (byId.get(a)!.addr < byId.get(b)!.addr ? -1 : 1));

  const slots = new Map<string, Slot>();
  for (const n of cfg.nodes) {
    slots.set(n.id, {
      id: n.id,
      node: n,
      layer: layer.get(n.id)!,
      x: 0,
      w: cardWidth(n),
      y: 0,
      h: cardHeight(n),
    });
  }

  // A call closure is a different picture and wants a different arrangement. It
  // fans dozens of functions into one layer, which laid out as a single row is
  // an unreadable smear however well its edges are routed, so those layers wrap
  // into a near-square grid. The crossing and straightening passes below are
  // for control flow, where a layer is a handful of blocks and the shape of the
  // branching is the thing being read.
  if (cfg.nodes.some((n) => n.kind !== "entry" && n.kind !== "block")) {
    let gy = 0;
    let gw = 0;
    rows.forEach((row) => {
      const cols = row.length > MAX_ROW ? Math.ceil(Math.sqrt(row.length)) : row.length;
      const cellH = Math.max(0, ...row.map((id) => slots.get(id)!.h));
      const subRows = Math.ceil(row.length / Math.max(1, cols));
      for (let sub = 0; sub < subRows; sub++) {
        const slice = row.slice(sub * cols, sub * cols + cols);
        const widths = slice.map((id) => slots.get(id)!.w);
        const rowW = widths.reduce((a, b) => a + b, 0) + Math.max(0, slice.length - 1) * GAP_X;
        gw = Math.max(gw, rowW);
        let x = -rowW / 2;
        slice.forEach((id, i) => {
          const s = slots.get(id)!;
          s.x = x;
          s.y = gy + sub * (cellH + GAP_Y);
          x += widths[i] + GAP_X;
        });
      }
      gy += subRows * (cellH + GAP_Y) + GAP_Y;
    });
    const gplaced = new Map<string, Placed>();
    for (const s of slots.values()) {
      if (s.node) gplaced.set(s.id, { node: s.node, x: s.x, y: s.y, w: s.w, h: s.h });
    }
    return {
      placed: gplaced,
      slots,
      chains: new Map<number, string[]>(),
      width: gw + 80,
      height: gy,
    };
  }

  // The chain of slot ids each edge travels through, ends included.
  const chains = new Map<number, string[]>();
  cfg.edges.forEach((e, i) => {
    if (!byId.has(e.from) || !byId.has(e.to)) return;
    if (e.back) return;
    const a = layer.get(e.from)!;
    const b = layer.get(e.to)!;
    const chain = [e.from];
    for (let d = a + 1; d < b; d++) {
      const id = `d:${i}:${d}`;
      slots.set(id, { id, node: null, layer: d, x: 0, w: LANE_W, y: 0, h: 0 });
      rows[d].push(id);
      chain.push(id);
    }
    chain.push(e.to);
    chains.set(i, chain);
  });

  // Adjacency over the proper graph — every link now spans exactly one layer.
  const pred = new Map<string, string[]>();
  const succ = new Map<string, string[]>();
  const link = (u: string, v: string) => {
    (succ.get(u) ?? succ.set(u, []).get(u)!).push(v);
    (pred.get(v) ?? pred.set(v, []).get(v)!).push(u);
  };
  for (const chain of chains.values()) {
    for (let i = 0; i + 1 < chain.length; i++) link(chain[i], chain[i + 1]);
  }

  order(rows, pred, succ);

  // Layer bands: a row is as tall as its tallest card, and a stand-in fills the
  // band so a long edge is a straight vertical run rather than a series of jogs.
  const bandTop: number[] = [];
  const bandH: number[] = [];
  let y = 0;
  rows.forEach((row, d) => {
    const h = Math.max(0, ...row.map((id) => slots.get(id)!.h));
    bandTop[d] = y;
    bandH[d] = h;
    y += h + GAP_Y;
  });
  for (const s of slots.values()) {
    s.y = bandTop[s.layer];
    if (!s.node) s.h = bandH[s.layer];
  }

  // Pack each row, then pull slots toward what they connect to and re-pack.
  // Packing alone leaves an edge slanting across the gutter for no reason; the
  // pull is what makes a straight run of blocks actually line up.
  const pack = (row: string[]) => {
    let x = 0;
    for (const id of row) {
      const s = slots.get(id)!;
      s.x = Math.max(s.x, x);
      x = s.x + s.w + GAP_X;
    }
  };
  const centre = (id: string) => {
    const s = slots.get(id)!;
    return s.x + s.w / 2;
  };
  rows.forEach(pack);
  for (let pass = 0; pass < 6; pass++) {
    const down = pass % 2 === 0;
    const seq = down ? rows.map((_, i) => i) : rows.map((_, i) => i).reverse();
    for (const d of seq) {
      for (const id of rows[d]) {
        const near = (down ? pred.get(id) : succ.get(id)) ?? [];
        if (!near.length) continue;
        const want = near.reduce((a, b) => a + centre(b), 0) / near.length;
        const s = slots.get(id)!;
        s.x = want - s.w / 2;
      }
      // A pull can put two slots on top of each other. Separating them left to
      // right settles it *in the order the crossing pass chose* — re-sorting by
      // the new x would let a slot that was pulled hard jump its neighbour and
      // undo the very crossing that pass removed.
      let x = -Infinity;
      for (const id of rows[d]) {
        const s = slots.get(id)!;
        s.x = Math.max(s.x, x);
        x = s.x + s.w + GAP_X;
      }
    }
  }

  // Centre the whole picture on x = 0.
  let lo = Infinity;
  let hi = -Infinity;
  for (const s of slots.values()) {
    lo = Math.min(lo, s.x);
    hi = Math.max(hi, s.x + s.w);
  }
  const shift = -(lo + hi) / 2;
  for (const s of slots.values()) s.x += shift;

  const placed = new Map<string, Placed>();
  for (const s of slots.values()) {
    if (s.node) placed.set(s.id, { node: s.node, x: s.x, y: s.y, w: s.w, h: s.h });
  }
  return {
    placed,
    slots,
    chains,
    width: hi - lo + 80,
    height: y,
  };
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

            let d: string;
            if (e.back) {
              // A back edge leaves the bottom, runs out past the widest thing
              // between it and its target, climbs, and comes in from above. It
              // has to go round rather than through: the forward path it returns
              // along is occupying the middle.
              const side = model.width / 2 + 24;
              d = orthPath([
                { x: x1, y: y1 },
                { x: x1, y: y1 + GAP_Y / 2 },
                { x: side, y: y1 + GAP_Y / 2 },
                { x: side, y: y2 - GAP_Y / 2 },
                { x: x2, y: y2 - GAP_Y / 2 },
                { x: x2, y: y2 },
              ]);
            } else {
              // Down the gutter, across, and down again — through the column
              // each stand-in reserved, so a long edge runs beside the blocks it
              // passes rather than over them.
              const chain = model.chains.get(i) ?? [e.from, e.to];
              const pts = [{ x: x1, y: y1 }];
              for (let k = 1; k < chain.length; k++) {
                const from = model.slots.get(chain[k - 1])!;
                const to = model.slots.get(chain[k])!;
                const gutter = from.y + from.h + GAP_Y / 2;
                const toX = to.node ? x2 : to.x + to.w / 2;
                pts.push({ x: pts[pts.length - 1].x, y: gutter });
                pts.push({ x: toX, y: gutter });
                if (!to.node) pts.push({ x: toX, y: to.y + to.h });
              }
              pts.push({ x: x2, y: y2 });
              d = orthPath(pts);
            }
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
