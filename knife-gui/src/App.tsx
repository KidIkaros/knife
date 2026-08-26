import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import knifechan from "./assets/knifechan.png";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import {
  api,
  type BinaryDetail,
  type Finding,
  type FnRow,
  type IrLine,
  type Line,
  type OpenResult,
  type StringRow,
  type XrefRow,
  type Cfg,
  type SymbolRow,
  type TargetRow,
  type LineActions,
  type FactRow,
  type BookmarkRow,
  type PatchRun,
  type DriverReport,
  type PathRow,
  type YaraHit,
  type Suggestion,
  type Overview,
} from "./api";
import { FunctionList } from "./components/FunctionList";
import { CodeView, type CodeViewHandle } from "./components/CodeView";
import { NavigatorBand } from "./components/NavigatorBand";
import { XrefPane, type RefMode } from "./components/XrefPane";
import { DetailPanel } from "./components/DetailPanel";
import { AttackSurface } from "./components/AttackSurface";
import { CriticalsDashboard } from "./components/CriticalsDashboard";
import { GraphView } from "./components/GraphView";
import { StringsList } from "./components/StringsList";
import { Palette } from "./components/Palette";
import { LineMenu, pseudoMenu, type MenuItem } from "./components/LineMenu";
import { FactsList } from "./components/FactsList";
import { HexInspector } from "./components/HexInspector";
import { KeyMap } from "./components/KeyMap";
import { PatchList } from "./components/PatchList";
import { DriverView } from "./components/DriverView";
import { Evidence } from "./components/Evidence";
import { AgentPane, type AgentDock } from "./components/AgentPane";
import {
  IconAttack,
  IconBack,
  IconAgent,
  IconConsole,
  IconDriver,
  IconExports,
  IconFacts,
  IconFunctions,
  IconImports,
  IconPatches,
  IconStrings,
} from "./components/Icons";
import { save as saveDialog } from "@tauri-apps/plugin-dialog";
import { Console } from "./components/Console";
import { SymbolList } from "./components/SymbolList";

type Tab = "disasm" | "pseudo" | "graph" | "calls" | "criticals" | "linear";
type LeftView =
  | "functions"
  | "attack"
  | "strings"
  | "imports"
  | "exports"
  | "facts"
  | "patches"
  | "driver";

const FN_LIMIT = 20000;

/**
 * Reconstruct clean, columnar text from a listing so it copies as readable
 * source. The on-screen columns (address / mnemonic / operands) are laid out
 * with flexbox `gap`, which contributes no characters — a raw selection copy
 * would run them together as `1400010a0movrax, rbx`. Here we rebuild each line
 * with real separators so pasted disassembly and pseudocode stay aligned.
 */
function listingToText(tab: Tab, lines: Line[], ir: IrLine[]): string {
  if (tab === "pseudo") return ir.map((l) => l.text).join("\n");
  return lines
    .map((l) => {
      if (l.kind === "label") return l.text;
      if (l.kind === "section")
        return `; ${l.name}  (${l.code}${l.perms ? ` ${l.perms}` : ""})  ${l.range}  ${l.size}`;
      if (l.kind === "sub") return `${l.name}:  ; ${l.meta}`;
      if (l.kind === "data") return `${l.addr}  ${l.text}`;
      const body = l.operands ? `${l.mnemonic.padEnd(7)} ${l.operands}` : l.mnemonic;
      return `${l.addr}  ${body}${l.annot ? `  ; ${l.annot.text}` : ""}`;
    })
    .join("\n");
}

/** Read a persisted number, tolerating a cleared or unreadable store. */
function loadNum(key: string, fallback: number): number {
  try {
    const raw = window.localStorage.getItem(key);
    const n = raw === null ? NaN : Number(raw);
    return Number.isFinite(n) ? n : fallback;
  } catch {
    return fallback;
  }
}

function saveNum(key: string, value: number) {
  try {
    window.localStorage.setItem(key, String(value));
  } catch {
    // A private window or blocked site data is not worth failing over.
  }
}

/**
 * Persist a number once it stops changing.
 *
 * For a value a drag updates on every mouse-move — a pane width — writing on
 * each change is a synchronous storage write per frame. Waiting for the value to
 * settle writes once per drag instead, and the only thing lost if the window
 * closes inside that window is a few pixels of layout.
 */
function useDeferredSave(key: string, value: number) {
  useEffect(() => {
    const t = setTimeout(() => saveNum(key, value), 400);
    return () => clearTimeout(t);
  }, [key, value]);
}

/** A draggable split between two panes. */
function Divider({ onDrag }: { onDrag: (dx: number) => void }) {
  return (
    <div
      className="divider"
      onMouseDown={(e) => {
        e.preventDefault();
        let last = e.clientX;
        const move = (m: MouseEvent) => {
          onDrag(m.clientX - last);
          last = m.clientX;
        };
        const up = () => {
          window.removeEventListener("mousemove", move);
          window.removeEventListener("mouseup", up);
        };
        window.addEventListener("mousemove", move);
        window.addEventListener("mouseup", up);
      }}
    />
  );
}

export default function App() {
  const [opened, setOpened] = useState<OpenResult | null>(null);
  const [targets, setTargets] = useState<TargetRow[]>([]);
  const [busy, setBusy] = useState(false);
  const [phase, setPhase] = useState("");
  // True only while a file is being dragged over the window, to show the drop
  // hint. The drop itself goes through the same open path as the file dialog.
  const [dragging, setDragging] = useState(false);
  // Pane sizes are dragged, not fixed: a wide monitor should give the code more
  // room, and a demangled C++ name needs a wider list than `sub_1400a2c0` does.
  const [leftW, setLeftW] = useState(() => loadNum("knife.leftW", 340));
  const [rightW, setRightW] = useState(() => loadNum("knife.rightW", 350));
  // Panels collapse, and the agent docks left / bottom / right. All persisted.
  const [leftOpen, setLeftOpen] = useState(() => loadNum("knife.leftOpen", 1) === 1);
  const [rightOpen, setRightOpen] = useState(() => loadNum("knife.rightOpen", 1) === 1);
  const [xrefOpen, setXrefOpen] = useState(() => loadNum("knife.xrefOpen", 1) === 1);
  const [agentDock, setAgentDock] = useState<AgentDock>(
    () => (localStorage.getItem("knife.agentDock") as AgentDock) || "bottom",
  );
  const [agentW, setAgentW] = useState(() => loadNum("knife.agentW", 380));
  const [toasts, setToasts] = useState<Array<{ id: number; text: string; ok: boolean }>>([]);
  // One channel, two tones. Everything used to arrive as an error, so copying an
  // address or saving a note flashed the same alarm-red box as a failure — the
  // most frequent messages in the app all looked like something had gone wrong.
  const toast = useCallback((text: string | null, ok: boolean) => {
    if (!text) return;
    // A backend error is a sentence, not a stack trace; strip the wrapper Tauri
    // adds so the toast reads as the engine wrote it.
    const clean = text.replace(/^Error:\s*/i, "");
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, text: clean, ok }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 6000);
  }, []);
  const setError = useCallback((text: string | null) => toast(text, false), [toast]);
  /// Something worked. Same channel, calm colour.
  const notify = useCallback((text: string) => toast(text, true), [toast]);

  const [functions, setFunctions] = useState<FnRow[]>([]);
  const [filter, setFilter] = useState("");
  const [leftView, setLeftView] = useState<LeftView>("functions");

  const [current, setCurrent] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("disasm");
  const [lines, setLines] = useState<Line[]>([]);
  const [ir, setIr] = useState<IrLine[]>([]);
  const [xrefs, setXrefs] = useState<XrefRow[]>([]);
  const [xrefDir, setXrefDir] = useState<RefMode>("to");
  const [paths, setPaths] = useState<PathRow[]>([]);
  const [history, setHistory] = useState<string[]>([]);
  // Forward stack for redo-navigation, mirroring a browser's back/forward.
  const [forward, setForward] = useState<string[]>([]);

  const [cfg, setCfg] = useState<Cfg | null>(null);
  // The current function's call closure, for the calls tab; fetched only when
  // that tab is shown.
  const [cgraph, setCgraph] = useState<Cfg | null>(null);
  const [strings, setStrings] = useState<StringRow[]>([]);
  const [symbols, setSymbols] = useState<SymbolRow[]>([]);
  const [facts, setFacts] = useState<FactRow[]>([]);
  // Bookmarks for the open binary; reloaded whenever the target changes.
  const [marks, setMarks] = useState<BookmarkRow[]>([]);
  // The hex inspector's address, or null while it is closed.
  const [inspectAt, setInspectAt] = useState<string | null>(null);
  // The keyboard map overlay.
  const [help, setHelp] = useState(false);
  // Recently opened targets, newest first, for the welcome screen.
  const [recents, setRecents] = useState<string[]>(() => {
    try {
      const raw = localStorage.getItem("knife.recents");
      const parsed = raw ? JSON.parse(raw) : [];
      return Array.isArray(parsed) ? parsed.filter((p) => typeof p === "string") : [];
    } catch {
      return [];
    }
  });
  // Attack-surface severity filter: null shows everything.
  const [sevFilter, setSevFilter] = useState<3 | 2 | 1 | null>(null);
  // A pinned xref target (e.g. a string literal), overriding the open function
  // until the next navigation.
  const [xrefTarget, setXrefTarget] = useState<string | null>(null);
  const [patches, setPatches] = useState<PatchRun[]>([]);
  const [driver, setDriver] = useState<DriverReport | null>(null);
  // The unfiltered report, fetched at open on a driver, for the inline primitive markers.
  const [driverFull, setDriverFull] = useState<DriverReport | null>(null);
  const [drvReach, setDrvReach] = useState(false);
  const [drvCrit, setDrvCrit] = useState(false);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [pickedFinding, setPickedFinding] = useState<Finding | null>(null);
  const [yara, setYara] = useState<YaraHit[]>([]);
  const [yaraRules, setYaraRules] = useState<string | null>(null);
  const [detail, setDetail] = useState<BinaryDetail | null>(null);
  const [overview, setOverview] = useState<Overview | null>(null);
  // The linear sweep: the image read straight through rather than one recovered
  // function at a time. Held apart from `lines` so switching tabs does not
  // disturb the function you were reading, and so scrolling on here does not
  // reload that.
  const [linear, setLinear] = useState<Line[]>([]);
  const [linearAt, setLinearAt] = useState<string | null>(null);
  const [linearBusy, setLinearBusy] = useState(false);
  // Where the next window starts. The backend hands this back because only the
  // decoder knows where the last instruction ended; `null` is end of file.
  const [linearNext, setLinearNext] = useState<number | null>(null);
  // Why the sweep has nothing, when it has nothing. Held rather than toasted: a
  // failed sweep leaves the tab empty, which is the condition that asks for the
  // sweep, so a toast per attempt turns one bad anchor into a stack of them.
  const [linearError, setLinearError] = useState<string | null>(null);
  // The two filter boxes below fetch straight from their input handler, where
  // there is no effect cleanup to hang a guard on. Each request takes a ticket
  // and only the newest one is allowed to write, so a slow reply for an earlier
  // keystroke cannot land on top of a newer one.
  const symbolReq = useRef(0);
  const stringReq = useRef(0);
  const navReq = useRef(0);
  const codeRef = useRef<CodeViewHandle>(null);

  const [palette, setPalette] = useState(false);
  const [find, setFind] = useState<string | null>(null);
  const [hit, setHit] = useState(0);
  const [acts, setActs] = useState<LineActions[]>([]);
  const [irSel, setIrSel] = useState<number | null>(null);
  const [pseudoLoading, setPseudoLoading] = useState(false);
  const [menu, setMenu] = useState<{ at: { x: number; y: number }; items: MenuItem[] } | null>(null);
  // One prompt serves every analyst edit: title, prefilled value, and what to
  // do with the answer.
  const [prompt, setPrompt] = useState<{
    title: string;
    value: string;
    hint?: string;
    run: (value: string) => void;
  } | null>(null);
  const [console_, setConsole] = useState(() => loadNum("knife.console", 0) === 1);
  // The agent is off until switched on, and then still asks per binary before
  // anything leaves the machine.
  const [agentOpen, setAgentOpen] = useState(false);
  const [agentEnabled, setAgentEnabled] = useState(() => loadNum("knife.agent", 0) === 1);
  const [agentKey, setAgentKey] = useState(false);
  const [agentModel, setAgentModel] = useState(() => {
    const stored = localStorage.getItem("knife.agent.model");
    // The stealth alias graduated to a real id and now 404s; move anyone still
    // pointed at it onto the model it became.
    if (!stored || stored === "stealth/ox-alpha") return "z-ai/glm-5.3-flash";
    return stored;
  });
  const [consented, setConsented] = useState<Set<string>>(new Set());
  // Where the last session left off, restored once the window is up.
  const [restored, setRestored] = useState(false);
  const [renaming, setRenaming] = useState(false);
  const [renameText, setRenameText] = useState("");
  const [noting, setNoting] = useState(false);
  const [noteText, setNoteText] = useState("");

  // Exact-address lookups run on every render — the title, the status bar — and
  // a scan of twenty thousand functions per lookup is not free. One pass builds
  // the map; the lookups are constant.
  const fnByAddr = useMemo(() => {
    const m = new Map<string, FnRow>();
    for (const f of functions) m.set(f.addr, f);
    return m;
  }, [functions]);

  const curName = (current ? fnByAddr.get(current)?.name : undefined) ?? current ?? "";

  // Reflect the open binary in Discord Rich Presence (no-op if not configured).
  // Deliberately shows no filename — the sample is identified by its hash, so the
  // status never reveals *what* is being reversed. Function count and sink count
  // go on the first line, the MD5 on the second and on the image hover. Detail
  // and findings arrive after the target opens, so the effect re-runs and fills
  // the hash and sink count in when they land.
  useEffect(() => {
    if (opened) {
      const md5 = detail?.hashes.md5 ?? "";
      const sinks = findings.length;
      api
        .presenceUpdate(
          `${opened.functions} functions · ${sinks} sink${sinks === 1 ? "" : "s"}`,
          // MD5 — short enough (32 hex) to show whole, no label, no truncation.
          md5 || "analyzing…",
          md5 || "",
        )
        .catch(() => {});
    } else {
      api.presenceUpdate("Idle", "no binary open", "").catch(() => {});
    }
  }, [opened, detail, findings]);

  // The audit findings, indexed for the views: highest severity per function for
  // the list's risk dots, and per-address for the inline markers in the code.
  const riskByFunc = useMemo(() => {
    const m = new Map<string, number>();
    for (const f of findings) {
      if (!f.func) continue;
      m.set(f.func, Math.max(m.get(f.func) ?? 0, f.severity));
    }
    return m;
  }, [findings]);

  const findingAt = useMemo(() => {
    const m = new Map<string, Finding>();
    for (const f of findings) {
      if (f.func === curName) m.set(f.addr, f);
    }
    return m;
  }, [findings, curName]);

  // The sinks in the open function, in ranked order — the strip above the code.
  const curFindings = useMemo(
    () => findings.filter((f) => f.func === curName),
    [findings, curName],
  );

  // The picked finding's data flow, keyed by address so the listing can mark it.
  // Only the picked one: several overlapping trails would be noise rather than
  // an explanation.
  //
  // Steps are not ranked into origin-and-hops. The audit unions its walk across
  // branch joins, so what it knows is which instructions participate, not which
  // came first — and with a loop back edge the lowest address is not the origin.
  // Marking them all as steps says exactly what is true.
  const trailAt = useMemo(() => {
    const m = new Map<string, "step" | "sink">();
    if (!pickedFinding || pickedFinding.func !== curName) return m;
    for (const a of pickedFinding.trail) m.set(a, "step");
    m.set(pickedFinding.addr, "sink");
    return m;
  }, [pickedFinding, curName]);

  const primAt = useMemo(() => {
    const m = new Map<string, { api: string; severity: number }>();
    for (const p of driverFull?.primitives ?? []) {
      for (const site of p.sites) m.set(site.from, { api: p.api, severity: p.severity });
    }
    return m;
  }, [driverFull]);

  // The driver icon escalates from amber to red when the kernel surface is
  // actually critical: a raw-buffer IOCTL, or a high-severity primitive user
  // mode can reach. One glance at the rail says "open this one first".
  const drvCritical = useMemo(
    () =>
      !!driverFull &&
      (driverFull.ioctls.some((c) => c.method === "METHOD_NEITHER") ||
        driverFull.primitives.some((p) => p.severity >= 3 && p.reachable)),
    [driverFull],
  );

  // IOCTL codes grouped by the dispatch function that decodes them, so the
  // driver view can show each handler's accepted codes beneath it.
  // Finding the function that contains an address is a range question, so it
  // needs bounds rather than a key. Parsing every function's address for every
  // code — two BigInts per candidate, tens of thousands of them per code, redone
  // whenever the filter box changed the list's identity — is what made opening a
  // driver crawl. The bounds are parsed once and searched.
  const fnBounds = useMemo(() => {
    const rows = functions.map((f) => {
      const start = BigInt(f.addr);
      return { start, end: start + BigInt(f.size), addr: f.addr };
    });
    rows.sort((a, b) => (a.start < b.start ? -1 : a.start > b.start ? 1 : 0));
    return rows;
  }, [functions]);

  const containing = useCallback(
    (addr: string) => {
      const at = BigInt(addr);
      let lo = 0;
      let hi = fnBounds.length - 1;
      while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        const r = fnBounds[mid];
        if (at < r.start) hi = mid - 1;
        else if (at >= r.end) lo = mid + 1;
        else return r.addr;
      }
      return undefined;
    },
    [fnBounds],
  );

  const ioctlsByHandler = useMemo(() => {
    const m = new Map<string, Array<{ code: string; addr: string; method: string }>>();
    if (!driverFull) return m;
    for (const c of driverFull.ioctls) {
      const key = containing(c.addr) ?? c.addr;
      const list = m.get(key) ?? [];
      list.push({ code: c.code, addr: c.addr, method: c.method });
      m.set(key, list);
    }
    return m;
  }, [driverFull, containing]);

  // Show a finding's evidence: pick it and switch to the attack-surface view.
  const showFinding = useCallback((f: Finding) => {
    setPickedFinding(f);
    setLeftView("attack");
    setLeftOpen(true);
  }, []);


  // Lines matching the find query, in the view that is actually showing.
  const hits = useMemo(() => {
    const q = (find ?? "").trim().toLowerCase();
    if (!q) return [] as number[];
    const out: number[] = [];
    if (tab === "pseudo") {
      ir.forEach((l, i) => l.text.toLowerCase().includes(q) && out.push(i));
    } else {
      // Hits are line indices, so they have to be indices into the listing the
      // view is actually showing — the sweep is its own listing.
      (tab === "linear" ? linear : lines).forEach((l, i) => {
        const text =
          l.kind === "insn"
            ? `${l.addr} ${l.mnemonic} ${l.operands} ${l.annot?.text ?? ""}`
            : l.kind === "section"
              ? `${l.name} ${l.range}`
              : l.kind === "sub"
                ? `${l.name} ${l.meta}`
                : l.text;
        if (text.toLowerCase().includes(q)) out.push(i);
      });
    }
    return out;
  }, [find, tab, ir, lines, linear]);

  // Bookmarks ride on the open target; refetch when it changes.
  useEffect(() => {
    if (!opened) return;
    api.bookmarksList(opened.path).then(setMarks).catch(() => setMarks([]));
  }, [opened?.path]);

  // Write the graph on screen out as Graphviz — the picture that outlives the
  // window, for reports and advisories.
  const exportDot = useCallback(
    async (kind: "cfg" | "calls") => {
      if (!current) return;
      const dest = await saveDialog({
        defaultPath: `${curName || "graph"}-${kind}.dot`,
        filters: [{ name: "Graphviz", extensions: ["dot", "gv"] }],
      });
      if (!dest) return;
      try {
        const [, nodes, edges] = await api.exportDot(kind, current, dest);
        setError(
          `wrote ${nodes} node${nodes === 1 ? "" : "s"}, ${edges} edge${edges === 1 ? "" : "s"} to ${dest}`,
        );
      } catch (e) {
        setError(String(e));
      }
    },
    [current, curName],
  );

  /// Remember the target and function so the next launch resumes here.
  const remember = useCallback((path: string, at: string | null) => {    try {
      localStorage.setItem("knife.last", JSON.stringify({ path, at }));
    } catch {
      // resuming is a convenience, not a requirement
    }
  }, []);

  const openFunction = useCallback(
    async (selector: string, push = true) => {
      // Two navigations in quick succession — a double-click in the list, a
      // finding chip clicked while the last one is still loading — both used to
      // apply, and the slower one won. You landed on the function you asked for
      // first, while the history recorded the other. Only the newest navigation
      // may write.
      const gen = ++navReq.current;
      try {
        // Only disassembly and the CFG are fetched up front. Pseudocode and its
        // identifier spans each cost a full decompile — seconds on a large
        // stripped image — and the view opens on disassembly, so they are
        // fetched lazily the first time the pseudocode tab is shown.
        const [ls, graph] = await Promise.all([
          api.disassemble(selector),
          api.cfg(selector).catch(() => null),
        ]);
        if (gen !== navReq.current) return;
        setCfg(graph);
        setCgraph(null);
        setActs([]);
        setIr([]);
        setIrSel(null);
        const entry = ls.length ? ls[0].addr : selector;
        const isNewJump = push && current && current !== entry;
        setHistory((h) => (isNewJump ? [...h, current] : h));
        // A fresh navigation invalidates the forward stack, as in a browser.
        if (isNewJump) setForward([]);
        setLines(ls);
        setSelected(null);
        setXrefTarget(null);
        setNoting(false);
        setRenaming(false);
        setCurrent(entry);
        if (opened?.path) remember(opened.path, entry);
      } catch (e) {
        if (gen === navReq.current) setError(String(e));
      }
    },
    [current, opened, remember],
  );

  /// Start the linear sweep somewhere: an address, or the entry point when the
  /// caller has nowhere particular in mind. Replaces whatever was there.
  const seekLinear = useCallback(async (opts?: { off?: number; at?: string }) => {
    setLinearBusy(true);
    setLinearError(null);
    try {
      const w = await api.disassembleLinear(opts?.off, opts?.at, 1500);
      setLinear(w.lines);
      setLinearAt(opts?.at ?? null);
      setLinearNext(w.next);
    } catch (e) {
      setLinear([]);
      setLinearNext(null);
      setLinearError(String(e).replace(/^Error:\s*/i, ""));
    } finally {
      setLinearBusy(false);
    }
  }, []);

  /// Read on from where the sweep stopped, at the offset it reported. Guessing
  /// that boundary from the last line is what would resume inside an instruction
  /// and decode rubbish from there on.
  const moreLinear = useCallback(async () => {
    if (linearBusy || linearNext === null) return;
    setLinearBusy(true);
    try {
      const w = await api.disassembleLinear(linearNext, undefined, 1500);
      if (!w.lines.length) setLinearNext(null);
      else {
        setLinear((all) => [...all, ...w.lines]);
        setLinearNext(w.next);
      }
    } catch {
      setLinearNext(null);
    } finally {
      setLinearBusy(false);
    }
  }, [linearBusy, linearNext]);

  /// Load every view for whichever target is currently active.
  const loadViews = useCallback(async () => {
    const [fns, fnd, det] = await Promise.all([
      api.listFunctions(undefined, false, FN_LIMIT),
      api.attackSurface(),
      api.binaryDetail(),
    ]);
    setFunctions(fns);
    setFindings(fnd);
    setDetail(det);
    api.strings(undefined, true, 5000).then(setStrings).catch(() => setStrings([]));
    api
      .driverReport(1, false)
      .then(setDriverFull)
      .catch(() => setDriverFull(null));
    // The navigator band is one linear entropy pass over the image; fetch it off
    // the critical path so the panes paint first.
    api.overview(1024).then(setOverview).catch(() => setOverview(null));
    return fns;
  }, []);
  // Cycle through the ranked weaknesses in place — IDA's mark navigation. Each
  // step opens the containing function, selects the flagged instruction, and
  // shows its evidence, so you walk the attack surface without hunting the list.
  const jumpFinding = useCallback(
    (dir: 1 | -1) => {
      if (!findings.length) return;
      const at = pickedFinding
        ? findings.findIndex(
            (f) => f.addr === pickedFinding.addr && f.pattern === pickedFinding.pattern,
          )
        : -1;
      const n = findings.length;
      const f = findings[(((at + dir) % n) + n) % n];
      setPickedFinding(f);
      setLeftView("attack");
      setLeftOpen(true);
      void openFunction(f.addr);
      setSelected(f.addr);
    },
    [findings, pickedFinding, openFunction],
  );

  const reloadAnalysis = useCallback(async () => {
    try {
      const [fns, fnd, det] = await Promise.all([
        api.listFunctions(filter || undefined, false, FN_LIMIT),
        api.attackSurface(),
        api.binaryDetail(),
      ]);
      setFunctions(fns);
      setFindings(fnd);
      setDetail(det);
    } catch (e) {
      setError(String(e));
    }
  }, [filter]);

  const doOpen = useCallback(
    async (path: string) => {
      setBusy(true);
      setPhase("reading file");
      setError(null);
      try {
        const res = await api.openTarget(path);
        setOpened(res);
        setCurrent(null);
        setSelected(null);
        setLines([]);
        setIr([]);
        setLinear([]);
        setLinearNext(null);
        setLinearError(null);
        setXrefs([]);
        setHistory([]);
        setFilter("");
        setYara([]);
        setYaraRules(null);
        const fns = await loadViews();
        api.listTargets().then(setTargets).catch(() => {});
        remember(path, null);
        // Remember the visit for the welcome screen, newest first.
        setRecents((all) => {
          const next = [path, ...all.filter((p) => p !== path)].slice(0, 8);
          try {
            localStorage.setItem("knife.recents", JSON.stringify(next));
          } catch {
            /* persistence is a convenience */
          }
          return next;
        });
        if (fns.length) void openFunction(fns[0].addr, false);
      } catch (e) {
        setError(String(e));
      } finally {
        setBusy(false);
        setPhase("");
      }
    },
    [openFunction, loadViews, remember],
  );

  const switchTo = useCallback(
    async (path: string) => {
      // Reloading every pane for another binary takes as long as opening one, and
      // said nothing while it happened: the window kept showing the target you
      // had left until the new one was ready.
      setBusy(true);
      setPhase("switching target");
      try {
        await api.selectTarget(path);
        const res = await api.openTarget(path); // already loaded: just re-reads the summary
        setOpened(res);
        setCurrent(null);
        setSelected(null);
        setLines([]);
        setIr([]);
        setLinear([]);
        setLinearNext(null);
        setLinearError(null);
        setCfg(null);
        setCgraph(null);
        setHistory([]);
        setFilter("");
        const fns = await loadViews();
        setTargets(await api.listTargets());
        if (fns.length) void openFunction(fns[0].addr, false);
      } catch (e) {
        setError(String(e));
      } finally {
        setBusy(false);
        setPhase("");
      }
    },
    [loadViews, openFunction, setError],
  );

  const closeTab = useCallback(
    async (path: string) => {
      try {
        // Closing a tab you are not reading should not disturb the one you are.
        // `switchTo` resets everything — the open function, the listing, the
        // history, the filter — so calling it for the already-active target threw
        // away your position and dropped you back at its first function.
        const wasActive = targets.find((t) => t.path === path)?.active ?? false;
        await api.closeTarget(path);
        const rows = await api.listTargets();
        setTargets(rows);
        const next = rows.find((t) => t.active);
        if (next) {
          if (wasActive) void switchTo(next.path);
        } else {
          // Nothing left open: back to the welcome screen.
          setOpened(null);
          setFunctions([]);
          setFindings([]);
          setDetail(null);
          setOverview(null);
          setStrings([]);
          setCurrent(null);
          setLines([]);
          setIr([]);
          setCfg(null);
          setCgraph(null);
        }
      } catch (e) {
        setError(String(e));
      }
    },
    [switchTo, setError, targets],
  );

  const pickAndOpen = useCallback(async () => {
    const file = await openDialog({ multiple: false, directory: false });
    if (typeof file === "string") void doOpen(file);
  }, [doOpen]);

  // Drop a binary anywhere on the window to open it. Tauri intercepts the OS
  // drag-drop itself (the webview's own HTML5 drop never fires), so we listen to
  // its event and route a dropped path through the exact same `doOpen` the file
  // dialog uses — a dropped file and a picked one are indistinguishable after
  // this. `busy` guards against dropping mid-analysis; only the first path is
  // taken, matching the dialog's single-select.
  const dropBusy = useRef(false);
  useEffect(() => {
    dropBusy.current = busy;
  }, [busy]);
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let alive = true;
    void getCurrentWebview()
      .onDragDropEvent((event) => {
        const p = event.payload;
        if (p.type === "enter" || p.type === "over") {
          if (!dropBusy.current) setDragging(true);
        } else if (p.type === "drop") {
          setDragging(false);
          const path = p.paths?.[0];
          if (path && !dropBusy.current) void doOpen(path);
        } else {
          setDragging(false); // leave / cancel
        }
      })
      .then((fn) => {
        if (alive) unlisten = fn;
        else fn();
      });
    return () => {
      alive = false;
      unlisten?.();
    };
  }, [doOpen]);

  // The three widths change on every mouse-move of a drag, and a width is only
  // worth remembering once it has settled — persisting each pixel meant a
  // synchronous write to storage on every frame of the drag.
  useDeferredSave("knife.leftW", leftW);
  useDeferredSave("knife.rightW", rightW);
  // The center tab rides with the session, so a restart lands you back in
  // pseudocode (or the graphs) instead of always restarting in disassembly.
  useEffect(() => {
    try {
      localStorage.setItem("knife.tab", tab);
    } catch {
      /* persistence is a convenience */
    }
  }, [tab]);
  // The left pane and the severity filter ride along too: an analyst mid-driver
  // audit should reopen inside the driver view, filtered as they left it.
  useEffect(() => {
    try {
      localStorage.setItem("knife.leftView", leftView);
    } catch {
      /* persistence is a convenience */
    }
  }, [leftView]);
  useEffect(() => {
    try {
      localStorage.setItem("knife.sev", sevFilter === null ? "" : String(sevFilter));
    } catch {
      /* persistence is a convenience */
    }
  }, [sevFilter]);
  useEffect(() => saveNum("knife.leftOpen", leftOpen ? 1 : 0), [leftOpen]);
  useEffect(() => saveNum("knife.rightOpen", rightOpen ? 1 : 0), [rightOpen]);
  useEffect(() => saveNum("knife.xrefOpen", xrefOpen ? 1 : 0), [xrefOpen]);
  useDeferredSave("knife.agentW", agentW);
  useEffect(() => {
    try {
      localStorage.setItem("knife.agentDock", agentDock);
    } catch {
      /* ignore */
    }
  }, [agentDock]);
  useEffect(() => saveNum("knife.console", console_ ? 1 : 0), [console_]);
  useEffect(() => saveNum("knife.agent", agentEnabled ? 1 : 0), [agentEnabled]);
  useEffect(() => {
    try {
      localStorage.setItem("knife.agent.model", agentModel);
    } catch {
      // not worth failing over
    }
  }, [agentModel]);
  useEffect(() => {
    api.agentHasKey().then(setAgentKey).catch(() => setAgentKey(false));
    try {
      const raw = localStorage.getItem("knife.agent.consent");
      if (raw) setConsented(new Set(JSON.parse(raw) as string[]));
    } catch {
      // a cleared store just means consent is asked again
    }
  }, []);

  useEffect(() => {
    if (restored) return;
    setRestored(true);
    let last: { path: string; at: string | null } | null = null;
    let lastTab: Tab | null = null;
    try {
      const raw = localStorage.getItem("knife.last");
      last = raw ? JSON.parse(raw) : null;
    } catch {
      last = null;
    }
    try {
      const t = localStorage.getItem("knife.tab");
      if (t === "disasm" || t === "pseudo" || t === "graph" || t === "calls" || t === "criticals")
        lastTab = t;
    } catch {
      lastTab = null;
    }
    let lastView: LeftView | null = null;
    try {
      const v = localStorage.getItem("knife.leftView");
      if (
        v === "functions" || v === "attack" || v === "strings" || v === "imports" ||
        v === "exports" || v === "facts" || v === "patches" || v === "driver"
      )
        lastView = v;
    } catch {
      lastView = null;
    }
    let lastSev: 1 | 2 | 3 | null = null;
    try {
      const s = localStorage.getItem("knife.sev");
      if (s === "1" || s === "2" || s === "3") lastSev = Number(s) as 1 | 2 | 3;
    } catch {
      lastSev = null;
    }
    if (!last?.path) return;
    (async () => {
      setBusy(true);
      setPhase("reopening the last target");
      try {
        const res = await api.openTarget(last.path);
        setOpened(res);
        const fns = await loadViews();
        setTargets(await api.listTargets());
        const at = last.at ?? fns[0]?.addr;
        if (lastTab) setTab(lastTab);
        if (lastView) setLeftView(lastView);
        if (lastSev) setSevFilter(lastSev);
        if (at) void openFunction(at, false);
      } catch {
        // The file may have moved or been deleted since; starting at the
        // welcome screen is the right answer, not an error.
        try {
          localStorage.removeItem("knife.last");
        } catch {
          /* ignore */
        }
      } finally {
        setBusy(false);
        setPhase("");
      }
    })();
  }, [restored, loadViews, openFunction]);

  // The backend names each stage of the load as it starts.
  useEffect(() => {
    const un = listen<string>("knife://phase", (e) => setPhase(e.payload));
    return () => {
      void un.then((f) => f());
    };
  }, []);

  // Imports and exports are fetched when their view is opened, and refetched
  // when the target changes.
  // Every branch is guarded: imports and exports write the *same* state, so
  // cycling the pane with `s` left both requests in flight and whichever landed
  // last won — rows from one under the other's heading. The guard drops any
  // reply whose pane is no longer the one being shown.
  useEffect(() => {
    if (!opened) return;
    let live = true;
    if (leftView === "driver") {
      api
        .driverReport(drvCrit ? 3 : 1, drvReach)
        .then((r) => live && setDriver(r))
        .catch(() => live && setDriver(null));
    } else if (leftView === "facts") {
      api.analystFacts().then((r) => live && setFacts(r)).catch(() => live && setFacts([]));
    } else if (leftView === "patches") {
      api.patchRuns().then((r) => live && setPatches(r)).catch(() => live && setPatches([]));
    } else if (leftView === "imports") {
      api.imports().then((r) => live && setSymbols(r)).catch(() => live && setSymbols([]));
    } else if (leftView === "exports") {
      api.exports().then((r) => live && setSymbols(r)).catch(() => live && setSymbols([]));
    }
    return () => {
      live = false;
    };
  }, [leftView, opened, drvReach, drvCrit]);

  // Re-filter the function list as the query changes.
  //
  // Guarded for the same reason, and it bites harder here: a narrower query
  // matches fewer functions and can come back first, so typing quickly left the
  // list showing results for a query the box no longer held.
  useEffect(() => {
    if (!opened) return;
    let live = true;
    api
      .listFunctions(filter || undefined, false, FN_LIMIT)
      .then((r) => live && setFunctions(r))
      .catch((e) => live && setError(String(e)));
    return () => {
      live = false;
    };
  }, [filter, opened]);

  // Decompile lazily: the first time the pseudocode tab is shown for a function.
  useEffect(() => {
    if (tab !== "pseudo" || !current || ir.length > 0 || pseudoLoading) return;
    setPseudoLoading(true);
    const sel = current;
    Promise.all([api.decompile(sel), api.lineActions(sel).catch(() => [] as LineActions[])])
      .then(([irs, la]) => {
        // Ignore a stale result if the user navigated away meanwhile.
        setCurrent((c) => {
          if (c === sel) {
            setIr(irs);
            setActs(la);
          }
          return c;
        });
      })
      .catch((e) => setError(String(e)))
      .finally(() => setPseudoLoading(false));
  }, [tab, current, ir.length, pseudoLoading]);

  // Load cross-references for the open function whenever it or the direction
  // changes. A pinned target (a string literal under inspection) overrides
  // until the next navigation.
  useEffect(() => {
    const sel = xrefTarget ?? current;
    if (!sel) {
      setXrefs([]);
      setPaths([]);
      return;
    }
    if (xrefDir === "paths") {
      api
        .pathsTo(sel, 12)
        .then(setPaths)
        .catch(() => setPaths([]));
    } else {
      api
        .xrefs(sel, xrefDir)
        .then(setXrefs)
        .catch(() => setXrefs([]));
    }
  }, [current, xrefDir, xrefTarget]);

  // The call closure costs one rooted walk over every function; fetch it only
  // when the calls tab is actually shown.
  useEffect(() => {
    if (tab !== "calls" || !current) return;
    let live = true;
    api
      .callGraph(current)
      .then((g) => {
        if (live) setCgraph(g);
      })
      .catch((e) => setError(String(e)));
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, current]);

  // Keyboard map, deliberately the same letters the TUI uses so muscle memory
  // carries between the two front ends. Bare letters are ignored while a text
  // field has focus, or typing a filter would trigger navigation.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = document.activeElement;
      const typing =
        el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement;

      if ((e.ctrlKey || e.metaKey) && e.key === "f") {
        e.preventDefault();
        setFind((f) => (f === null ? "" : f));
        setTimeout(() => document.querySelector<HTMLInputElement>(".findbar input")?.focus(), 0);
        return;
      }
      if ((e.ctrlKey || e.metaKey) && (e.key === "p" || e.key === "k")) {
        e.preventDefault();
        setPalette(true);
        return;
      }
      if (e.ctrlKey && e.key === "`") {
        e.preventDefault();
        setConsole((c) => !c);
        return;
      }
      if (e.key === "Escape") {
        setFind(null);
        setPalette(false);
        setRenaming(false);
        setNoting(false);
        setInspectAt(null);
        setHelp(false);
        return;
      }
      if (e.altKey && e.key === "ArrowLeft") {
        e.preventDefault();
        back();
        return;
      }
      if (e.altKey && e.key === "ArrowRight") {
        e.preventDefault();
        forwardNav();
        return;
      }
      if (typing || !opened || prompt || menu || find !== null) return;

      switch (e.key) {
        case ".":
          e.preventDefault();
          jumpFinding(1);
          break;
        case ",":
          e.preventDefault();
          jumpFinding(-1);
          break;
        case "[":
          e.preventDefault();
          setLeftOpen((v) => !v);
          break;
        case "]":
          e.preventDefault();
          setRightOpen((v) => !v);
          break;
        case "g":
          e.preventDefault();
          setPalette(true);
          break;
        case "/":
          e.preventDefault();
          setLeftView("functions");
          // The pane has to be open for the filter to exist, never mind be
          // focused: with it collapsed this key did nothing at all.
          setLeftOpen(true);
          // Focus happens after the pane has switched.
          setTimeout(() => {
            document.querySelector<HTMLInputElement>(".left .filter input")?.focus();
          }, 0);
          break;
        case "d":
          setTab((t) => (t === "pseudo" ? "disasm" : "pseudo"));
          break;
        case "f":
          setTab((t) => (t === "graph" ? "disasm" : "graph"));
          break;
        case "s":
          // Cycling a pane nobody can see is not cycling anything.
          setLeftOpen(true);
          setLeftView((v) => {
            const order: LeftView[] = [
              "functions",
              "attack",
              "strings",
              "imports",
              "exports",
              "facts",
              "patches",
              "driver",
            ];
            return order[(order.indexOf(v) + 1) % order.length];
          });
          break;
        case "x":
          setXrefOpen(true);
          setXrefDir((d) => (d === "to" ? "from" : d === "from" ? "paths" : "to"));
          break;
        case "t":
          if (tab === "pseudo" && irSel !== null && acts[irSel]?.field) {
            e.preventDefault();
            editHandlers.bindType(acts[irSel].field!.base);
          }
          break;
        case "e":
          if (tab === "pseudo" && irSel !== null) {
            const f = acts[irSel]?.field;
            if (f?.type_name) {
              e.preventDefault();
              editHandlers.nameField(f.type_name, f.offset, f.member);
            }
          }
          break;
        case "l":
          if (tab === "pseudo" && irSel !== null && acts[irSel]?.variable) {
            e.preventDefault();
            editHandlers.renameVar(acts[irSel].variable!);
          }
          break;
        case "p":
          if (tab === "pseudo" && current) {
            e.preventDefault();
            editHandlers.setPrototype();
          }
          break;
        case "P":
          if (tab === "disasm" && selected) {
            e.preventDefault();
            const line = lines.find((l) => l.kind === "insn" && l.addr === selected);
            ask(
              `Stage bytes at ${selected}`,
              "",
              "hex bytes, empty to restore the run",
              async (v) => {
                try {
                  if (v.trim()) await api.stagePatch(selected, v);
                  else await api.clearPatch(selected);
                  await afterEdit();
                } catch (err) {
                  setError(String(err));
                }
              },
            );
            void line;
          }
          break;
        case "n":
          if (current) {
            e.preventDefault();
            setRenameText(curName);
            setRenaming(true);
          }
          break;
        case "c":
          if (current) {
            e.preventDefault();
            setNoteText("");
            setNoting(true);
          }
          break;
        case "y": {
          // Copy where you are: the selected instruction if one is, else the
          // function address.
          const text = selected ?? current;
          if (!text) break;
          e.preventDefault();
          void navigator.clipboard.writeText(text);
          notify(`copied ${text}`);
          break;
        }
        case "Y":
          if (!curName) break;
          e.preventDefault();
          void navigator.clipboard.writeText(curName);
          notify(`copied ${curName}`);
          break;
        case "C": {
          // Copy the whole listing, or the current text selection if there is
          // one. Only meaningful on the code tabs; graph/criticals have nothing
          // line-shaped to copy.
          if (tab !== "disasm" && tab !== "pseudo") break;
          e.preventDefault();
          const sel = window.getSelection()?.toString();
          const text = sel && sel.trim() ? sel : listingToText(tab, lines, ir);
          if (!text.trim()) break;
          void navigator.clipboard.writeText(text);
          notify(
            sel && sel.trim()
              ? `copied selection (${text.split("\n").length} lines)`
              : `copied ${tab === "pseudo" ? "pseudocode" : "disassembly"} (${text.split("\n").length} lines)`,
          );
          break;
        }
        case "b":
          e.preventDefault();
          jumpMark(1);
          break;
        case "B":
          e.preventDefault();
          jumpMark(-1);
          break;
        case "m":
          if (opened && (selected || current)) {
            e.preventDefault();
            const at = (selected ?? current!).toLowerCase();
            api
              .bookmarkToggle(opened.path, at)
              .then(async (marked) => {
                setMarks(await api.bookmarksList(opened.path));
                notify(marked ? `marked ${at}` : `unmarked ${at}`);
              })
              .catch((err) => setError(String(err)));
          }
          break;
        case "h":
          // The data inspector: what the selected instruction touches.
          e.preventDefault();
          setInspectAt((v) => (v !== null ? null : selected ?? current));
          break;
        case "?":
          e.preventDefault();
          setHelp((v) => !v);
          break;
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  /// Re-read the current function after an analyst edit, so the pseudocode
  /// shows the new type, name, or prototype immediately.
  const afterEdit = useCallback(async () => {
    await reloadAnalysis();
    if (current) await openFunction(current, false);
    // The fact inventory and the patch list are what an edit changed, so keep
    // them current whether or not their pane happens to be open.
    api.analystFacts().then(setFacts).catch(() => {});
    api.patchRuns().then(setPatches).catch(() => {});
  }, [reloadAnalysis, current, openFunction]);

  const loadYara = useCallback(async () => {
    const file = await openDialog({
      multiple: false,
      title: "YARA rules (a .yar file or a directory of them)",
    });
    if (typeof file !== "string") return;
    try {
      const n = await api.setYaraRules(file);
      const [rules, hits] = await api.yaraMatches();
      setYara(hits);
      setYaraRules(rules);
      setDetail(await api.binaryDetail());
      api.overview(1024).then(setOverview).catch(() => {});
      notify(`${n} rule${n === 1 ? "" : "s"} matched; verdict recomputed`);
    } catch (e) {
      setError(String(e));
    }
  }, [setError]);

  const clearYara = useCallback(async () => {
    try {
      await api.setYaraRules(undefined);
      setYara([]);
      setYaraRules(null);
      setDetail(await api.binaryDetail());
      api.overview(1024).then(setOverview).catch(() => {});
    } catch (e) {
      setError(String(e));
    }
  }, [setError]);

  // Consent is remembered per binary, keyed by the path the window opened.
  const consentKey = opened?.path ?? "";
  const grantConsent = useCallback(() => {
    setConsented((prev) => {
      const next = new Set(prev).add(consentKey);
      try {
        localStorage.setItem("knife.agent.consent", JSON.stringify([...next]));
      } catch {
        // remembering is a convenience, not a requirement
      }
      return next;
    });
  }, [consentKey]);

  const askForKey = useCallback(() => {
    setPrompt({
      title: "OpenRouter API key",
      value: "",
      hint: "stored in Windows Credential Manager, never in a file",
      run: async (v) => {
        try {
          await api.agentSetKey(v);
          setAgentKey(await api.agentHasKey());
        } catch (e) {
          setError(String(e));
        }
      },
    });
  }, [setError]);

  const ask = useCallback(
    (title: string, value: string, hint: string, run: (v: string) => void) =>
      setPrompt({ title, value, hint, run }),
    [],
  );

  const editHandlers = useMemo(
    () => ({
      bindType: (base: string) =>
        ask(`Bind a type to ${base}`, "", "a type name, empty to clear", async (v) => {
          try {
            if (!current) return;
            if (v.trim()) await api.bindType(current, base, v);
            else await api.clearBinding(current, base);
            await afterEdit();
          } catch (e) {
            setError(String(e));
          }
        }),
      nameField: (typeName: string, offset: number, member: string) =>
        ask(
          `Name ${typeName} field at ${offset < 0 ? "-" : "+"}0x${Math.abs(offset).toString(16)}`,
          member.startsWith("field_") ? "" : member,
          "a field name, empty to clear",
          async (v) => {
            try {
              if (v.trim()) await api.setField(typeName, offset, v);
              else await api.clearField(typeName, offset);
              await afterEdit();
            } catch (e) {
              setError(String(e));
            }
          },
        ),
      renameVar: (base: string) =>
        ask(`Rename ${base}`, "", "a variable name, empty to clear", async (v) => {
          try {
            if (!current) return;
            if (v.trim()) await api.setVariable(current, base, v);
            else await api.clearVariable(current, base);
            await afterEdit();
          } catch (e) {
            setError(String(e));
          }
        }),
      setPrototype: () =>
        ask("Prototype", "", "RETURN (PARAM, PARAM), empty to clear", async (v) => {
          try {
            if (!current) return;
            const text = v.trim();
            if (!text) {
              await api.clearPrototype(current);
            } else {
              // `bool (CONTEXT *, size_t)` splits into a return type and a
              // parameter list, the same syntax the terminal interface takes.
              const open = text.indexOf("(");
              const returns = (open < 0 ? text : text.slice(0, open)).trim();
              const inner = open < 0 ? "" : text.slice(open + 1).replace(/\)\s*$/, "");
              const params = inner
                .split(",")
                .map((p) => p.trim())
                .filter(Boolean);
              await api.setPrototype(current, returns, params);
            }
            await afterEdit();
          } catch (e) {
            setError(String(e));
          }
        }),
    }),
    [ask, current, afterEdit, setError],
  );

  useEffect(() => {
    if (!hits.length) return;
    codeRef.current?.scrollToLine(hits[Math.min(hit, hits.length - 1)]);
  }, [hit, hits]);

  // The sweep is only built when the tab is first shown, and it starts wherever
  // you were reading — the function you have open is far likelier to be what you
  // want to see in context than the entry point is.
  // `linearError` is part of the guard, not just a message: an empty sweep is
  // exactly what triggers this, so without it a failed anchor retries forever.
  useEffect(() => {
    if (tab !== "linear" || linear.length || linearBusy || linearError) return;
    // Start at the top of the file: the sweep's whole point is that it covers
    // what the function views cannot, and that begins with the headers.
    void seekLinear({ off: 0 });
  }, [tab, linear.length, linearBusy, linearError, seekLinear]);

  // A newly opened function starts at its top. The scroll container outlives the
  // listing inside it, so without this you arrive halfway down a function because
  // that is where you were reading the last one.
  useEffect(() => {
    if (current) codeRef.current?.scrollToLine(0);
  }, [current]);

  // Bring the selected instruction into view. Picking a finding — from the
  // attack surface, the criticals dashboard, the strip above the code, or by
  // cycling with `.` and `,` — selects a line that is usually nowhere near the
  // top of the function, and nothing used to scroll to it: the evidence named an
  // address the listing was not showing. Only for the disassembly tab, whose
  // lines are addressed; the pseudocode tab has its own selection.
  useEffect(() => {
    if (tab !== "disasm" || !selected) return;
    const idx = lines.findIndex((l) => l.kind === "insn" && l.addr === selected);
    if (idx >= 0) codeRef.current?.scrollToLine(idx);
  }, [selected, lines, tab]);

  const pickLeft = useCallback(
    (v: LeftView) => {
      if (leftView === v && leftOpen) setLeftOpen(false);
      else {
        setLeftView(v);
        setLeftOpen(true);
      }
    },
    [leftView, leftOpen],
  );

  // Apply a suggestion the agent proposed. Read stays read; this is the write
  // the analyst chose, through the ordinary validated command.
  const applySuggestion = useCallback(
    async (sug: Suggestion) => {
      const addr = /^0x[0-9a-f]+$/i.test(sug.selector)
        ? sug.selector
        : functions.find((f) => f.name === sug.selector)?.addr;
      if (!addr) throw new Error(`no function named ${sug.selector}`);
      if (sug.kind === "rename" && sug.new_name) {
        await api.setName(addr, sug.new_name);
      } else if (sug.kind === "prototype" && sug.returns) {
        await api.setPrototype(addr, sug.returns, sug.params ?? []);
      } else if (sug.kind === "note" && sug.note) {
        await api.setNote(addr, sug.note);
      } else {
        throw new Error("incomplete suggestion");
      }
      await afterEdit();
    },
    [functions, afterEdit],
  );

  const back = useCallback(() => {
    setHistory((h) => {
      if (!h.length) return h;
      if (current) setForward((f) => [...f, current]);
      void openFunction(h[h.length - 1], false);
      return h.slice(0, -1);
    });
  }, [openFunction, current]);

  const forwardNav = useCallback(() => {
    setForward((f) => {
      if (!f.length) return f;
      if (current) setHistory((h) => [...h, current]);
      void openFunction(f[f.length - 1], false);
      return f.slice(0, -1);
    });
  }, [openFunction, current]);

  // Cycle the bookmarks in address order, like . / , cycle findings.
  const jumpMark = useCallback(
    (dir: 1 | -1) => {
      if (!marks.length) return;
      const sorted = [...marks].sort((a, b) => a.addr.localeCompare(b.addr));
      const cur = selected ?? current;
      const at = cur ? sorted.findIndex((m) => m.addr.toLowerCase() === cur.toLowerCase()) : -1;
      const n = sorted.length;
      const m = sorted[(((at + dir) % n) + n) % n];
      void openFunction(m.addr);
      setSelected(m.addr);
    },
    [marks, selected, current, openFunction],
  );

  const submitRename = useCallback(async () => {
    if (!current) return;
    const name = renameText.trim();
    setRenaming(false);
    if (!name || name === curName) return;
    try {
      await api.setName(current, name);
      await reloadAnalysis();
      await openFunction(current, false);
    } catch (e) {
      setError(String(e));
    }
  }, [current, renameText, curName, reloadAnalysis, openFunction]);

  const submitNote = useCallback(async () => {
    const at = selected ?? current;
    const note = noteText.trim();
    setNoting(false);
    if (!at || !note) return;
    try {
      await api.setNote(at, note);
      if (current) await openFunction(current, false);
    } catch (e) {
      setError(String(e));
    }
  }, [selected, current, noteText, openFunction]);

  const agentEl =
    opened && agentOpen ? (
      <AgentPane
        enabled={agentEnabled}
        consented={consented.has(consentKey)}
        targetName={opened.title}
        targetKey={opened.path}
        isDriver={!!opened.is_driver}
        hasKey={agentKey}
        model={agentModel}
        dock={agentDock}
        onModel={setAgentModel}
        onDock={setAgentDock}
        onConsent={grantConsent}
        onNeedKey={askForKey}
        onClose={() => setAgentOpen(false)}
        onJump={(a) => openFunction(a)}
        onApply={applySuggestion}
        onApplied={afterEdit}
      />
    ) : null;

  return (
    <div className="app">
      {dragging && (
        <div className="drop-overlay">
          <div className="drop-hint">Drop a binary to open</div>
        </div>
      )}
      <div className="topbar">
        <span className="brand">
          <img className="brandmark" src={knifechan} alt="" draggable={false} />
          <span className="slash">╱</span> KNIFE
        </span>
        {opened && (
          <span className="topmeta">
            <b>{opened.title}</b> · {opened.format} · {opened.arch} · {opened.functions} functions ·{" "}
            {opened.high_risk} high-risk{opened.is_driver ? " · driver" : ""}
          </span>
        )}
        {opened && (
          <span className="navpair">
            <button
              className="navbtn"
              disabled={!history.length}
              title="Back (Alt+←)"
              onClick={back}
            >
              ‹
            </button>
            <button
              className="navbtn"
              disabled={!forward.length}
              title="Forward (Alt+→)"
              onClick={forwardNav}
            >
              ›
            </button>
          </span>
        )}
        <div className="spacer" />
        {opened && (
          <span
            className={"panel-toggle" + (rightOpen ? " on" : "")}
            title="Show/hide the detail panel ( ] )"
            onClick={() => setRightOpen((v) => !v)}
          >
            detail
          </span>
        )}
        <span
          className={"agent-toggle" + (agentEnabled ? " on" : "")}
          title={
            agentEnabled
              ? "AI agent enabled; click to switch it off entirely"
              : "AI agent switched off; click to enable"
          }
          onClick={() => setAgentEnabled((v) => !v)}
        >
          agent {agentEnabled ? "on" : "off"}
        </span>
        <button className="btn" onClick={pickAndOpen} disabled={busy}>
          {busy ? "analyzing…" : "Open binary"}
        </button>
      </div>

      {targets.length > 0 && (
        <div className="tabbar">
          {targets.map((t) => (
            <div
              key={t.path}
              className={"ttab" + (t.active ? " active" : "")}
              title={t.path}
              onClick={() => !t.active && switchTo(t.path)}
            >
              <span className="tname">{t.title}</span>
              <span
                className="tclose"
                title="Close"
                onClick={(e) => {
                  e.stopPropagation();
                  void closeTab(t.path);
                }}
              >
                ✕
              </span>
            </div>
          ))}
        </div>
      )}

      <div className="body">
        <div className="rail">
          <button
            className={leftView === "functions" ? "active" : ""}
            title="Functions"
            onClick={() => pickLeft("functions")}
          >
            <IconFunctions />
          </button>
          <button
            className={leftView === "attack" ? "active" : ""}
            title="Attack surface"
            onClick={() => pickLeft("attack")}
          >
            <IconAttack />
            {findings.length > 0 && (
              <span className="count">
                {findings.length > 99 ? "99+" : findings.length}
              </span>
            )}
          </button>
          <button
            className={leftView === "strings" ? "active" : ""}
            title="Strings"
            onClick={() => pickLeft("strings")}
          >
            <IconStrings />
          </button>
          <button
            className={leftView === "imports" ? "active" : ""}
            title="Imports"
            onClick={() => pickLeft("imports")}
          >
            <IconImports />
          </button>
          <button
            className={leftView === "exports" ? "active" : ""}
            title="Exports"
            onClick={() => pickLeft("exports")}
          >
            <IconExports />
          </button>
          <button
            className={
              (leftView === "driver" ? "active" : "") +
              (opened?.is_driver ? (drvCritical ? " flag crit" : " flag") : "")
            }
            title={
              opened?.is_driver
                ? drvCritical
                  ? "Driver analysis — critical surface: raw-buffer ioctl or reachable high-severity primitive"
                  : "Driver analysis"
                : "Driver analysis (not a driver)"
            }
            onClick={() => pickLeft("driver")}
          >
            <IconDriver />
          </button>
          <button
            className={leftView === "facts" ? "active" : ""}
            title="Types and analyst facts"
            onClick={() => pickLeft("facts")}
          >
            <IconFacts />
          </button>
          <button
            className={leftView === "patches" ? "active" : ""}
            title="Staged patches"
            onClick={() => pickLeft("patches")}
          >
            <IconPatches />
          </button>
          <button
            className={agentOpen ? "active" : ""}
            title="Agent"
            onClick={() => setAgentOpen((v) => !v)}
          >
            <IconAgent />
          </button>
          <button
            className={console_ ? "active" : ""}
            title="Console (ctrl+`)"
            onClick={() => setConsole((c) => !c)}
          >
            <IconConsole />
          </button>
          <div className="spacer" />
          <button title="Back" onClick={back} disabled={!history.length}>
            <IconBack />
          </button>
        </div>

        {!opened ? (
          <div className="welcome">
            <div>
              <img className="welcome-art" src={knifechan} alt="" draggable={false} />
              <div className="big">╱ knife</div>
              <div className="sub">Find the bug, not just the binary.</div>
              <div style={{ marginTop: 16 }}>
                <button className="btn" onClick={pickAndOpen}>
                  Open a PE / ELF / Mach-O
                </button>
              </div>
              {recents.length > 0 && (
                <div className="recents">
                  {recents.map((p) => (
                    <div
                      key={p}
                      className="recent"
                      title={p}
                      onClick={() => void doOpen(p)}
                    >
                      {p.split(/[\\/]/).pop()}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        ) : (
          <>
            {agentOpen && agentDock === "left" && (
              <>
                <div className="agent-col" style={{ width: agentW, flex: `0 0 ${agentW}px` }}>
                  {agentEl}
                </div>
                <Divider onDrag={(dx) => setAgentW((w) => Math.min(760, Math.max(280, w + dx)))} />
              </>
            )}
            {leftOpen && (
            <div className="panel left" style={{ width: leftW, flex: `0 0 ${leftW}px` }}>
              {leftView === "functions" ? (
                <>
                  <div className="panel-head">
                    <span>functions</span>
                    <span
                      className="risk-legend"
                      title="row dots — red: contains a high-severity finding · amber: contains a finding · hollow: clean"
                    >
                      <i className="risk-dot s3" />
                      <i className="risk-dot s2" />
                      <i className="risk-dot none" />
                    </span>
                    <span className="count">({functions.length})</span>
                  </div>
                  <div className="filter">
                    <input
                      placeholder="filter…"
                      value={filter}
                      onChange={(e) => setFilter(e.target.value)}
                    />
                  </div>
                  <FunctionList
                    rows={functions}
                    current={current}
                    risk={riskByFunc}
                    filter={filter}
                    onPick={(a) => openFunction(a)}
                  />
                </>
              ) : leftView === "driver" ? (
                <>
                  <div className="panel-head">
                    <span>driver</span>
                    <span className="count">
                      {driver ? `(${driver.primitives.length} primitives)` : "(none)"}
                    </span>
                  </div>
                  <DriverView
                    report={driver}
                    isDriver={opened?.is_driver}
                    reachableOnly={drvReach}
                    criticalOnly={drvCrit}
                    ioctlsByHandler={ioctlsByHandler}
                    onToggleReachable={() => setDrvReach((v) => !v)}
                    onToggleCritical={() => setDrvCrit((v) => !v)}
                    onJump={(a) => openFunction(a)}
                    onPseudo={(a) => {
                      // The decompile is lazy: open the function, then show
                      // its pseudocode tab and let the effect fetch it.
                      void openFunction(a).then(() => setTab("pseudo"));
                    }}
                  />
                </>
              ) : leftView === "facts" ? (
                <>
                  <div className="panel-head">
                    <span>analyst facts</span>
                    <span className="count">({facts.length})</span>
                  </div>
                  <div className="filter">
                    <input
                      placeholder="filter types, prototypes, bindings…"
                      onChange={(e) =>
                        api
                          .analystFacts(e.target.value || undefined)
                          .then(setFacts)
                          .catch(() => setFacts([]))
                      }
                    />
                  </div>
                  <FactsList
                    rows={facts}
                    marks={marks}
                    onJump={(a) => openFunction(a)}
                    onUnmark={(a) => {
                      if (!opened) return;
                      api
                        .bookmarkToggle(opened.path, a)
                        .then(() => api.bookmarksList(opened.path).then(setMarks))
                        .catch((err) => setError(String(err)));
                    }}
                  />
                </>
              ) : leftView === "patches" ? (
                <>
                  <div className="panel-head">
                    <span>staged patches</span>
                    <span className="count">({patches.length})</span>
                  </div>
                  <PatchList
                    runs={patches}
                    onJump={(a) => openFunction(a)}
                    onClear={async (offset) => {
                      try {
                        await api.clearPatch(offset);
                        await afterEdit();
                      } catch (e) {
                        setError(String(e));
                      }
                    }}
                    onExport={async () => {
                      const out = await saveDialog({ title: "Export patched binary" });
                      if (typeof out !== "string") return;
                      try {
                        notify(await api.exportPatched(out));
                      } catch (e) {
                        setError(String(e));
                      }
                    }}
                  />
                </>
              ) : leftView === "imports" || leftView === "exports" ? (
                <>
                  <div className="panel-head">
                    <span>{leftView}</span>
                    <span className="count">({symbols.length})</span>
                  </div>
                  <div className="filter">
                    <input
                      placeholder={`filter ${leftView}…`}
                      onChange={(e) => {
                        const q = e.target.value || undefined;
                        const call = leftView === "imports" ? api.imports : api.exports;
                        const gen = ++symbolReq.current;
                        call(q)
                          .then((r) => gen === symbolReq.current && setSymbols(r))
                          .catch(() => gen === symbolReq.current && setSymbols([]));
                      }}
                    />
                  </div>
                  <SymbolList
                    rows={symbols}
                    showModules={leftView === "imports"}
                    onJump={(a) => openFunction(a)}
                  />
                </>
              ) : leftView === "strings" ? (
                <>
                  <div className="panel-head">
                    <span>strings</span>
                    <span className="count">({strings.length})</span>
                  </div>
                  <div className="filter">
                    <input
                      placeholder="filter literals…"
                      onChange={(e) => {
                        const q = e.target.value;
                        const gen = ++stringReq.current;
                        api
                          .strings(q || undefined, !q, 5000)
                          .then((r) => gen === stringReq.current && setStrings(r))
                          .catch(() => gen === stringReq.current && setStrings([]));
                      }}
                    />
                  </div>
                  <StringsList
                    rows={strings}
                    onJump={(a) => openFunction(a)}
                    onRefs={(s) => {
                      // A referenced literal is a door: open the function that
                      // holds it and pin the xref pane to the string itself.
                      void (async () => {
                        await openFunction(s.addr);
                        setXrefDir("to");
                        setXrefTarget(s.addr);
                      })();
                    }}
                  />
                </>
              ) : (
                <>
                  <div className="panel-head">
                    <span>attack surface</span>
                    <span className="chips">
                      {([3, 2, 1] as const).map((s) => (
                        <span
                          key={s}
                          className={"chip" + (sevFilter === s ? " on" : "")}
                          title={
                            s === 3
                              ? "high severity only"
                              : s === 2
                                ? "medium severity only"
                                : "low severity only"
                          }
                          onClick={() => setSevFilter((v) => (v === s ? null : s))}
                        >
                          {s === 3 ? "H" : s === 2 ? "M" : "L"}
                        </span>
                      ))}
                    </span>
                    <span
                      className="panel-action"
                      title="write the ranked findings to a markdown report"
                      onClick={async () => {
                        const dest = await saveDialog({
                          defaultPath: "findings.md",
                          filters: [{ name: "Markdown", extensions: ["md"] }],
                        });
                        if (!dest) return;
                        try {
                          const n = await api.exportFindings(dest);
                          notify(`wrote ${n} finding${n === 1 ? "" : "s"} to ${dest}`);
                        } catch (err) {
                          setError(String(err));
                        }
                      }}
                    >
                      export
                    </span>
                    <span className="count">({findings.length})</span>
                  </div>
                  <AttackSurface
                    findings={
                      sevFilter === 3
                        ? findings.filter((f) => f.severity >= 3)
                        : sevFilter === 2
                          ? findings.filter((f) => f.severity === 2)
                          : sevFilter === 1
                            ? findings.filter((f) => f.severity <= 1)
                            : findings
                    }
                    selected={pickedFinding?.addr ?? selected}
                    total={findings.length}
                    onPick={(f) => {
                      setPickedFinding(f);
                      setSelected(f.addr);
                      void openFunction(f.addr);
                    }}
                  />
                </>
              )}
            </div>
            )}
            {leftOpen && (
              <Divider onDrag={(dx) => setLeftW((w) => Math.min(700, Math.max(220, w + dx)))} />
            )}
            <div className="center">
              <div className="tabs">
                <div
                  className={"tab" + (tab === "disasm" ? " active" : "")}
                  onClick={() => setTab("disasm")}
                >
                  disassembly
                </div>
                <div
                  className={"tab" + (tab === "pseudo" ? " active" : "")}
                  onClick={() => setTab("pseudo")}
                >
                  pseudocode
                </div>
                <div
                  className={"tab" + (tab === "graph" ? " active" : "")}
                  onClick={() => setTab("graph")}
                >
                  graph
                </div>
                <div
                  className={"tab crit-tab" + (tab === "criticals" ? " active" : "")}
                  onClick={() => setTab("criticals")}
                >
                  criticals
                  {findings.length > 0 && (
                    <span className={"tab-badge" + (findings.some((f) => f.severity >= 3) ? " hi" : "")}>
                      {findings.length}
                    </span>
                  )}
                </div>
                <div
                  className={"tab" + (tab === "calls" ? " active" : "")}
                  onClick={() => setTab("calls")}
                >
                  calls
                </div>
                <div
                  className={"tab" + (tab === "linear" ? " active" : "")}
                  title="the image read straight through, not one function at a time"
                  onClick={() => setTab("linear")}
                >
                  linear
                </div>
                <div className="title">
                  {renaming ? (
                    <input
                      className="inline-input"
                      autoFocus
                      style={{ width: 220 }}
                      value={renameText}
                      onChange={(e) => setRenameText(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") void submitRename();
                        if (e.key === "Escape") setRenaming(false);
                      }}
                      onBlur={() => setRenaming(false)}
                    />
                  ) : (
                    <span className="fname">{curName}</span>
                  )}
                  <button
                    className="act"
                    disabled={!current}
                    onClick={() => {
                      setRenameText(curName);
                      setRenaming(true);
                    }}
                  >
                    rename
                  </button>
                  <button
                    className="act"
                    disabled={!current}
                    onClick={() => {
                      setNoteText("");
                      setNoting((n) => !n);
                    }}
                  >
                    note
                  </button>
                  <button
                    className="act"
                    title="copy the listing (or the current selection) — C"
                    disabled={
                      (tab !== "disasm" && tab !== "pseudo") ||
                      (tab === "disasm" ? lines.length === 0 : ir.length === 0)
                    }
                    onClick={() => {
                      if (tab !== "disasm" && tab !== "pseudo") return;
                      const sel = window.getSelection()?.toString();
                      const text = sel && sel.trim() ? sel : listingToText(tab, lines, ir);
                      if (!text.trim()) return;
                      void navigator.clipboard.writeText(text);
                      setError(
                        sel && sel.trim()
                          ? `copied selection (${text.split("\n").length} lines)`
                          : `copied ${tab === "pseudo" ? "pseudocode" : "disassembly"} (${text.split("\n").length} lines)`,
                      );
                    }}
                  >
                    copy
                  </button>
                </div>
              </div>

              {noting && (
                <div className="filter">
                  <input
                    className="inline-input"
                    autoFocus
                    placeholder={
                      selected ? `note on ${selected}` : "select an instruction, then type a note"
                    }
                    value={noteText}
                    onChange={(e) => setNoteText(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") void submitNote();
                      if (e.key === "Escape") setNoting(false);
                    }}
                  />
                </div>
              )}

              {find !== null && (
                <div className="findbar">
                  <input
                    autoFocus
                    placeholder={`find in ${tab === "pseudo" ? "pseudocode" : "disassembly"}…`}
                    value={find}
                    onChange={(e) => {
                      setFind(e.target.value);
                      setHit(0);
                    }}
                    onKeyDown={(e) => {
                      if (e.key === "Escape") setFind(null);
                      else if (e.key === "Enter") {
                        e.preventDefault();
                        if (hits.length) {
                          setHit((h) => (e.shiftKey ? (h - 1 + hits.length) : h + 1) % hits.length);
                        }
                      }
                    }}
                  />
                  <span className="fcount">
                    {hits.length ? `${(hit % hits.length) + 1}/${hits.length}` : "none"}
                  </span>
                  <span className="fclose" onClick={() => setFind(null)}>
                    ✕
                  </span>
                </div>
              )}

              {curFindings.length > 0 && (
                <div className="fstrip" title="the ranked sinks in this function">
                  {curFindings.map((f) => (
                    <span
                      key={f.addr + f.pattern}
                      className={"fchip sev s" + Math.min(f.severity, 3) + (selected === f.addr ? " on" : "")}
                      title={`${f.pattern.replace(/-/g, " ")} — ${f.detail}\nalt-click: open its evidence`}
                      onClick={(e) => {
                        // Alt is "why": jump straight to the evidence pane.
                        if (e.altKey) {
                          showFinding(f);
                          return;
                        }
                        if (tab === "graph" || tab === "calls") setTab("disasm");
                        setSelected(f.addr);
                      }}
                    >
                      <i>{f.severity >= 3 ? "H" : f.severity >= 2 ? "M" : "L"}</i>
                      {f.api} @ {f.addr.replace("0x", "")}
                    </span>
                  ))}
                </div>
              )}

              {tab === "linear" ? (
                <>
                  {/* What the file is, before what is in it — the sweep opens on
                      the headers, and this is the reading of them. */}
                  {detail && (
                    <div className="lintriage">
                      <span className={"verdict " + detail.triage.verdict.replace(/\s+/g, "")}>
                        {detail.triage.verdict}
                      </span>
                      <span className="tscore">score {detail.triage.score}</span>
                      <span className="tsep">·</span>
                      <span>
                        {detail.format} · {detail.arch} · {detail.bits}-bit
                      </span>
                      <span className="tsep">·</span>
                      <span>{(detail.size / (1 << 20)).toFixed(2)} MB</span>
                      <span className="tsep">·</span>
                      <span>
                        base <b>{detail.image_base}</b>
                      </span>
                      <span className="tsep">·</span>
                      <span>
                        entry <b>{detail.entry}</b>
                      </span>
                      {detail.is_stripped && <span className="tflag">stripped</span>}
                      {detail.signing.signed ? (
                        <span className="tflag ok">signed</span>
                      ) : (
                        <span className="tflag">unsigned</span>
                      )}
                      {detail.triage.signals.slice(0, 2).map((s, i) => (
                        <span key={i} className="tsignal" title={s.text}>
                          {s.text}
                        </span>
                      ))}
                    </div>
                  )}
                  <div className="linbar">
                    <span className={"linwhere" + (linearError ? " bad" : "")}>
                      {linearError
                        ? linearError
                        : linear.length
                          ? `${linear[0].addr} — ${linear[linear.length - 1].addr}`
                          : linearBusy
                            ? "sweeping…"
                            : "nothing decoded"}
                    </span>
                    {!linearError && (
                      <span className="lincount">
                        {linear.length} lines{linearNext === null ? " · end of file" : ""}
                      </span>
                    )}
                    <div className="spacer" />
                    <button
                      className="act"
                      title="the top of the file — headers first"
                      onClick={() => void seekLinear({ off: 0 })}
                    >
                      top
                    </button>
                    <button
                      className="act"
                      disabled={!detail}
                      title="where execution starts"
                      onClick={() => detail && void seekLinear({ at: detail.entry })}
                    >
                      entry
                    </button>
                    <button
                      className="act"
                      disabled={!current}
                      title="sweep from the function you have open"
                      onClick={() => current && void seekLinear({ at: current })}
                    >
                      here
                    </button>
                    <button
                      className="act"
                      title="sweep from an address"
                      onClick={() =>
                        ask("Sweep from", linearAt ?? "", "an address in a mapped section", (v) => {
                          if (v.trim()) void seekLinear({ at: v.trim() });
                        })
                      }
                    >
                      goto
                    </button>
                  </div>
                  <CodeView
                    ref={codeRef}
                    tab="disasm"
                    lines={linear}
                    ir={[]}
                    selected={selected}
                    irSelected={null}
                    hits={hits}
                    currentHit={hits.length ? hits[hit % hits.length] : null}
                    findingAt={findingAt}
                    primAt={primAt}
                    trailAt={trailAt}
                    onSelect={setSelected}
                    onSelectIr={() => {}}
                    onFollow={(sel) => {
                      // Following a call from the sweep opens that routine the
                      // usual way, which is the point of naming the target.
                      setTab("disasm");
                      void openFunction(sel);
                    }}
                    onFinding={showFinding}
                    onPrimitive={() => {
                      setLeftView("driver");
                      setLeftOpen(true);
                    }}
                    onLineMenu={() => {}}
                    onEndReached={moreLinear}
                  />
                </>
              ) : tab === "criticals" ? (
                <CriticalsDashboard
                  findings={findings}
                  onJump={(f) => {
                    setTab("disasm");
                    void openFunction(f.addr);
                    setSelected(f.addr);
                  }}
                  onEvidence={showFinding}
                />
              ) : tab === "graph" ? (
                <GraphView
                  cfg={cfg}
                  onOpenBlock={(a) => { setTab("disasm"); setSelected(a); }}
                  onExport={current ? () => void exportDot("cfg") : undefined}
                />
              ) : tab === "calls" ? (
                <GraphView
                  cfg={cgraph}
                  onOpenBlock={(a) => {
                    // A call-graph card is a whole function; open it so its own
                    // code, pseudocode, and closure are one step away.
                    void openFunction(a);
                  }}
                  onExport={current ? () => void exportDot("calls") : undefined}
                />
              ) : tab === "pseudo" && ir.length === 0 && pseudoLoading ? (
                <div className="code decompiling">decompiling…</div>
              ) : (
                <CodeView
                  ref={codeRef}
                  tab={tab}
                  lines={lines}
                  ir={ir}
                  selected={selected}
                  irSelected={irSel}
                  hits={hits}
                  currentHit={hits.length ? hits[hit % hits.length] : null}
                  findingAt={findingAt}
                  primAt={primAt}
                  trailAt={trailAt}
                  onSelect={setSelected}
                  onSelectIr={setIrSel}
                  onFollow={(sel) => openFunction(sel)}
                  onFinding={showFinding}
                  onPrimitive={() => {
                    setLeftView("driver");
                    setLeftOpen(true);
                  }}
                  onLineMenu={(i, at) =>
                    setMenu({
                      at,
                      items: pseudoMenu(acts[i], editHandlers, {
                        addr: selected ?? current,
                        func: curName,
                        copy: (text) => {
                          void navigator.clipboard.writeText(text);
                          notify(`copied ${text}`);
                        },
                      }),
                    })
                  }
                />
              )}

              {leftView === "attack" && pickedFinding && (
                <Evidence
                  finding={pickedFinding}
                  onJump={(a) => openFunction(a)}
                  onPaths={() => setXrefDir("paths")}
                />
              )}

                <XrefPane
                  rows={xrefs}
                  paths={paths}
                  dir={xrefDir}
                  onDir={setXrefDir}
                  about={xrefTarget}
                  collapsed={!xrefOpen}
                  onToggle={() => setXrefOpen((v) => !v)}
                  onJump={async (a) => {
                    await openFunction(a);
                    // Caller rows carry the exact referencing instruction;
                    // land on that line, not just inside its function.
                    setSelected(a);
                  }}
                />
            </div>

            {rightOpen && (
              <Divider onDrag={(dx) => setRightW((w) => Math.min(720, Math.max(240, w - dx)))} />
            )}
            {rightOpen && (
            <div className="right" style={{ width: rightW, flex: `0 0 ${rightW}px` }}>
              <div className="detail-sec yara-sec">
                <h4 className="static">
                  <span className="stitle">YARA</span>
                  <span className="sright">
                    {yaraRules ? (
                      <>
                        <span className={yara.length ? "sr-bad" : "sr-dim"}>
                          {yara.length} matched
                        </span>
                        <span className="elink" onClick={clearYara}>
                          clear
                        </span>
                      </>
                    ) : (
                      <span className="elink" onClick={loadYara}>
                        load rules
                      </span>
                    )}
                  </span>
                </h4>
                {yaraRules && (
                  <div className="sbody">
                    {yara.length === 0 && (
                      <div className="kv">
                        <span className="v dim">no rule matched this image</span>
                      </div>
                    )}
                    {yara.map((m, i) => (
                      <div
                        className="yhit"
                        key={i}
                        title={m.meta.map(([k, v]) => `${k}: ${v}`).join(", ")}
                      >
                        <span className="yrule">{m.rule}</span>
                        {m.tags.length > 0 && (
                          <span className="ytags">{m.tags.join(" ")}</span>
                        )}
                        <span className="ypat">
                          {m.patterns.reduce((n, [, c]) => n + c, 0)} hits
                        </span>
                      </div>
                    ))}
                    <div className="signote">
                      matches are folded into the triage verdict above, as
                      <code> knife info --rules</code> does
                    </div>
                  </div>
                )}
              </div>
              {detail && <DetailPanel d={detail} driver={driverFull} />}
            </div>
            )}
            {agentOpen && agentDock === "right" && (
              <>
                <Divider onDrag={(dx) => setAgentW((w) => Math.min(760, Math.max(280, w - dx)))} />
                <div className="agent-col" style={{ width: agentW, flex: `0 0 ${agentW}px` }}>
                  {agentEl}
                </div>
              </>
            )}
            {/* The whole file, down the far edge — outside the panes that
                collapse, because an overview you have to open is not one. */}
            <NavigatorBand
              overview={overview}
              current={selected ?? current}
              orientation="vertical"
              onSeek={(va) => {
                // A click may land on code or on data; the disassembly tab
                // renders both (a data view for a non-function address), so seek
                // there and let openFunction resolve it.
                setTab("disasm");
                void openFunction(va);
              }}
            />
          </>
        )}
      </div>

      {opened && agentOpen && agentDock === "bottom" && agentEl}

      {opened && console_ && (
        <Console onClose={() => setConsole(false)} onJump={(a) => openFunction(a)} />
      )}

      {opened && inspectAt && (
        <HexInspector addr={inspectAt} onSeek={setInspectAt} onClose={() => setInspectAt(null)} />
      )}

      {opened && (
        <div className="statusbar">
          <span className="sb-fn">{curName || "—"}</span>
          {pickedFinding &&
            (() => {
              const i = findings.findIndex(
                (f) =>
                  f.addr === pickedFinding.addr && f.pattern === pickedFinding.pattern,
              );
              return i >= 0 ? (
                <span className="sb-finding">
                  ⚑ {i + 1}/{findings.length}
                </span>
              ) : null;
            })()}
          {(() => {
            const f = current ? fnByAddr.get(current) : undefined;
            return f ? (
              <span className="sb-meta">
                {f.blocks} blocks · {f.size} bytes · {f.incoming} refs
              </span>
            ) : null;
          })()}
          <div className="spacer" />
          <span className="sb-keys">
            {(
              [
                ["ctrl+p", "open"],
                ["g", "goto"],
                ["/", "filter"],
                ["d", "pseudo"],
                ["f", "graph"],
                ["x", "xrefs"],
                ["?", "all keys"],
              ] as const
            ).map(([k, label]) => (
              <span className="sb-key" key={k}>
                <kbd>{k}</kbd>
                {label}
              </span>
            ))}
          </span>
        </div>
      )}

      {toasts.length > 0 && (
        <div className="toasts">
          {toasts.map((t) => (
            <div
              key={t.id}
              className={"toast" + (t.ok ? " ok" : "")}
              onClick={() => setToasts((all) => all.filter((x) => x.id !== t.id))}
            >
              {t.text}
            </div>
          ))}
        </div>
      )}

      {busy && (
        <div className="overlay loading">
          <div className="loadbox">
            <div className="spinner" />
            <div className="lphase">{phase || "analyzing"}…</div>
            <div className="lhint">reading the bytes on disk · the target is never executed</div>
          </div>
        </div>
      )}

      {menu && (
        <LineMenu at={menu.at} items={menu.items} onClose={() => setMenu(null)} />
      )}

      {prompt && (
        <div className="overlay" onMouseDown={() => setPrompt(null)}>
          <div className="askbox" onMouseDown={(e) => e.stopPropagation()}>
            <div className="asktitle">{prompt.title}</div>
            <input
              className="palette-input"
              autoFocus
              defaultValue={prompt.value}
              placeholder={prompt.hint}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  const v = (e.target as HTMLInputElement).value;
                  setPrompt(null);
                  prompt.run(v);
                } else if (e.key === "Escape") {
                  setPrompt(null);
                }
              }}
            />
            <div className="askfoot">
              <span>{prompt.hint}</span>
              <span>↵ apply</span>
              <span>esc cancel</span>
            </div>
          </div>
        </div>
      )}

      {palette && (
        <Palette
          functions={functions}
          strings={strings}
          onPick={(sel) => openFunction(sel)}
          onClose={() => setPalette(false)}
        />
      )}

      {help && <KeyMap onClose={() => setHelp(false)} />}
    </div>
  );
}
