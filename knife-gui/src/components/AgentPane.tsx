import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import {
  api,
  type AgentQuota,
  type Applied,
  type AgentStep,
  type ChatMessage,
  type ModelInfo,
  type Suggestion,
} from "../api";
import { Markdown } from "./Markdown";

export type AgentDock = "bottom" | "left" | "right";

/// A framed panel with the docked edge filled, so the button reads as "the
/// agent sits on the left / bottom / right" rather than the bar glyphs it used
/// to show, which said nothing.
function DockIcon({ side }: { side: AgentDock }) {
  // The filled sliver inside a 14×14 frame, per side.
  const fill =
    side === "left"
      ? { x: 2.5, y: 2.5, width: 4, height: 9 }
      : side === "right"
        ? { x: 7.5, y: 2.5, width: 4, height: 9 }
        : { x: 2.5, y: 8, width: 9, height: 3.5 };
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true">
      <rect
        x="1.5"
        y="1.5"
        width="11"
        height="11"
        rx="1.5"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.2"
      />
      <rect {...fill} rx="0.5" fill="currentColor" />
    </svg>
  );
}

interface Turn {
  question: string;
  reply: string;
  steps: AgentStep[];
  suggestions: Suggestion[];
  applied: Applied[];
}

interface Live {
  question: string;
  reply: string;
  steps: AgentStep[];
  suggestions: Suggestion[];
  status: string;
}

type AgentEvent =
  | { kind: "round" }
  | { kind: "token"; text: string }
  | { kind: "tool"; tool: string; args: string }
  | { kind: "result"; tool: string; preview: string }
  | { kind: "suggestion"; suggestion: Suggestion }
  | { kind: "applied" }
  | { kind: "retry"; attempt: number; of: number; seconds: number; why: string }
  | { kind: "paced"; seconds: number }
  | { kind: "done" };

/// The picker is filled live from the provider's own catalogue (see
/// `api.agentModels`), so free-vs-paid is real pricing and a retired model
/// simply is not in the list — the hardcoded list this replaced went stale the
/// moment a stealth model graduated and its id started returning 404.
///
/// This handful is only the fallback for when that fetch cannot run — offline,
/// or the endpoint is down — so the picker is never empty and the agent stays
/// usable. Anything not listed can still be typed in via "other…".
const FALLBACK_MODELS: ModelInfo[] = [
  { id: "z-ai/glm-5.3-flash", name: "Z.ai: GLM 5.3 Flash", free: false, context: 1310720 },
  { id: "z-ai/glm-4.5-air:free", name: "Z.ai: GLM 4.5 Air (free)", free: true, context: 131072 },
  { id: "deepseek/deepseek-chat-v3.1:free", name: "DeepSeek V3.1 (free)", free: true, context: 163840 },
  { id: "anthropic/claude-sonnet-4.5", name: "Anthropic: Claude Sonnet 4.5", free: false, context: 200000 },
  { id: "google/gemini-2.5-flash", name: "Google: Gemini 2.5 Flash", free: false, context: 1048576 },
];

/// The catalogue is fetched once per app run and shared across every mount of
/// the pane — reopening it should not hit the network again.
let modelCache: ModelInfo[] | null = null;
let modelFetch: Promise<ModelInfo[]> | null = null;
function loadModels(): Promise<ModelInfo[]> {
  if (modelCache) return Promise.resolve(modelCache);
  if (!modelFetch) {
    modelFetch = api
      .agentModels()
      .then((list) => {
        modelCache = list.length ? list : FALLBACK_MODELS;
        return modelCache;
      })
      .catch(() => {
        modelFetch = null; // a failure is not cached; a later open may succeed
        return FALLBACK_MODELS;
      });
  }
  return modelFetch;
}

const CUSTOM = "__custom__";

/// A context window as a short token count: 1310720 → "1.3M", 131072 → "128k".
function ctxLabel(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1).replace(/\.0$/, "")}M`;
  if (n >= 1000) return `${Math.round(n / 1000)}k`;
  return `${n}`;
}

function ModelOption({ m }: { m: ModelInfo }) {
  return (
    <option value={m.id} title={`${m.id} · ${ctxLabel(m.context)} context`}>
      {m.name}
      {m.context ? ` · ${ctxLabel(m.context)}` : ""}
    </option>
  );
}

const chatKey = (target: string) => `knife.agent.chat.${target}`;

function loadChat(target: string): { turns: Turn[]; history: ChatMessage[] } {
  try {
    const raw = localStorage.getItem(chatKey(target));
    if (raw) return JSON.parse(raw);
  } catch {
    // a cleared or corrupt store just starts an empty chat
  }
  return { turns: [], history: [] };
}

/**
 * The agent pane.
 *
 * The model reads this binary through knife's tools, and the turn streams: each
 * tool call appears as it is made, and the answer types itself. Replies render
 * as markdown so a returned table is a table; addresses stay clickable. It is
 * read-only — it can propose a rename or a prototype, and applying one is your
 * click, never its own.
 */
export function AgentPane({
  enabled,
  consented,
  targetName,
  targetKey,
  isDriver,
  hasKey,
  model,
  dock,
  onModel,
  onDock,
  onConsent,
  onNeedKey,
  onClose,
  onJump,
  onApply,
  onApplied,
}: {
  enabled: boolean;
  consented: boolean;
  targetName: string;
  targetKey: string;
  isDriver: boolean;
  hasKey: boolean;
  model: string;
  dock: AgentDock;
  onModel: (m: string) => void;
  onDock: (d: AgentDock) => void;
  onConsent: () => void;
  onNeedKey: () => void;
  onClose: () => void;
  onJump: (addr: string) => void;
  onApply: (s: Suggestion) => Promise<void>;
  onApplied: () => Promise<void> | void;
}) {
  const [turns, setTurns] = useState<Turn[]>([]);
  const [history, setHistory] = useState<ChatMessage[]>([]);
  const [applied, setApplied] = useState<Set<string>>(new Set());
  const [live, setLive] = useState<Live | null>(null);
  const [input, setInput] = useState("");
  const [error, setError] = useState<string | null>(null);
  // Typing an id the list does not carry.
  const [typing, setTyping] = useState(false);
  // What the provider says this key may do. Shown rather than guessed at: a
  // limit you can see is a limit you can plan around.
  const [quota, setQuota] = useState<AgentQuota | null>(null);
  const [models, setModels] = useState<ModelInfo[]>(modelCache ?? FALLBACK_MODELS);
  const [modelFilter, setModelFilter] = useState("");
  useEffect(() => {
    let alive = true;
    void loadModels().then((list) => {
      if (alive) setModels(list);
    });
    return () => {
      alive = false;
    };
  }, []);
  const known = models.some((m) => m.id === model);
  const grouped = useMemo(() => {
    const q = modelFilter.trim().toLowerCase();
    const hit = (m: ModelInfo) =>
      !q || m.id.toLowerCase().includes(q) || m.name.toLowerCase().includes(q);
    return {
      free: models.filter((m) => m.free && hit(m)),
      paid: models.filter((m) => !m.free && hit(m)),
    };
  }, [models, modelFilter]);
  const endRef = useRef<HTMLDivElement>(null);
  const liveRef = useRef(false);

  // Load the conversation for this binary, and reload when the binary changes.
  useEffect(() => {
    const { turns, history } = loadChat(targetKey);
    setTurns(turns);
    setHistory(history);
    setApplied(new Set());
    setLive(null);
    liveRef.current = false;
  }, [targetKey]);

  /// Write the conversation out, for the binary it belongs to.
  ///
  /// Saving used to be an effect watching the turns, which destroyed chats:
  /// switching binaries runs the load and the save in the same commit, and the
  /// save saw the *new* key while the turns it wrote were still the *old*
  /// binary's — so opening B overwrote B's saved conversation with A's. Saving
  /// where a turn actually completes means the key and the turns can never
  /// disagree.
  const saveChat = useCallback(
    (key: string, turns: Turn[], history: ChatMessage[]) => {
      if (!key) return;
      try {
        localStorage.setItem(chatKey(key), JSON.stringify({ turns, history }));
      } catch {
        // remembering the chat is a convenience, not a requirement
      }
    },
    [],
  );

  useEffect(() => {
    endRef.current?.scrollIntoView({ block: "end" });
  }, [turns, live]);

  // Ask once the key exists, and again after a turn — usage moves.
  useEffect(() => {
    if (!hasKey || !enabled) return;
    let live = true;
    api
      .agentQuota()
      .then((q) => live && setQuota(q))
      .catch(() => live && setQuota(null));
    return () => {
      live = false;
    };
  }, [hasKey, enabled, turns.length]);

  useEffect(() => {
    const un = listen<AgentEvent>("knife://agent", (e) => {
      if (!liveRef.current) return;
      const ev = e.payload;
      setLive((l) => {
        if (!l) return l;
        switch (ev.kind) {
          case "round":
            return { ...l, status: "thinking" };
          case "token":
            return { ...l, reply: l.reply + ev.text, status: "" };
          case "tool":
            return {
              ...l,
              status: `reading ${ev.tool}`,
              steps: [...l.steps, { tool: ev.tool, args: ev.args, preview: "" }],
            };
          case "result": {
            const steps = l.steps.slice();
            for (let i = steps.length - 1; i >= 0; i--) {
              if (steps[i].tool === ev.tool && !steps[i].preview) {
                steps[i] = { ...steps[i], preview: ev.preview };
                break;
              }
            }
            return { ...l, steps, status: "thinking" };
          }
          case "suggestion":
            return { ...l, suggestions: [...l.suggestions, ev.suggestion] };
          // Being made to wait is not the same as being broken, and the pane
          // used to show nothing at all until the whole turn failed.
          case "retry":
            return {
              ...l,
              status: `rate limited — retrying in ${ev.seconds}s (${ev.attempt}/${ev.of})`,
            };
          // Said once, when the pane decides to slow down for the rest of the
          // session. Otherwise the turn just appears to get slower for no reason.
          case "paced":
            return { ...l, status: `pacing requests for this model (${ev.seconds}s apart)` };
          case "done":
            return { ...l, status: "" };
          default:
            return l;
        }
      });
    });
    return () => {
      void un.then((f) => f());
    };
  }, []);

  const ask = async () => {
    const q = input.trim();
    if (!q || liveRef.current) return;
    // The binary this answer belongs to, taken now: a turn runs for a while and
    // the analyst may have moved on by the time it lands.
    const key = targetKey;
    setInput("");
    setError(null);
    setLive({ question: q, reply: "", steps: [], suggestions: [], status: "thinking" });
    liveRef.current = true;
    try {
      const t = await api.agentAsk(model, q, history);
      const turn: Turn = {
        question: q,
        reply: t.reply,
        steps: t.steps,
        suggestions: t.suggestions,
        applied: t.applied,
      };
      setTurns((all) => {
        const next = [...all, turn];
        saveChat(key, next, t.history);
        return next;
      });
      setHistory(t.history);
      if (t.applied.length) await onApplied();
    } catch (e) {
      setError(String(e));
    } finally {
      liveRef.current = false;
      setLive(null);
    }
  };

  const autopilot = async () => {
    if (liveRef.current) return;
    const key = targetKey;
    setError(null);
    setLive({
      question: "🛰 Autopilot — investigating this binary",
      reply: "",
      steps: [],
      suggestions: [],
      status: "surveying",
    });
    liveRef.current = true;
    try {
      const t = await api.agentAutopilot(model);
      const turn: Turn = {
        question: "🛰 Autopilot investigation",
        reply: t.reply,
        steps: t.steps,
        suggestions: t.suggestions,
        applied: t.applied,
      };
      setTurns((all) => {
        const next = [...all, turn];
        saveChat(key, next, t.history);
        return next;
      });
      setHistory(t.history);
      if (t.applied.length) await onApplied();
    } catch (e) {
      setError(String(e));
    } finally {
      liveRef.current = false;
      setLive(null);
    }
  };

  const newChat = () => {
    setTurns([]);
    setHistory([]);
    setApplied(new Set());
    try {
      localStorage.removeItem(chatKey(targetKey));
    } catch {
      /* ignore */
    }
  };

  const stepArgs = (raw: string): string => {
    try {
      const o = JSON.parse(raw || "{}");
      const parts = Object.entries(o)
        .map(([k, v]) => {
          const val = String(v);
          const short = val.length > 22 ? val.slice(0, 21) + "…" : val;
          // A single obvious argument reads better without its key.
          return k === "selector" || k === "query" ? short : `${k} ${short}`;
        })
        .filter(Boolean);
      return parts.join("  ");
    } catch {
      return "";
    }
  };

  const renderSteps = (steps: AgentStep[]) =>
    steps.length > 0 && (
      <div className="steps">
        {steps.map((s, j) => (
          <div className="step" key={j} title={s.preview}>
            <span className="stool">{s.tool}</span>
            {stepArgs(s.args) && <span className="sargs">{stepArgs(s.args)}</span>}
          </div>
        ))}
      </div>
    );

  const undoApplied = async (list: Applied[]) => {
    for (const a of list) {
      try {
        if (a.kind === "rename") await api.clearName(a.addr);
        else await api.clearNote(a.addr);
      } catch {
        // best-effort; a manual re-edit may have removed it already
      }
    }
    await onApplied();
  };

  const renderApplied = (list: Applied[]) =>
    list.length > 0 && (
      <div className="applied">
        <div className="applied-head">
          <span className="applied-tag">
            ⚡ autopilot applied {list.length} edit{list.length > 1 ? "s" : ""}
          </span>
          <button className="applied-undo" onClick={() => void undoApplied(list)}>
            undo
          </button>
        </div>
        {list.map((a, i) => (
          <div className="applied-item" key={i} onClick={() => onJump(a.addr)}>
            <span className="ai-kind">{a.kind}</span>
            <span className="ai-text">
              {a.selector}
              {a.name ? ` → ${a.name}` : ""}
              {a.note ? `: ${a.note}` : ""}
            </span>
          </div>
        ))}
      </div>
    );

  const suggestionLabel = (s: Suggestion) =>
    s.kind === "rename"
      ? `rename ${s.selector} → ${s.new_name}`
      : s.kind === "note"
        ? `note @ ${s.selector}: ${s.note}`
        : `prototype ${s.selector}: ${s.returns} (${(s.params ?? []).join(", ")})`;

  const renderSuggestions = (list: Suggestion[]) =>
    list.length > 0 && (
      <div className="suggestions">
        {list.map((s, j) => {
          const id = `${s.kind}:${s.selector}:${s.new_name ?? ""}:${s.returns ?? ""}`;
          const done = applied.has(id);
          return (
            <div className="suggestion" key={j} title={s.reason}>
              <span className="sug-kind">{s.kind}</span>
              <span className={"sug-conf c-" + s.confidence}>{s.confidence}</span>
              <span className="sug-text">{suggestionLabel(s)}</span>
              {done ? (
                <span className="sug-done">applied</span>
              ) : (
                <button
                  className="sug-apply"
                  onClick={async () => {
                    try {
                      await onApply(s);
                      setApplied((prev) => new Set(prev).add(id));
                    } catch (e) {
                      setError(String(e));
                    }
                  }}
                >
                  apply
                </button>
              )}
            </div>
          );
        })}
      </div>
    );

  const examples = isDriver
    ? [
        "Map the IOCTL attack surface and flag any LPE primitive.",
        "Is there an arbitrary read/write reachable from an IOCTL?",
        "Which handler runs with no ProbeForRead on the input buffer?",
      ]
    : [
        "What does this binary do?",
        "Explain the worst audit finding and whether it is reachable.",
        "Which functions parse untrusted input?",
      ];

  return (
    <div className={`agent dock-${dock}`}>
      <div className="panel-head">
        <span>agent</span>
        {isDriver && <span className="agent-mode">LPE hunt</span>}
        <div className="spacer" />
        <span className="dock-controls" title="Dock the agent pane">
          {(["left", "bottom", "right"] as AgentDock[]).map((d) => (
            <button
              key={d}
              className={"dockbtn" + (dock === d ? " on" : "")}
              title={`dock ${d}`}
              aria-label={`dock ${d}`}
              aria-pressed={dock === d}
              onClick={() => onDock(d)}
            >
              <DockIcon side={d} />
            </button>
          ))}
        </span>
        {!live && (
          <button className="act autopilot-btn" onClick={autopilot} title="Investigate autonomously">
            ▶ autopilot
          </button>
        )}
        {(turns.length > 0 || history.length > 0) && !live && (
          <button className="act" onClick={newChat}>
            new chat
          </button>
        )}
        <button className="act" onClick={onClose}>
          ✕
        </button>
      </div>

      {!enabled ? (
        <div className="agent-gate">
          <p>The agent is switched off.</p>
          <p className="sub">Turn it on in the top bar to use it on any binary.</p>
        </div>
      ) : !hasKey ? (
        <div className="agent-gate">
          <p>No OpenRouter key stored.</p>
          <p className="sub">
            The key is kept in Windows Credential Manager, not in a file or this repo.
          </p>
          <button className="btn" onClick={onNeedKey}>
            Add key
          </button>
        </div>
      ) : !consented ? (
        <div className="agent-gate warn">
          <p>Code from this binary would be sent to OpenRouter.</p>
          <p className="sub">
            Disassembly, pseudocode and strings from <b>{targetName}</b> leave your machine when you
            ask a question. Fine for your own binaries; think twice for someone else's.
          </p>
          <button className="btn" onClick={onConsent}>
            Enable for this binary
          </button>
        </div>
      ) : (
        <>
          <div className="agent-log">
            {turns.length === 0 && !live && (
              <div className="agent-hint">
                {isDriver
                  ? "Driver loaded. Ask it to hunt a privilege-escalation primitive; it reads the IOCTL surface with knife's tools and shows every call."
                  : "Ask about the open binary. The model reads it with knife's tools and shows every call it makes."}
                <div className="agent-eg">
                  {examples.map((ex) => (
                    <span key={ex} onClick={() => setInput(ex)}>
                      {ex}
                    </span>
                  ))}
                </div>
                <button className="autopilot-cta" onClick={autopilot}>
                  ▶ Auto-pilot this binary
                  <span className="sub">
                    survey → prioritise → deep-dive → ranked criticals report
                  </span>
                </button>
              </div>
            )}

            {turns.map((t, i) => (
              <div className="turn" key={i}>
                <div className="q">{t.question}</div>
                {renderSteps(t.steps)}
                <div className="a">
                  <Markdown text={t.reply} onJump={onJump} />
                </div>
                {renderSuggestions(t.suggestions)}
                {renderApplied(t.applied)}
              </div>
            ))}

            {live && (
              <div className="turn">
                <div className="q">{live.question}</div>
                {renderSteps(live.steps)}
                {live.reply && <div className="a streaming">{live.reply}</div>}
                {renderSuggestions(live.suggestions)}
                {live.status && (
                  <div className="agent-busy">
                    <span className="dot" />
                    {live.status}…
                    <button className="stopbtn" onClick={() => void api.agentCancel()}>
                      stop
                    </button>
                  </div>
                )}
              </div>
            )}

            {error && <div className="agent-err">{error}</div>}
            <div ref={endRef} />
          </div>

          <div className="cin">
            <span className="prompt">?</span>
            <input
              className="inline-input"
              placeholder={live ? "working…" : "ask about this binary"}
              value={input}
              disabled={!!live}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  void ask();
                } else if (e.key === "Escape") {
                  onClose();
                }
              }}
            />
            {quota && (
              <span
                className={"agent-quota" + (quota.free_tier ? " free" : "")}
                title={
                  quota.requests && quota.interval
                    ? `${quota.label || "this key"} — ${quota.requests} requests per ${quota.interval}` +
                      (quota.free_tier ? ", free tier" : "") +
                      `. Requests are spaced to stay inside it.`
                    : `${quota.label || "this key"} — usage ${quota.usage}`
                }
              >
                {quota.free_tier ? "free" : "paid"}
                {quota.requests && quota.interval ? ` · ${quota.requests}/${quota.interval}` : ""}
              </span>
            )}
            {/* A list, not a text box. The id had to be typed from memory, and
                a typo reads back as a failed request rather than a wrong name.
                The list is live from the provider (see loadModels), grouped by
                what actually costs money, with a filter because it is long. */}
            {models.length > 14 && (
              <input
                className="agent-model-filter"
                value={modelFilter}
                placeholder="filter models"
                title="Narrow the model list"
                onChange={(e) => setModelFilter(e.target.value)}
              />
            )}
            <select
              className="agent-model"
              value={known ? model : CUSTOM}
              title="Which model reads the binary"
              onChange={(e) => {
                if (e.target.value === CUSTOM) setTyping(true);
                else {
                  setTyping(false);
                  onModel(e.target.value);
                }
              }}
            >
              {grouped.free.length > 0 && (
                <optgroup label="Free">
                  {grouped.free.map((m) => (
                    <ModelOption key={m.id} m={m} />
                  ))}
                </optgroup>
              )}
              {grouped.paid.length > 0 && (
                <optgroup label="Paid">
                  {grouped.paid.map((m) => (
                    <ModelOption key={m.id} m={m} />
                  ))}
                </optgroup>
              )}
              {!known && (
                <option value={model} title={model}>
                  {model}
                </option>
              )}
              <option value={CUSTOM}>other…</option>
            </select>
            {typing && (
              <input
                className="agent-model-id"
                autoFocus
                defaultValue={model}
                placeholder="provider/model-id"
                title="An OpenRouter model id"
                onBlur={() => setTyping(false)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    const v = (e.target as HTMLInputElement).value.trim();
                    if (v) onModel(v);
                    setTyping(false);
                  } else if (e.key === "Escape") {
                    setTyping(false);
                  }
                }}
              />
            )}
          </div>
        </>
      )}
    </div>
  );
}
