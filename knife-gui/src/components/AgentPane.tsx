import { useCallback, useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { api, type Applied, type AgentStep, type ChatMessage, type Suggestion } from "../api";
import { Markdown } from "./Markdown";
import knifechan from "../assets/knifechan.png";

export type AgentDock = "bottom" | "left" | "right";

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

/// The models offered in the picker.
///
/// A short list, not a catalogue: OpenRouter carries hundreds and almost none of
/// them are worth pointing at a disassembler. What this work needs is a long
/// context — a decompiled function and its callers add up quickly — and tool
/// calling that holds together over a dozen rounds. The stealth entries are free
/// and rate limited hard, which is the trade being made when one is chosen.
/// Anything not listed can still be typed in.
const MODELS: Array<{ id: string; label: string; note: string }> = [
  { id: "stealth/ox-alpha", label: "ox-alpha", note: "stealth · free · rate limited" },
  { id: "anthropic/claude-sonnet-4", label: "Claude Sonnet 4", note: "strong tool use" },
  { id: "anthropic/claude-3.5-haiku", label: "Claude 3.5 Haiku", note: "fast, cheap" },
  { id: "openai/gpt-4o", label: "GPT-4o", note: "general purpose" },
  { id: "openai/gpt-4o-mini", label: "GPT-4o mini", note: "fast, cheap" },
  { id: "google/gemini-2.0-flash-001", label: "Gemini 2.0 Flash", note: "long context" },
  { id: "deepseek/deepseek-chat", label: "DeepSeek", note: "cheap, capable" },
  { id: "meta-llama/llama-3.3-70b-instruct", label: "Llama 3.3 70B", note: "open weights" },
];

const CUSTOM = "__custom__";

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
  const known = MODELS.some((m) => m.id === model);
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
        <img className="agent-avatar" src={knifechan} alt="" draggable={false} />
        <span>agent</span>
        {isDriver && <span className="agent-mode">LPE hunt</span>}
        <div className="spacer" />
        <span className="dock-controls" title="Dock position">
          {(["left", "bottom", "right"] as AgentDock[]).map((d) => (
            <button
              key={d}
              className={"dockbtn" + (dock === d ? " on" : "")}
              title={`dock ${d}`}
              onClick={() => onDock(d)}
            >
              {d === "left" ? "▏" : d === "right" ? "▕" : "▁"}
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
            {/* A list, not a text box. The id had to be typed from memory, and
                a typo reads back as a failed request rather than a wrong name. */}
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
              {MODELS.map((m) => (
                <option key={m.id} value={m.id} title={`${m.id} — ${m.note}`}>
                  {m.label}
                </option>
              ))}
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
