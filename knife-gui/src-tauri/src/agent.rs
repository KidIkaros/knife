//! The agent pane: a model that can read this binary through knife's own tools.
//!
//! knife already exposes its analysis to agents over MCP (`knife mcp`). This is
//! the same idea inside the window: the model asks for a disassembly or an
//! audit, the request runs locally against the open `Session`, and the answer
//! goes back as a tool result. The analysis never leaves the engine; only the
//! text of what it produced does.
//!
//! Three deliberate limits:
//!
//! * **Read-only.** The tool list has no writes. The model can argue that a
//!   function should be called `parse_header`; applying that is the analyst's
//!   click. An agent that renames things on its own is very hard to unpick
//!   later, and its mistakes look exactly like your own work.
//! * **Consent per binary.** Code from the open file is sent to a third party.
//!   That is fine for a CTF binary and possibly a firing offence for a client's,
//!   so it is off until enabled for a specific file, remembered by hash.
//! * **The key lives in the OS keyring**, never in this repo, a config file, or
//!   the webview.

use crate::state::AppState;
use anyhow::{anyhow, Result};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;
use tauri::{Emitter, State};

const SERVICE: &str = "knife-gui";
const ACCOUNT: &str = "openrouter";
const ENDPOINT: &str = "https://openrouter.ai/api/v1/chat/completions";

/// Set by `agent_cancel` to stop the turn in flight. One turn runs at a
/// time, so a single flag is enough; `agent_ask` clears it at the start.
static CANCEL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// How many rounds of tool calls to allow before requiring an answer.
///
/// Reading a binary genuinely takes several steps — list the functions, look at
/// one, follow a call, check what reaches it — so this is not a tight budget.
/// What matters more is what happens at the end of it: see `force_answer`.
const MAX_TOOL_ROUNDS: usize = 16;
/// Autopilot drives a whole investigation, so it gets a deeper tool budget.
const AUTOPILOT_ROUNDS: usize = 40;

/// Rows returned to the model from a listing tool. Enough to reason about,
/// bounded so a large function cannot blow the context in one call.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// What the pane shows after a turn: the reply, and what the model looked at
/// to produce it.
#[derive(Serialize)]
pub struct AgentTurn {
    pub reply: String,
    /// Tool calls made, in order, for the transcript.
    pub steps: Vec<AgentStep>,
    /// The full message list, to be sent back as history next turn.
    pub history: Vec<ChatMessage>,
    /// Edits the model proposed. Applying one is the analyst's click; the agent
    /// never writes.
    pub suggestions: Vec<Suggestion>,
    /// Edits autopilot applied automatically (high-confidence only). Empty for
    /// an ordinary turn. Each is reversible.
    pub applied: Vec<Applied>,
}

/// An edit autopilot applied on its own — a high-confidence rename or note. The
/// analyst can undo it; every one maps to an existing clear command.
#[derive(Serialize, Clone)]
pub struct Applied {
    /// "rename" or "note".
    pub kind: &'static str,
    /// Display address the edit landed on.
    pub addr: String,
    pub selector: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// An edit the model recommends. Recording it is read-only; the frontend turns
/// it into an Apply button that calls the ordinary validated write command.
#[derive(Serialize, Clone)]
pub struct Suggestion {
    /// "rename", "prototype", or "note".
    pub kind: &'static str,
    /// Function name or hex address the edit applies to.
    pub selector: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub returns: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// "high" | "medium" | "low" — how sure the model is. Autopilot applies
    /// high-confidence edits automatically; the analyst clicks the rest.
    pub confidence: String,
    /// Why the model proposed it, for the analyst deciding whether to apply.
    pub reason: String,
}

#[derive(Serialize, Clone)]
pub struct AgentStep {
    pub tool: String,
    pub args: String,
    /// Truncated for display; the model saw the whole thing.
    pub preview: String,
}

// ── key handling ────────────────────────────────────────────────────────────

fn entry() -> Result<keyring::Entry> {
    keyring::Entry::new(SERVICE, ACCOUNT).map_err(|e| anyhow!("keyring unavailable: {e}"))
}

#[tauri::command]
pub fn agent_set_key(key: String) -> Result<(), String> {
    let key = key.trim().to_string();
    if key.is_empty() {
        return entry()
            .and_then(|e| e.delete_credential().map_err(|e| anyhow!("{e}")))
            .map_err(|e| e.to_string());
    }
    entry()
        .and_then(|e| e.set_password(&key).map_err(|e| anyhow!("{e}")))
        .map_err(|e| e.to_string())
}

/// Whether a key is stored. The key itself is never returned to the frontend.
#[tauri::command]
pub fn agent_has_key() -> bool {
    entry()
        .and_then(|e| e.get_password().map_err(|e| anyhow!("{e}")))
        .is_ok()
}

fn read_key() -> Result<String> {
    entry()?
        .get_password()
        .map_err(|_| anyhow!("no OpenRouter key stored: add one in the agent pane"))
}

// ── the tools the model may call ────────────────────────────────────────────

/// The tool schema, in OpenAI function-calling form. Every one of these is a
/// read: nothing here can change the database.
fn tool_schema() -> Value {
    // Read tools come from reknife's shared catalog, so the agent gains every
    // analysis at once. The agent adds the propose_* tools, which record a
    // suggestion for the analyst rather than run.
    let mut tools: Vec<Value> = reknife::tools::catalog()
        .into_iter()
        .map(|t| {
            json!({
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.params,
                }
            })
        })
        .collect();

    let f = |name: &str, desc: &str, props: Value, required: Vec<&str>| {
        json!({
            "type": "function",
            "function": {
                "name": name,
                "description": desc,
                "parameters": { "type": "object", "properties": props, "required": required },
            }
        })
    };
    let confidence = || {
        json!({
            "type": "string",
            "enum": ["high", "medium", "low"],
            "description": "how sure you are; autopilot applies high-confidence edits automatically",
        })
    };
    tools.push(f(
        "propose_rename",
        "Recommend renaming a function. Does not modify anything; it surfaces an Apply button (and in autopilot, a high-confidence rename is applied automatically). selector is the current name or hex address.",
        json!({"selector": {"type": "string"}, "new_name": {"type": "string"}, "confidence": confidence(), "reason": {"type": "string"}}),
        vec!["selector", "new_name", "reason"],
    ));
    tools.push(f(
        "propose_prototype",
        "Recommend a function prototype. Read-only like propose_rename. returns is a C type; params an array of C types in order.",
        json!({"function": {"type": "string"}, "returns": {"type": "string"}, "params": {"type": "array", "items": {"type": "string"}}, "confidence": confidence(), "reason": {"type": "string"}}),
        vec!["function", "returns", "reason"],
    ));
    tools.push(f(
        "propose_note",
        "Recommend an analyst note at an address: a finding, a function's role, or a caveat worth recording. selector is a hex address or function name.",
        json!({"selector": {"type": "string"}, "note": {"type": "string"}, "confidence": confidence(), "reason": {"type": "string"}}),
        vec!["selector", "note", "reason"],
    ));
    json!(tools)
}

fn run_tool(state: &State<AppState>, name: &str, args: &Value) -> Result<String> {
    state.read(|l| {
        let v = reknife::tools::dispatch(&l.session, name, args)?;
        Ok(match v {
            Value::String(text) => text,
            other => serde_json::to_string_pretty(&other).unwrap_or_else(|_| other.to_string()),
        })
    })
}

/// Apply the high-confidence renames and notes autopilot proposed, in one edit
/// (a single re-analysis for the batch). Ordinary turns apply nothing.
fn apply_high(
    app: &tauri::AppHandle,
    state: &State<AppState>,
    suggestions: &[Suggestion],
    autopilot: bool,
) -> Vec<Applied> {
    if !autopilot {
        return Vec::new();
    }
    let high: Vec<&Suggestion> = suggestions
        .iter()
        .filter(|s| s.confidence == "high" && matches!(s.kind, "rename" | "note"))
        .collect();
    if high.is_empty() {
        return Vec::new();
    }
    let applied = state
        .edit(|sess| {
            let base = reknife::analysis::engine::display_base(&sess.bin);
            let mut applied: Vec<Applied> = Vec::new();
            for s in &high {
                match s.kind {
                    "rename" => {
                        let Some(new) = s.new_name.as_deref() else {
                            continue;
                        };
                        if !reknife::db::valid_identifier(new) {
                            continue;
                        }
                        let Some(f) = crate::commands::resolve(&sess.an, &s.selector) else {
                            continue;
                        };
                        let va = f.addr;
                        sess.db.set_name(va.wrapping_sub(base), new);
                        applied.push(Applied {
                            kind: "rename",
                            addr: format!("0x{va:x}"),
                            selector: s.selector.clone(),
                            name: Some(new.to_string()),
                            note: None,
                        });
                    }
                    "note" => {
                        let Some(text) = s.note.as_deref() else {
                            continue;
                        };
                        let va = crate::commands::resolve(&sess.an, &s.selector)
                            .map(|f| f.addr)
                            .or_else(|| crate::commands::parse_addr(&s.selector).ok());
                        let Some(va) = va else { continue };
                        sess.db.set_note(va.wrapping_sub(base), text);
                        applied.push(Applied {
                            kind: "note",
                            addr: format!("0x{va:x}"),
                            selector: s.selector.clone(),
                            name: None,
                            note: Some(text.to_string()),
                        });
                    }
                    _ => {}
                }
            }
            Ok(applied)
        })
        .unwrap_or_default();
    for a in &applied {
        emit(app, json!({ "kind": "applied", "applied": a }));
    }
    applied
}

fn system_prompt(target: &str, is_driver: bool, autopilot: bool) -> String {
    let mut p = format!(
        "You are assisting a reverse engineer working on {target} inside knife, a static \
         binary analysis tool. Use the tools to read the binary rather than guessing; if you \
         have not looked at a function, say so instead of inventing its behaviour. Prefer \
         concrete evidence: addresses, call chains, the audit's own reasoning. You cannot \
         modify the analysis database; when something should be renamed or retyped, say what \
         and why, and the analyst will apply it. The binary is never executed. Answer as soon \
         as you can support an answer, and never repeat a tool call you have already made with \
         the same arguments, since it returns the same bytes."
    );
    if autopilot {
        p.push_str(
            " AUTOPILOT MODE. Work autonomously and do not ask the analyst questions; run the              whole investigation yourself and finish with one report. Method: (1) Survey — call              info, audit, and strings, and note the entry point, exports, and the imported APIs              that matter (memory, process/token, crypto, network, registry, device I/O).              (2) Prioritise — build a short target list from the audit findings, the dangerous              imports, the entry and exports, and, for a driver, the IOCTL dispatch; highest              severity and most reachable first. (3) Investigate each target — decompile it, read              the sinks in context, and use xrefs and paths_to to show how caller-controlled input              reaches it and whether it is reachable from an entry point, export, or IOCTL;              separate a concrete exploitable site from a generic pattern the audit merely              pattern-matched. (4) As you work out a function's role, call propose_rename with a              precise name so the analyst is left with a labelled binary. Keep going until you have              covered the high-value targets, then STOP calling tools and write the report.              Finish with markdown sections: '## Verdict' (one line: is anything critical, and the              overall risk), '## Criticals' (each: title, address, why it matters, what the              attacker controls, the reachability chain, and exploitability — concrete,              needs-conditions, or theoretical), '## Interesting' (lower-severity but notable              behaviour, with addresses), and '## Map' (the functions you named and their roles).              Be honest about coverage: state what you did not reach. Never invent behaviour you              did not read.",
        );
    }
    if is_driver {
        p.push_str(
            " This target is a Windows kernel driver and the analyst is hunting local \
             privilege escalation through a vulnerable driver (BYOVD). Work the IOCTL attack \
             surface reachable from user mode: find the IRP dispatch and the DeviceIoControl \
             handler, decode each IOCTL code, and trace what its handler does with the input \
             buffer the caller controls. Flag classic LPE primitives and name the IOCTL that \
             reaches each: arbitrary read/write (MmMapIoSpace, MmMapLockedPagesSpecifyCache, \
             a copy whose address or length is caller-controlled), physical memory mapping \
             (PhysicalMemory device, ZwMapViewOfSection), MSR read/write (__readmsr / \
             __writemsr reachable from an IOCTL), process-token theft (PsLookupProcessByProcessId \
             then swapping the Token pointer), and any routine taking a user pointer with no \
             ProbeForRead or ProbeForWrite. For each candidate say the IOCTL, what the attacker \
             controls, and what the primitive grants. Use audit and paths_to to prove a \
             handler is reachable before calling it a finding.",
        );
    }
    p
}

fn emit(app: &tauri::AppHandle, payload: Value) {
    let _ = app.emit("knife://agent", payload);
}

/// Pull a human message out of an OpenRouter error body.
fn error_message(text: &str) -> String {
    serde_json::from_str::<Value>(text)
        .ok()
        .and_then(|v| {
            v.get("error")
                .and_then(|e| e.get("message"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| text.chars().take(300).collect())
}

/// One reassembled streamed tool call.
#[derive(Default, Clone)]
struct ToolAcc {
    id: String,
    name: String,
    args: String,
}

/// Stream one completion, emitting a token event per content chunk, and return
/// the assembled text plus any tool calls the model asked for.
///
/// Streaming is the point of this pass: a turn can take many seconds of tool
/// round-trips, and a pane that shows nothing until it finishes reads as broken.
/// Here the answer types itself and each tool call surfaces as it lands.
async fn stream_once(
    client: &reqwest::Client,
    key: &str,
    app: &tauri::AppHandle,
    body: Value,
) -> Result<(String, Vec<ToolAcc>)> {
    let resp = client
        .post(ENDPOINT)
        .bearer_auth(key)
        .header("HTTP-Referer", "https://github.com/bl4ckr0ss3/knife")
        .header("X-Title", "knife")
        .json(&body)
        .send()
        .await
        .map_err(|e| anyhow!("request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(anyhow!("{}", error_message(&text)).context(format!("HTTP {status}")));
    }

    let mut stream = resp.bytes_stream();
    // Bytes, not text. A chunk boundary falls wherever the network puts it, which
    // can be in the middle of a multi-byte character: decoding each chunk on its
    // own turned that character into a replacement one, and when the split landed
    // inside a `data:` line the JSON no longer parsed and the whole delta was
    // dropped — losing a piece of the reply, or a fragment of a tool call's
    // arguments, with nothing said about it. Lines are decoded once they are
    // whole, so a character split across chunks survives.
    let mut buf: Vec<u8> = Vec::new();
    let mut content = String::new();
    let mut tools: Vec<ToolAcc> = Vec::new();
    let mut cancelled = false;

    while let Some(chunk) = stream.next().await {
        if CANCEL.load(std::sync::atomic::Ordering::Relaxed) {
            // Return what streamed so far rather than an error: a stop is a
            // choice, not a failure.
            cancelled = true;
            break;
        }
        let bytes = chunk.map_err(|e| anyhow!("stream interrupted: {e}"))?;
        buf.extend_from_slice(&bytes);

        // Server-sent events: one JSON object per data line; [DONE] closes.
        while let Some(nl) = buf.iter().position(|b| *b == b'\n') {
            let line = buf.drain(..=nl).collect::<Vec<u8>>();
            let line = String::from_utf8_lossy(&line);
            let line = line.trim();
            let Some(data) = line.strip_prefix("data:") else {
                continue;
            };
            let data = data.trim();
            if data.is_empty() || data == "[DONE]" {
                continue;
            }
            let Ok(v) = serde_json::from_str::<Value>(data) else {
                continue;
            };
            if let Some(msg) = v
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(Value::as_str)
            {
                return Err(anyhow!("{msg}"));
            }
            let delta = v.pointer("/choices/0/delta").cloned().unwrap_or(json!({}));

            if let Some(t) = delta.get("content").and_then(Value::as_str) {
                if !t.is_empty() {
                    content.push_str(t);
                    emit(app, json!({ "kind": "token", "text": t }));
                }
            }
            if let Some(calls) = delta.get("tool_calls").and_then(Value::as_array) {
                for tc in calls {
                    let idx = tc.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
                    while tools.len() <= idx {
                        tools.push(ToolAcc::default());
                    }
                    if let Some(id) = tc.get("id").and_then(Value::as_str) {
                        if !id.is_empty() {
                            tools[idx].id = id.to_string();
                        }
                    }
                    if let Some(f) = tc.get("function") {
                        if let Some(n) = f.get("name").and_then(Value::as_str) {
                            tools[idx].name.push_str(n);
                        }
                        if let Some(a) = f.get("arguments").and_then(Value::as_str) {
                            tools[idx].args.push_str(a);
                        }
                    }
                }
            }
        }
    }
    // A cancelled stream stops mid-message, so any tool call it had begun
    // accumulating is a fragment: the name may be half-written and the arguments
    // are rarely valid JSON. Running those is worse than running nothing, and the
    // user asked for nothing. Keep the prose, drop the calls.
    if cancelled {
        return Ok((content, Vec::new()));
    }
    Ok((content, tools))
}

#[tauri::command]
pub async fn agent_ask(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    model: String,
    question: String,
    history: Vec<ChatMessage>,
) -> Result<AgentTurn, String> {
    agent_turn(app, state, model, question, history, MAX_TOOL_ROUNDS, false)
        .await
        .map_err(|e| format!("{e:#}"))
}

/// Autopilot: the agent investigates the whole binary on its own and returns a
/// ranked report plus proposed renames. A fresh run (no history), deeper budget.
#[tauri::command]
pub async fn agent_autopilot(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    model: String,
) -> Result<AgentTurn, String> {
    let seed = "Auto-pilot this binary: investigate it end to end on your own and                 report the interesting findings and criticals."
        .to_string();
    agent_turn(app, state, model, seed, Vec::new(), AUTOPILOT_ROUNDS, true)
        .await
        .map_err(|e| format!("{e:#}"))
}

async fn agent_turn(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    model: String,
    question: String,
    history: Vec<ChatMessage>,
    rounds: usize,
    autopilot: bool,
) -> Result<AgentTurn> {
    let key = read_key()?;
    let (target, is_driver) = state
        .read(|l| {
            Ok((
                l.session.bin.path.clone(),
                reknife::analysis::driver::plausibly_a_driver(&l.session.bin),
            ))
        })
        .unwrap_or_else(|_| ("a binary".to_string(), false));

    let mut messages: Vec<ChatMessage> = Vec::new();
    if history.is_empty() {
        messages.push(ChatMessage {
            role: "system".into(),
            content: Some(system_prompt(&target, is_driver, autopilot)),
            tool_calls: None,
            tool_call_id: None,
            name: None,
        });
    } else {
        messages.extend(history);
    }
    messages.push(ChatMessage {
        role: "user".into(),
        content: Some(question),
        tool_calls: None,
        tool_call_id: None,
        name: None,
    });

    CANCEL.store(false, std::sync::atomic::Ordering::Relaxed);
    let client = reqwest::Client::new();
    let mut steps: Vec<AgentStep> = Vec::new();
    let mut suggestions: Vec<Suggestion> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for _ in 0..rounds {
        // Check before the request, not only inside the stream. The in-stream
        // check cannot fire until the first chunk arrives, so a stop between
        // rounds still paid for a whole round trip — several of them, on an
        // autopilot budget, each one billed and then thrown away.
        if CANCEL.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        emit(&app, json!({ "kind": "round" }));
        let body = json!({
            "model": model,
            "messages": messages,
            "tools": tool_schema(),
            "stream": true,
        });
        let (content, tools) = stream_once(&client, &key, &app, body).await?;

        let tool_calls_json = (!tools.is_empty()).then(|| {
            Value::Array(
                tools
                    .iter()
                    .map(|t| {
                        json!({
                            "id": t.id,
                            "type": "function",
                            "function": { "name": t.name, "arguments": t.args },
                        })
                    })
                    .collect(),
            )
        });
        messages.push(ChatMessage {
            role: "assistant".into(),
            content: (!content.is_empty()).then(|| content.clone()),
            tool_calls: tool_calls_json,
            tool_call_id: None,
            name: None,
        });

        if tools.is_empty() {
            emit(&app, json!({ "kind": "done" }));
            let applied = apply_high(&app, &state, &suggestions, autopilot);
            return Ok(AgentTurn {
                reply: content,
                steps,
                history: messages,
                suggestions,
                applied,
            });
        }

        for t in &tools {
            emit(
                &app,
                json!({ "kind": "tool", "tool": t.name, "args": t.args }),
            );
            let args: Value = serde_json::from_str(&t.args).unwrap_or(json!({}));

            // The propose_* tools do not read or write; they record a suggestion
            // the analyst can apply with a click, preserving the read-only rule.
            if t.name == "propose_rename"
                || t.name == "propose_prototype"
                || t.name == "propose_note"
            {
                let get = |k: &str| {
                    args.get(k)
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string()
                };
                let confidence = match args.get("confidence").and_then(Value::as_str) {
                    Some("high") => "high",
                    Some("low") => "low",
                    _ => "medium",
                }
                .to_string();
                let suggestion = match t.name.as_str() {
                    "propose_rename" => Suggestion {
                        kind: "rename",
                        selector: get("selector"),
                        new_name: Some(get("new_name")),
                        returns: None,
                        params: None,
                        note: None,
                        confidence,
                        reason: get("reason"),
                    },
                    "propose_note" => Suggestion {
                        kind: "note",
                        selector: get("selector"),
                        new_name: None,
                        returns: None,
                        params: None,
                        note: Some(get("note")),
                        confidence,
                        reason: get("reason"),
                    },
                    _ => Suggestion {
                        kind: "prototype",
                        selector: get("function"),
                        new_name: None,
                        returns: Some(get("returns")),
                        params: Some(
                            args.get("params")
                                .and_then(Value::as_array)
                                .map(|a| {
                                    a.iter()
                                        .filter_map(|v| v.as_str().map(str::to_string))
                                        .collect()
                                })
                                .unwrap_or_default(),
                        ),
                        note: None,
                        confidence,
                        reason: get("reason"),
                    },
                };
                emit(
                    &app,
                    json!({ "kind": "suggestion", "suggestion": suggestion }),
                );
                suggestions.push(suggestion);
                messages.push(ChatMessage {
                    role: "tool".into(),
                    content: Some("recorded; the analyst will decide whether to apply it".into()),
                    tool_calls: None,
                    tool_call_id: Some(t.id.clone()),
                    name: Some(t.name.clone()),
                });
                continue;
            }

            let signature = format!("{}{}", t.name, t.args);
            let result = if !seen.insert(signature) {
                "you already called this with the same arguments; the result is unchanged. \
                 Use what you have or call something different."
                    .to_string()
            } else {
                match run_tool(&state, &t.name, &args) {
                    Ok(text) => text,
                    Err(e) => format!("error: {e}"),
                }
            };
            emit(
                &app,
                json!({ "kind": "result", "tool": t.name,
                        "preview": result.chars().take(200).collect::<String>() }),
            );
            steps.push(AgentStep {
                tool: t.name.clone(),
                args: t.args.clone(),
                preview: result.chars().take(300).collect(),
            });
            messages.push(ChatMessage {
                role: "tool".into(),
                content: Some(result),
                tool_calls: None,
                tool_call_id: Some(t.id.clone()),
                name: Some(t.name.clone()),
            });
        }
    }

    // Out of rounds: answer from what it has rather than discarding the work.
    emit(&app, json!({ "kind": "round" }));
    messages.push(ChatMessage {
        role: "user".into(),
        content: Some(
            "Answer now from what you have read. Do not call more tools. If something is still \
             unknown, say what and why."
                .into(),
        ),
        tool_calls: None,
        tool_call_id: None,
        name: None,
    });
    let body =
        json!({ "model": model, "messages": messages, "tool_choice": "none", "stream": true });
    let (reply, _) = stream_once(&client, &key, &app, body).await?;
    emit(&app, json!({ "kind": "done" }));
    messages.push(ChatMessage {
        role: "assistant".into(),
        content: Some(reply.clone()),
        tool_calls: None,
        tool_call_id: None,
        name: None,
    });
    let applied = apply_high(&app, &state, &suggestions, autopilot);
    Ok(AgentTurn {
        reply,
        steps,
        history: messages,
        suggestions,
        applied,
    })
}

/// Stop the turn currently running.
#[tauri::command]
pub fn agent_cancel() {
    CANCEL.store(true, std::sync::atomic::Ordering::Relaxed);
}
