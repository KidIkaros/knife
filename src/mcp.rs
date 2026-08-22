//! A Model Context Protocol server (`knife mcp`): a JSON-RPC 2.0 stream over
//! stdio that exposes the analysis as tools, so an agent (ARGUS, or any MCP
//! client) can drive knife directly. It reuses the same engine, listing,
//! decompiler, and audit the command line does; only the wire format is new.
//!
//! The stdio transport is newline-delimited JSON: one message per line, nothing
//! else on stdout (logs go to stderr), so the stream stays clean.

use crate::analysis::engine;
use crate::{tools, workspace::Session, ANALYSIS_BUDGET};
use anyhow::Result;
use serde_json::{json, Value};
use std::io::{BufRead, Write};

const PROTOCOL: &str = "2024-11-05";

/// The largest single frame we will buffer. MCP frames are one JSON object per
/// line; nothing this server does needs more, so a client that streams a huge
/// line fails closed (the rest of the line is drained and dropped) instead of
/// making us allocate it all.
const MAX_FRAME: usize = 16 * 1024 * 1024;

/// Read one newline-delimited frame. `Ok(None)` is clean EOF; `Ok(Some(vec))`
/// is a complete line without its newline; a line longer than `MAX_FRAME` is
/// drained to its newline so the stream stays framed, and returned truncated so
/// the caller can tell an oversized frame from a valid one.
fn read_frame(reader: &mut impl BufRead) -> std::io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    loop {
        if reader.read(&mut byte)? == 0 {
            return Ok(if buf.is_empty() { None } else { Some(buf) });
        }
        if byte[0] == b'\n' {
            return Ok(Some(buf));
        }
        if buf.len() < MAX_FRAME {
            buf.push(byte[0]);
        }
    }
}

/// Run the server until stdin closes.
pub fn run() -> Result<()> {
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let mut out = std::io::stdout();
    // The last file analysed, cached so repeated tool calls on one target do not
    // re-run the whole engine each time.
    let mut cache: Option<(String, Session)> = None;

    while let Some(frame) = read_frame(&mut reader)? {
        if frame.len() >= MAX_FRAME {
            continue; // oversized frame: drain-and-drop, fail closed
        }
        let line = String::from_utf8_lossy(&frame);
        if line.trim().is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            continue; // not JSON: ignore rather than crash the stream
        };
        let id = msg.get("id").cloned();
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("");

        // A message with no id is a notification: act on it, never reply.
        let Some(id) = id else {
            continue;
        };

        // The analysis it runs is a black box (dying inputs, adversarial bytes),
        // so contain every request: a panic is reported as an error reply and
        // the poisoned session is dropped so the next call re-analyzes clean.
        let panic_id = id.clone();
        let reply = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match method {
            "initialize" => ok(id.clone(), initialize()),
            "ping" => ok(id.clone(), json!({})),
            "tools/list" => ok(id.clone(), json!({ "tools": tool_list() })),
            "tools/call" => match call_tool(&msg, &mut cache) {
                Ok(text) => ok(id.clone(), tool_text(&text, false)),
                Err(e) => ok(id.clone(), tool_text(&format!("error: {e:#}"), true)),
            },
            _ => err(id.clone(), -32601, "method not found"),
        }))
        .unwrap_or_else(|_| {
            cache = None; // drop any state a panic may have poisoned
            err(panic_id, -32603, "internal error: the analysis panicked")
        });
        writeln!(out, "{}", serde_json::to_string(&reply)?)?;
        out.flush()?;
    }
    Ok(())
}

fn ok(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn err(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn tool_text(text: &str, is_error: bool) -> Value {
    json!({ "content": [{ "type": "text", "text": text }], "isError": is_error })
}

fn initialize() -> Value {
    json!({
        "protocolVersion": PROTOCOL,
        "capabilities": { "tools": {} },
        "serverInfo": { "name": "knife", "version": env!("CARGO_PKG_VERSION") },
    })
}

fn file_arg() -> Value {
    json!({ "type": "string", "description": "path to the binary" })
}

fn tool_list() -> Vec<Value> {
    // Read tools come from the shared catalog; MCP only adds its transport
    // `file` argument to each. Write tools are MCP-specific and listed after.
    let mut all: Vec<Value> = tools::catalog()
        .into_iter()
        .map(|t| {
            let mut schema = t.params;
            if let Some(props) = schema.get_mut("properties").and_then(Value::as_object_mut) {
                props.insert("file".into(), file_arg());
            }
            if let Some(req) = schema.get_mut("required").and_then(Value::as_array_mut) {
                req.insert(0, json!("file"));
            }
            tool(t.name, t.description, schema)
        })
        .collect();

    let addr = || json!({ "type": "string", "description": "address (0x...)" });
    all.push(tool(
        "set_name",
        "Persist an analyst name for the code at an address. Mutates the saved database.",
        json!({ "type": "object", "properties": {
            "file": file_arg(), "address": addr(), "name": { "type": "string" } },
            "required": ["file", "address", "name"] }),
    ));
    all.push(tool(
        "set_note",
        "Attach an analyst note to an address. Mutates the saved database.",
        json!({ "type": "object", "properties": {
            "file": file_arg(), "address": addr(), "note": { "type": "string" } },
            "required": ["file", "address", "note"] }),
    ));
    all.push(tool(
        "set_prototype",
        "Set a function prototype: a return C type and ordered parameter C types. Mutates the saved database.",
        json!({ "type": "object", "properties": {
            "file": file_arg(),
            "function": { "type": "string", "description": "name or address (0x...)" },
            "returns": { "type": "string" },
            "params": { "type": "array", "items": { "type": "string" } } },
            "required": ["file", "function", "returns"] }),
    ));
    all.push(tool(
        "stage_patch",
        "Stage a byte patch at a file offset (replacement bytes as hex). Staged only; exporting writes it out.",
        json!({ "type": "object", "properties": {
            "file": file_arg(),
            "offset": { "type": "string", "description": "file offset (0x...)" },
            "bytes": { "type": "string", "description": "replacement bytes as hex, e.g. 90 90" } },
            "required": ["file", "offset", "bytes"] }),
    ));
    all
}

fn tool(name: &str, description: &str, schema: Value) -> Value {
    json!({ "name": name, "description": description, "inputSchema": schema })
}

fn call_tool(msg: &Value, cache: &mut Option<(String, Session)>) -> Result<String> {
    let params = msg.get("params").cloned().unwrap_or(json!({}));
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing tool name"))?
        .to_string();
    let args = params.get("arguments").cloned().unwrap_or(json!({}));
    let file = args
        .get("file")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing `file`"))?
        .to_string();

    // Read tools dispatch through the shared catalog. A string result (a
    // disassembly, pseudocode, a hex dump) is returned verbatim; anything else
    // is JSON.
    if tools::catalog().iter().any(|t| t.name == name) {
        let sess = session(cache, &file)?;
        let v = tools::dispatch(sess, &name, &args)?;
        return Ok(match v {
            Value::String(text) => text,
            other => other.to_string(),
        });
    }

    // Write tools mutate the saved database, exactly as the CLI edit commands do;
    // the Session layer re-applies them on the next open.
    match name.as_str() {
        "set_name" | "set_note" => {
            let va = addr_arg(&args, "address")?;
            let key = if name == "set_name" { "name" } else { "note" };
            let text = args
                .get(key)
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("missing `{key}`"))?
                .to_string();
            let sess = session_mut(cache, &file)?;
            let at = va.wrapping_sub(engine::display_base(&sess.bin));
            if name == "set_name" {
                sess.db.set_name(at, &text);
            } else {
                sess.db.set_note(at, &text);
            }
            sess.db.save()?;
            Ok(json!({ "ok": true, "address": format!("0x{va:x}"), key: text }).to_string())
        }
        "set_prototype" => {
            let selector = args
                .get("function")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("missing `function`"))?
                .to_string();
            let returns = args
                .get("returns")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("missing `returns`"))?
                .to_string();
            let ps: Vec<String> = args
                .get("params")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let sess = session_mut(cache, &file)?;
            let func = resolve(&sess.an, &selector)
                .ok_or_else(|| anyhow::anyhow!("no function '{selector}'"))?;
            let at = func.addr.wrapping_sub(sess.an.display_base);
            let fname = func.name.clone();
            sess.db.set_prototype(at, &returns, &ps)?;
            sess.db.save()?;
            Ok(json!({ "ok": true, "function": fname,
                       "prototype": format!("{returns} ({})", ps.join(", ")) })
            .to_string())
        }
        "stage_patch" => {
            let offset = addr_arg(&args, "offset")?;
            let hex = args
                .get("bytes")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("missing `bytes`"))?;
            let raw = parse_hex_bytes(hex)?;
            let sess = session_mut(cache, &file)?;
            let n = sess.db.stage_patch(&sess.bytes, offset, &raw)?;
            sess.db.save()?;
            Ok(json!({ "ok": true, "offset": format!("0x{offset:x}"), "staged": n }).to_string())
        }
        other => anyhow::bail!("unknown tool '{other}'"),
    }
}

fn session<'a>(cache: &'a mut Option<(String, Session)>, file: &str) -> Result<&'a Session> {
    let stale = cache.as_ref().map(|(p, _)| p != file).unwrap_or(true);
    if stale {
        let sess = Session::open(file, None, ANALYSIS_BUDGET, "the MCP server")?;
        *cache = Some((file.to_string(), sess));
    }
    Ok(&cache.as_ref().expect("just set").1)
}

fn resolve<'a>(an: &'a engine::Analysis, sel: &str) -> Option<&'a engine::Function> {
    if let Some(f) = an.find_by_name(sel) {
        return Some(f);
    }
    let hex = sel.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(hex, 16)
        .ok()
        .and_then(|a| an.find_function(a).or_else(|| an.function_at(a)))
}

fn session_mut<'a>(
    cache: &'a mut Option<(String, Session)>,
    file: &str,
) -> Result<&'a mut Session> {
    let stale = cache.as_ref().map(|(p, _)| p != file).unwrap_or(true);
    if stale {
        let sess = Session::open(file, None, ANALYSIS_BUDGET, "the MCP server")?;
        *cache = Some((file.to_string(), sess));
    }
    Ok(&mut cache.as_mut().expect("just set").1)
}

fn addr_arg(args: &Value, key: &str) -> Result<u64> {
    let s = args
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing `{key}`"))?;
    let h = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(h, 16).map_err(|_| anyhow::anyhow!("bad address '{s}'"))
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() || !cleaned.len().is_multiple_of(2) {
        anyhow::bail!("hex bytes must be a non-empty even-length hex string");
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&cleaned[i..i + 2], 16).map_err(|_| anyhow::anyhow!("bad hex byte"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_and_tools_are_well_formed() {
        let init = initialize();
        assert_eq!(init["protocolVersion"], PROTOCOL);
        assert_eq!(init["serverInfo"]["name"], "knife");

        let tools = tool_list();
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        for want in [
            "list_functions",
            "disassemble",
            "decompile",
            "audit",
            "xrefs",
            "info",
        ] {
            assert!(names.contains(&want), "missing tool {want}");
        }
        // Every tool advertises an object input schema requiring a file.
        for t in &tools {
            assert_eq!(t["inputSchema"]["type"], "object");
            let req = t["inputSchema"]["required"].as_array().unwrap();
            assert!(req.iter().any(|r| r == "file"));
        }
    }

    #[test]
    fn a_tool_error_is_reported_in_band() {
        // No cached session and a missing file: the call should fail cleanly with
        // an error result rather than panicking.
        let mut cache = None;
        let msg = json!({
            "params": { "name": "info", "arguments": { "file": "/no/such/file.bin" } }
        });
        assert!(call_tool(&msg, &mut cache).is_err());
    }
}
