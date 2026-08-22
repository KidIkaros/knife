import { useEffect, useState } from "react";
import { api } from "../api";

type Row = { label: string; hex: string; ascii: string };

const seek = (addr: string, delta: number): string => {
  const v = BigInt(addr) + BigInt(delta);
  return "0x" + (v < 0n ? 0n : v).toString(16);
};

/** The row's bytes as eight little-endian qwords (a partial tail renders empty). */
function qwords(hex: string): Array<[string, bigint]> {
  const bytes = hex.split(" ").map((b) => parseInt(b, 16));
  const out: Array<[string, bigint]> = [];
  for (let i = 0; i < bytes.length; i += 8) {
    if (i + 8 > bytes.length) break;
    let v = 0n;
    for (let j = 7; j >= 0; j--) v = (v << 8n) | BigInt(bytes[i + j]);
    out.push([v.toString(16).padStart(16, "0"), v]);
  }
  return out;
}

/**
 * The bytes under the cursor.
 *
 * Disassembly tells you what the instruction does; this shows what it touches.
 * Paged in 64-byte steps so a table or an imported string can be walked the
 * way the hex verb walks it in the terminal — and a qword that looks like a
 * pointer is one click from becoming the view itself.
 */
export function HexInspector({
  addr,
  onSeek,
  onClose,
}: {
  addr: string;
  onSeek: (addr: string) => void;
  onClose: () => void;
}) {
  const [rows, setRows] = useState<Row[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    setRows(null);
    setErr(null);
    api
      .hexDump(addr)
      .then((r) => live && setRows(r))
      .catch((e) => live && setErr(String(e)));
    return () => {
      live = false;
    };
  }, [addr]);

  return (
    <div className="hexcard">
      <div className="hexhead">
        <span>data @ {addr}</span>
        <span className="hexnav">
          <span className="hnav" title="back 64 bytes" onClick={() => onSeek(seek(addr, -64))}>
            ‹
          </span>
          <span className="hnav" title="forward 64 bytes" onClick={() => onSeek(seek(addr, 64))}>
            ›
          </span>
          <span className="fclose" title="close" onClick={onClose}>
            ✕
          </span>
        </span>
      </div>
      {err ? (
        <div className="hexnote">{err}</div>
      ) : rows === null ? (
        <div className="hexnote">reading…</div>
      ) : (
        rows.map((r) => {
          const qs = qwords(r.hex);
          const tail = r.hex.split(" ").length % 8;
          return (
            <div className="hexrow" key={r.label}>
              <span className="hexlabel">{r.label.replace("0x", "")}</span>
              <span className="hexbytes">
                {qs.map(([text, v], i) =>
                  // A plausible pointer: mapped-space sized, not small data.
                  // Seeking to a wrong guess just reports "not in any section".
                  v >= 0x10000n ? (
                    <span
                      key={i}
                      className="hexptr"
                      title={"0x" + v.toString(16) + " — follow this pointer"}
                      onClick={() => onSeek("0x" + v.toString(16))}
                    >
                      {text.slice(0, 8)} {text.slice(8)}
                    </span>
                  ) : (
                    <span key={i} className="hexq">
                      {text.slice(0, 8)} {text.slice(8)}
                    </span>
                  ),
                )}
                {tail > 0 && <span className="hexq">{r.hex.split(" ").slice(-tail).join(" ")}</span>}
              </span>
              <span className="hexascii">{r.ascii}</span>
            </div>
          );
        })
      )}
      {!err && rows !== null && rows.length > 0 && (
        <div className="hexnote">underlined qwords are pointers — click to seek</div>
      )}
    </div>
  );
}
