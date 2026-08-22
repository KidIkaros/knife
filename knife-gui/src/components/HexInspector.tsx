import { useEffect, useState } from "react";
import { api } from "../api";

type Row = { label: string; hex: string; ascii: string };

const seek = (addr: string, delta: number): string => {
  const v = BigInt(addr) + BigInt(delta);
  return "0x" + (v < 0n ? 0n : v).toString(16);
};

/**
 * The bytes under the cursor.
 *
 * Disassembly tells you what the instruction does; this shows what it touches.
 * Paged in 64-byte steps so a table or an imported string can be walked the
 * way the hex verb walks it in the terminal.
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
        rows.map((r) => (
          <div className="hexrow" key={r.label}>
            <span className="hexlabel">{r.label.replace("0x", "")}</span>
            <span className="hexbytes">{r.hex}</span>
            <span className="hexascii">{r.ascii}</span>
          </div>
        ))
      )}
    </div>
  );
}
