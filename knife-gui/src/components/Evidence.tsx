import { useEffect, useState } from "react";
import { api, type Finding, type PathRow } from "../api";

/**
 * Why a finding is a finding.
 *
 * A list of dangerous API calls is something grep can produce. What makes this
 * an audit is the argument behind each one: where the value came from, how it
 * reached the call, and whether anything outside the binary can drive it. That
 * reasoning is the product, so it gets shown rather than summarised into a
 * severity colour — including the call chain itself, so "REACHABLE" is a proof
 * you can read, not a badge you must believe.
 */
export function Evidence({
  finding,
  onJump,
  onPaths,
}: {
  finding: Finding | null;
  onJump: (addr: string) => void;
  onPaths: () => void;
}) {
  const [paths, setPaths] = useState<PathRow[] | null>(null);
  const [copied, setCopied] = useState(false);

  // The walk is per finding; refetch when the picked sink changes.
  useEffect(() => {
    if (!finding) return;
    let live = true;
    setPaths(null);
    setCopied(false);
    api
      .pathsTo(finding.addr, 3)
      .then((p) => live && setPaths(p))
      .catch(() => live && setPaths([]));
    return () => {
      live = false;
    };
  }, [finding?.addr]);

  const chainText = (rows: PathRow[]) =>
    rows
      .map((p) => p.hops.map((h) => `${h.name || h.addr}`).join(" → "))
      .join("\n");

  if (!finding) return null;

  const level = finding.severity >= 3 ? "HIGH" : finding.severity >= 2 ? "MEDIUM" : "LOW";
  const tone = finding.severity >= 3 ? "s3" : finding.severity >= 2 ? "s2" : "s1";

  return (
    <div className={"evidence " + tone}>
      <div className="ehead">
        <span className="elevel">{level}</span>
        <span
          className={"ereach " + (finding.reachable ? "yes" : "no")}
          title={
            finding.reachable
              ? "a call site sits in a function reachable from an entry point or export"
              : "no path from an entry point or export was found, which is not proof there is none"
          }
        >
          {finding.reachable ? "REACHABLE" : "UNPROVEN"}
        </span>
        <div className="spacer" />
        <span className="elink" onClick={onPaths}>
          show paths
        </span>
      </div>

      <div className="erow">
        <span className="ekey">pattern</span>
        <span className="epattern">{finding.pattern.replace(/-/g, " ")}</span>
        <span className="ekey">sink</span>
        <span className="esink" onClick={() => onJump(finding.addr)}>
          {finding.api} @ {finding.addr}
        </span>
      </div>

      <div className="erow">
        <span className="ekey">signal</span>
        <span className="echain">
          <b>{finding.source}</b>
          <i>{"→"}</i>DATA FLOW<i>{"→"}</i>
          <b>{finding.api.toUpperCase()}</b>
        </span>
        {finding.func && (
          <>
            <span className="ekey">in</span>
            <span className="efunc">{finding.func}</span>
          </>
        )}
      </div>

      <div className="erow why">
        <span className="ekey">why</span>
        <span className="ewhy">{finding.detail}</span>
      </div>

      <div className="erow why">
        <span className="ekey">proof</span>
        <span className="eproof">
          {paths === null
            ? "walking…"
            : paths.length === 0
              ? "no path from an entry point or export"
              : paths.slice(0, 3).map((p) => (
                  <div className="epath" key={p.hops[0]?.addr} onClick={() => p.hops[0] && onJump(p.hops[0].addr)}>
                    {p.hops.map((h, i) => (
                      <span key={i}>
                        {i > 0 && <i>{" → "}</i>}
                        <b title={h.addr}>{h.name || h.addr}</b>
                      </span>
                    ))}
                  </div>
                ))}
        </span>
        {paths !== null && paths.length > 0 && (
          <span
            className="elink"
            title="copy the chains as text"
            onClick={() => {
              void navigator.clipboard.writeText(chainText(paths));
              setCopied(true);
              setTimeout(() => setCopied(false), 1500);
            }}
          >
            {copied ? "copied" : "copy"}
          </span>
        )}
      </div>
    </div>
  );
}
