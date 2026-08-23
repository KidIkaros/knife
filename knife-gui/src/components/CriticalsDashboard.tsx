import { useMemo, useState } from "react";
import type { Finding } from "../api";

/**
 * The criticals war-room: every ranked finding at once, full width, with its
 * severity, reachability, and the provenance the audit recovered — the same
 * evidence the attack-surface pane shows one at a time, laid out to scan and
 * triage. Click a row to jump to the site; "why" opens its proof chain.
 */

type Filt = "all" | "high" | "reachable";
const sev = (s: number) => (s >= 3 ? "H" : s >= 2 ? "M" : "L");

export function CriticalsDashboard({
  findings,
  onJump,
  onEvidence,
}: {
  findings: Finding[];
  onJump: (f: Finding) => void;
  onEvidence: (f: Finding) => void;
}) {
  const [filt, setFilt] = useState<Filt>("all");
  const [q, setQ] = useState("");

  const high = findings.filter((f) => f.severity >= 3).length;
  const reach = findings.filter((f) => f.reachable).length;

  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return findings.filter((f) => {
      if (filt === "high" && f.severity < 3) return false;
      if (filt === "reachable" && !f.reachable) return false;
      if (needle) {
        return `${f.pattern} ${f.api} ${f.func ?? ""} ${f.detail}`
          .toLowerCase()
          .includes(needle);
      }
      return true;
    });
  }, [findings, filt, q]);

  return (
    <div className="criticals">
      <div className="crit-head">
        <div className="crit-counts">
          <span className="crit-total">{findings.length} findings</span>
          <span className="crit-hi" data-none={high === 0}>
            {high} high
          </span>
          <span className="crit-reach">{reach} reachable</span>
        </div>
        <div className="crit-filters">
          {(["all", "high", "reachable"] as Filt[]).map((f) => (
            <button
              key={f}
              className={"crit-filt" + (filt === f ? " on" : "")}
              onClick={() => setFilt(f)}
            >
              {f}
            </button>
          ))}
          <input
            className="crit-search inline-input"
            placeholder="filter findings…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
      </div>

      <div className="crit-list">
        {findings.length === 0 && (
          <div className="crit-empty">no findings — the attack surface is clean</div>
        )}
        {findings.length > 0 && shown.length === 0 && (
          <div className="crit-empty">nothing matches the filter</div>
        )}
        {shown.map((f, i) => (
          <div
            key={`${f.addr}-${f.pattern}-${i}`}
            className={"crit-row s" + Math.min(f.severity, 3)}
            onClick={() => onJump(f)}
            title="click: jump to the call site"
          >
            <span className={"crit-sev s" + Math.min(f.severity, 3)}>{sev(f.severity)}</span>
            <div className="crit-main">
              <div className="crit-top">
                <span className="crit-pat">{f.pattern.replace(/-/g, " ")}</span>
                <span className="crit-api">{f.api}</span>
                <span className="crit-in">in {f.func ?? "?"}</span>
                <span className="crit-addr">@ {f.addr.replace("0x", "")}</span>
                <span className={"crit-reach-b " + (f.reachable ? "yes" : "no")}>
                  {f.reachable ? "reachable" : "unproven"}
                </span>
              </div>
              <div className="crit-detail">{f.detail}</div>
            </div>
            <button
              className="crit-why"
              title="show the reachability proof and provenance"
              onClick={(e) => {
                e.stopPropagation();
                onEvidence(f);
              }}
            >
              why →
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
