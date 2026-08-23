import type { Finding } from "../api";

const sevLabel = (s: number) => (s >= 3 ? "H" : s >= 2 ? "M" : "L");

export function AttackSurface({
  findings,
  selected,
  total,
  onPick,
}: {
  findings: Finding[];
  selected: string | null;
  /// How many findings exist before the severity chips narrowed them, so an
  /// empty list can tell the difference between "the audit found nothing" and
  /// "you are only looking at one band of what it found".
  total?: number;
  onPick: (f: Finding) => void;
}) {
  const hidden = (total ?? findings.length) - findings.length;
  return (
    <div className="list">
      {findings.length === 0 && (
        <div className="finding" style={{ color: "var(--faint)" }}>
          {hidden > 0
            ? `none at this severity — ${hidden} finding${hidden === 1 ? "" : "s"} at others`
            : "no findings"}
        </div>
      )}
      {findings.map((f, i) => (
        <div
          key={i}
          className={"finding" + (f.addr === selected ? " sel" : "")}
          onClick={() => onPick(f)}
        >
          <div className="top">
            <span className={"sev s" + f.severity}>[{sevLabel(f.severity)}]</span>
            <span className="pat">{f.pattern.replace(/-/g, " ")}</span>
            <span className="where">{f.func ?? f.addr.replace("0x", "")}</span>
          </div>
          <div className="detail">
            {f.api} @ {f.addr.replace("0x", "")}
            {f.reachable ? " · reachable" : ""}
          </div>
        </div>
      ))}
    </div>
  );
}
