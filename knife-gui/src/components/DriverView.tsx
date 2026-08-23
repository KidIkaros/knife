import type { DriverReport } from "../api";

/**
 * What a kernel driver exposes, and what it lets you reach.
 *
 * The order is the order the question is asked in: which devices user mode can
 * open, which dispatch handlers those reach, which IOCTL codes they accept, and
 * finally which kernel primitives sit behind them. A primitive nothing can
 * reach is context; one reachable from a dispatch handler is the finding.
 */
export function DriverView({
  report,
  isDriver,
  reachableOnly,
  criticalOnly,
  ioctlsByHandler,
  onToggleReachable,
  onToggleCritical,
  onJump,
  onPseudo,
}: {
  report: DriverReport | null;
  reachableOnly: boolean;
  criticalOnly: boolean;
  /** IOCTLs keyed by their containing handler's address. */
  ioctlsByHandler?: Map<string, Array<{ code: string; addr: string; method: string }>>;
  onToggleReachable: () => void;
  onToggleCritical: () => void;
  /** Whether the open image is a driver at all, known before the report lands. */
  isDriver?: boolean;
  onJump: (addr: string) => void;
  onPseudo: (addr: string) => void;
}) {
  if (!report) {
    // "Not a driver" was shown for the whole time the report was being built,
    // so opening a real driver asserted the opposite of the truth for a beat.
    // The image already told us which of the two this is.
    return (
      <div className="list">
        <div className="empty-hint">
          {isDriver ? "reading the kernel surface…" : "not a driver"}
          <br />
          <span>
            {isDriver
              ? "devices, dispatch handlers and IOCTLs are on their way"
              : "no kernel surface was found in this image"}
          </span>
        </div>
      </div>
    );
  }

  return (
    <div className="list">
      {report.known_bad.length > 0 && (
        <>
          <div className="sym-module bad">KNOWN VULNERABLE ({report.known_bad.length})</div>
          {report.known_bad.map((k, i) => (
            <div key={i} className="drow">
              <span className="dname bad">{k.product || k.file}</span>
              <span className="ddetail">
                {[k.vendor, k.category].filter(Boolean).join(" ")}
                {k.malicious ? " malicious" : ""}
              </span>
            </div>
          ))}
        </>
      )}

      <div className="sym-module">IDENTITY</div>
      <div className="drow" onClick={() => onJump(report.entry)}>
        <span className="dname">{report.entry_name || "entry"}</span>
        <span className="ddetail">{report.entry.replace("0x", "")}</span>
      </div>
      {report.why.slice(0, 3).map((w, i) => (
        <div key={i} className="drow">
          <span className="ddetail wide">{w}</span>
        </div>
      ))}

      <div className="sym-module">DEVICES ({report.devices.length})</div>
      {report.devices.length === 0 && <div className="drow"><span className="ddetail">none found</span></div>}
      {report.devices.map((d, i) => (
        <div key={i} className="drow" onClick={() => onJump(d.addr)}>
          <span className={"dname" + (d.created ? " created" : "")}>{d.name}</span>
          <span className="ddetail">
            {d.created ? "created " : ""}
            {d.xrefs} refs
          </span>
        </div>
      ))}

      <div className="sym-module">IRP DISPATCH ({report.irp.length})</div>
      {report.irp.map((h, i) => {
        const codes = ioctlsByHandler?.get(h.addr) ?? [];
        return (
          <div key={i}>
            <div className="drow" onClick={() => onJump(h.addr)}>
              <span className="dname">{h.derived || h.name}</span>
              <span className="ddetail">
                {h.major} {h.addr.replace("0x", "")}
              </span>
            </div>
            {codes.length > 0 && (
              <div className="drow dsub" title="IOCTL codes this handler accepts">
                {codes.map((c) => (
                  <span
                    key={c.addr}
                    className={"ioctlchip" + (c.method === "METHOD_NEITHER" ? " bad" : "")}
                    title={`${c.code} · ${c.method} — click to open the comparison`}
                    onClick={(e) => {
                      e.stopPropagation();
                      onJump(c.addr);
                    }}
                  >
                    {c.code}
                  </span>
                ))}
              </div>
            )}
          </div>
        );
      })}

      <div className="sym-module">IOCTLS ({report.ioctls.length})</div>
      {report.ioctls.map((c, i) => {
        // METHOD_NEITHER hands the raw user-mode pointer to the driver: no
        // SystemBuffer, no probing by the I/O manager. It is the access method
        // behind a whole class of kernel LPEs, so it gets flagged on sight.
        const neither = c.method === "METHOD_NEITHER";
        return (
          <div
            key={i}
            className="drow"
            onClick={() => onJump(c.addr)}
            title={`CTL_CODE(${c.device_type}, ${c.function}, ${c.method}, ${c.access})${
              neither
                ? " — METHOD_NEITHER: the user buffer arrives unvalidated; check UserBuffer handling before trusting it"
                : ""
            }`}
          >
            <span className={"dname" + (neither ? " bad" : "")}>{c.code}</span>
            <span className="ddetail">
              dev {c.device_type} · fn {c.function} · {c.method} · access {c.access}
              {neither ? " · raw buffer" : ""}
            </span>
          </div>
        );
      })}

      <div className="sym-module">
        PRIMITIVES ({report.primitives.length})
        <span className="dfilters">
          <span
            className={"dfilter" + (reachableOnly ? " on" : "")}
            title="only primitives user mode can reach"
            onClick={(e) => {
              e.stopPropagation();
              onToggleReachable();
            }}
          >
            reachable
          </span>
          <span
            className={"dfilter" + (criticalOnly ? " on" : "")}
            title="only critical primitives"
            onClick={(e) => {
              e.stopPropagation();
              onToggleCritical();
            }}
          >
            critical
          </span>
        </span>
      </div>
      {report.primitives.length === 0 && (
        <div className="drow">
          <span className="ddetail">nothing matches the current filters</span>
        </div>
      )}
      {report.primitives.map((p, i) => (
        <div
          key={i}
          className="drow"
          onClick={() => p.sites[0] && onJump(p.sites[0].from)}
          title={p.sites.map((s) => `${s.in_func ?? "?"}+${s.at_off}`).join("\n")}
        >
          <span className={"sev s" + Math.min(p.severity, 3)}>
            {p.severity >= 3 ? "[H]" : p.severity >= 2 ? "[M]" : "[L]"}
          </span>
          <span className={"dname" + (p.reachable ? "" : " unreachable")}>{p.api}</span>
          <span className="ddetail">
            {p.class} {p.sites.length} site{p.sites.length === 1 ? "" : "s"}
            {p.reachable ? " reachable" : ""}
          </span>
          {p.sites[0] && (
            <span
              className="dlink"
              title="open the first call site in pseudocode"
              onClick={(e) => {
                e.stopPropagation();
                onPseudo(p.sites[0].from);
              }}
            >
              p
            </span>
          )}
        </div>
      ))}
    </div>
  );
}
