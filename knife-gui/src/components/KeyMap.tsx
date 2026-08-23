/**
 * Every binding, on one card.
 *
 * The status bar shows the letters it fits; the rest lived only in this file.
 * A reverse-engineering tool is keyboard-first by temperament, so the map
 * belongs where the keys are: one press away, gone with Escape.
 */
const GROUPS: Array<[string, Array<[string, string]>]> = [
  [
    "navigate",
    [
      ["ctrl+p", "quick-open a function, string, or address"],
      ["g", "the same quick-open"],
      ["/", "filter the function list"],
      ["alt+← / →", "back / forward through where you came from"],
      ["[ / ]", "collapse or restore the left / right pane"],
    ],
  ],
  [
    "views",
    [
      ["d", "pseudocode for the open function"],
      ["f", "its control-flow graph"],
      ["h", "hex bytes at the selection"],
      ["s", "cycle the left pane"],
      ["x", "cycle xrefs: callers · callees · paths"],
      ["ctrl+`", "the command console"],
      ["ctrl+f", "find in the current view"],
    ],
  ],
  [
    "analyze",
    [
      [". / ,", "next / previous ranked finding"],
      ["m", "bookmark the selection"],
      ["b / B", "next / previous bookmark"],
      ["y / Y", "copy address / function name"],
      ["C", "copy the listing (or selection)"],
      ["n", "rename the function"],
      ["c", "note on the selection"],
      ["P", "stage patch bytes at the selection"],
    ],
  ],
  [
    "in pseudocode",
    [
      ["t", "bind a type to the pointer base"],
      ["e", "name the field at the offset"],
      ["l", "rename a recovered variable"],
      ["p", "set an exact prototype"],
    ],
  ],
];

export function KeyMap({ onClose }: { onClose: () => void }) {
  return (
    <div className="overlay" onMouseDown={onClose}>
      <div className="helpcard" onMouseDown={(e) => e.stopPropagation()}>
        <div className="helphead">
          <span>keyboard</span>
          <span className="fclose" title="close" onClick={onClose}>
            ✕
          </span>
        </div>
        <div className="helpcols">
          {GROUPS.map(([title, rows]) => (
            <div className="helpgroup" key={title}>
              <div className="helpgrouptitle">{title}</div>
              {rows.map(([k, d]) => (
                <div className="helpline" key={k}>
                  <kbd>{k}</kbd>
                  <span>{d}</span>
                </div>
              ))}
            </div>
          ))}
        </div>
        <div className="helpfoot">esc closes</div>
      </div>
    </div>
  );
}
