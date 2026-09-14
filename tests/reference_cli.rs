use reknife::address::StaticVa;
use reknife::api::references::{self, ReferenceView};
use reknife::workspace::Session;

#[test]
fn cli_call_sites_match_the_shared_terminal_query() {
    let root = std::env::temp_dir().join(format!("knife-reference-cli-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let target = root.join("fixture.exe");
    let database = root.join("fixture.json");
    std::fs::write(&target, reknife::formats::fixture::pe_with_iat_call()).unwrap();
    let session = Session::open(
        target.to_str().unwrap(),
        database.to_str(),
        reknife::ANALYSIS_BUDGET,
        "reference parity test",
    )
    .unwrap();
    let address = StaticVa(session.bin.image_base + session.bin.entry);
    let calls = references::query(&session, address, ReferenceView::Callees);
    assert!(!calls.is_empty(), "fixture must exercise a recovered call");
    for (verb, view, address) in [
        ("callees", ReferenceView::Callees, address),
        ("callers", ReferenceView::Callers, calls[0].target),
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_knife"))
            .arg(verb)
            .arg(&target)
            .args([
                "--function",
                &format!("0x{:x}", address.get()),
                "--json",
                "--db",
            ])
            .arg(&database)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let actual: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let expected = serde_json::to_value(references::query(&session, address, view)).unwrap();
        assert_eq!(actual, expected, "CLI {verb} and shared query disagree");
    }
    std::fs::remove_dir_all(&root).unwrap();
}
