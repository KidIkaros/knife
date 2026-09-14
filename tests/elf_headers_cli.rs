use std::process::Command;

#[test]
fn header_commands_match_core_and_reject_non_elf() {
    let root = std::env::temp_dir().join(format!("knife-elf-cli-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("fixture.elf");
    let bytes = reknife::formats::fixture::elf_with_plt_call();
    std::fs::write(&path, &bytes).unwrap();
    let core = reknife::formats::elf_headers::inspect(&bytes).unwrap();
    for (command, detail, expected) in [
        (
            "headers",
            false,
            serde_json::to_value(&core.header).unwrap(),
        ),
        (
            "segments",
            false,
            serde_json::to_value(&core.segments).unwrap(),
        ),
        (
            "sections",
            true,
            serde_json::to_value(&core.sections).unwrap(),
        ),
    ] {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_knife"));
        cmd.arg(command).arg(&path).arg("--json");
        if detail {
            cmd.arg("--details");
        }
        let out = cmd.output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap(),
            expected
        );
    }
    let text = Command::new(env!("CARGO_BIN_EXE_knife"))
        .arg("headers")
        .arg(&path)
        .output()
        .unwrap();
    assert!(text.status.success());
    assert!(String::from_utf8_lossy(&text.stdout).contains("7f 45 4c 46"));
    std::fs::write(&path, b"MZ not ELF").unwrap();
    let bad = Command::new(env!("CARGO_BIN_EXE_knife"))
        .arg("headers")
        .arg(&path)
        .arg("--json")
        .output()
        .unwrap();
    assert!(!bad.status.success());
    assert!(bad.stdout.is_empty());
    std::fs::remove_file(path).unwrap();
    std::fs::remove_dir(root).unwrap();
}
