use assert_cmd::Command;
use tempfile::tempdir;

fn repo_url(path: &std::path::Path) -> String {
    format!("file://{}", path.display())
}

fn base_command() -> Command {
    let mut cmd = Command::cargo_bin("dj").expect("binary dj is built");
    cmd.env_remove("DJ_REPO");
    cmd.env_remove("DJ_PASSWORD");
    cmd
}

#[test]
fn repo_init_and_stats_workflow_succeeds() {
    let temp_repo = tempdir().expect("create temp repo dir");
    let repo = repo_url(temp_repo.path());
    const TEST_PASSWORD: &str = "integration-passphrase";

    base_command()
        .env("DJ_PASSWORD", TEST_PASSWORD)
        .arg("--repo")
        .arg(&repo)
        .args(["repo", "init"])
        .assert()
        .success()
        .stdout(predicates::str::contains(
            "Repository initialized successfully",
        ));

    assert!(
        temp_repo.path().join("config").exists(),
        "expected repo config file to be created"
    );

    base_command()
        .env("DJ_PASSWORD", TEST_PASSWORD)
        .arg("--repo")
        .arg(&repo)
        .args(["repo", "stats"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Repository Statistics:"))
        .stdout(predicates::str::contains("Encryption: Enabled"));
}
