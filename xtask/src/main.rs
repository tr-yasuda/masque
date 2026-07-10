//! Development helper tasks for the masque workspace.
//!
//! Run with:
//!
//! ```text
//! cargo xtask <task>
//! ```

use std::env;
use std::process::{Command, ExitCode};

type CheckFn = fn() -> ExitCode;

/// The CI checks run by `cargo xtask ci`, in order.
const CI_CHECKS: &[(&str, CheckFn)] = &[
    ("fmt", run_fmt),
    ("clippy", run_clippy),
    ("clippy-h3", run_clippy_h3),
    ("doc", run_doc),
    ("doc-h3", run_doc_h3),
    ("test", run_test),
    ("test-h3", run_test_h3),
];

/// Help text shared by `print_help` and the unit tests.
const HELP_TEXT: &str = concat!(
    "Development tasks for the masque workspace.\n\n",
    "Usage: cargo xtask <task>\n\n",
    "Tasks:\n",
    "  ci          Run fmt, clippy, doc, and test checks (with and without the h3 feature)\n",
    "  fmt         Run cargo fmt --all -- --check\n",
    "  clippy      Run cargo clippy --workspace --all-targets --locked -- -D warnings\n",
    "  clippy-h3   Run cargo clippy --workspace --all-targets --features masque/h3,masque/test-utils --locked -- -D warnings\n",
    "  doc         Run cargo doc --workspace --no-deps --document-private-items --locked (RUSTDOCFLAGS=-D warnings)\n",
    "  doc-h3      Run cargo doc --workspace --no-deps --document-private-items --features masque/h3,masque/test-utils --locked (RUSTDOCFLAGS=-D warnings)\n",
    "  test        Run cargo test --workspace --locked\n",
    "  test-h3     Run cargo test --workspace --features masque/h3,masque/test-utils --locked\n",
    "  help        Print this message\n",
);

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let task = args.get(1).map_or("help", String::as_str);

    match task {
        "ci" => run_ci(),
        "fmt" => run_fmt(),
        "clippy" => run_clippy(),
        "clippy-h3" => run_clippy_h3(),
        "doc" => run_doc(),
        "doc-h3" => run_doc_h3(),
        "test" => run_test(),
        "test-h3" => run_test_h3(),
        _ => {
            print_help();
            ExitCode::SUCCESS
        }
    }
}

fn run_ci() -> ExitCode {
    let mut failed = Vec::new();
    for (name, check) in CI_CHECKS {
        println!("\nRunning {name} check...");
        if check() != ExitCode::SUCCESS {
            failed.push(*name);
        }
    }

    if failed.is_empty() {
        println!("\nAll CI checks passed.");
        ExitCode::SUCCESS
    } else {
        eprintln!("\nFailed checks: {}", failed.join(", "));
        ExitCode::FAILURE
    }
}

fn run_fmt() -> ExitCode {
    println!("Running cargo fmt --check...");
    run_command(Command::new("cargo").args(["fmt", "--all", "--", "--check"]))
}

fn run_clippy() -> ExitCode {
    println!("Running cargo clippy --workspace --all-targets --locked -- -D warnings...");
    run_command(Command::new("cargo").args([
        "clippy",
        "--workspace",
        "--all-targets",
        "--locked",
        "--",
        "-D",
        "warnings",
    ]))
}

fn run_clippy_h3() -> ExitCode {
    println!(
        "Running cargo clippy --workspace --all-targets --features masque/h3,masque/test-utils --locked -- -D warnings..."
    );
    run_command(Command::new("cargo").args([
        "clippy",
        "--workspace",
        "--all-targets",
        "--features",
        "masque/h3,masque/test-utils",
        "--locked",
        "--",
        "-D",
        "warnings",
    ]))
}

fn run_doc() -> ExitCode {
    println!(
        "Running cargo doc --workspace --no-deps --document-private-items --locked (RUSTDOCFLAGS=-D warnings)..."
    );
    run_command(
        Command::new("cargo")
            .args([
                "doc",
                "--workspace",
                "--no-deps",
                "--document-private-items",
                "--locked",
            ])
            .env("RUSTDOCFLAGS", "-D warnings"),
    )
}

fn run_doc_h3() -> ExitCode {
    println!(
        "Running cargo doc --workspace --no-deps --document-private-items --features masque/h3,masque/test-utils --locked (RUSTDOCFLAGS=-D warnings)..."
    );
    run_command(
        Command::new("cargo")
            .args([
                "doc",
                "--workspace",
                "--no-deps",
                "--document-private-items",
                "--features",
                "masque/h3,masque/test-utils",
                "--locked",
            ])
            .env("RUSTDOCFLAGS", "-D warnings"),
    )
}

fn run_test() -> ExitCode {
    println!("Running cargo test --workspace --locked...");
    run_command(Command::new("cargo").args(["test", "--workspace", "--locked"]))
}

fn run_test_h3() -> ExitCode {
    println!("Running cargo test --workspace --features masque/h3,masque/test-utils --locked...");
    run_command(Command::new("cargo").args([
        "test",
        "--workspace",
        "--features",
        "masque/h3,masque/test-utils",
        "--locked",
    ]))
}

fn run_command(cmd: &mut Command) -> ExitCode {
    match cmd.status() {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(_) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("Failed to spawn command: {e}");
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    print!("{HELP_TEXT}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_text_contains_expected_commands() {
        assert!(HELP_TEXT.contains("ci"));
        assert!(HELP_TEXT.contains("fmt"));
        assert!(HELP_TEXT.contains("clippy"));
        assert!(HELP_TEXT.contains("clippy-h3"));
        assert!(HELP_TEXT.contains("doc"));
        assert!(HELP_TEXT.contains("doc-h3"));
        assert!(HELP_TEXT.contains("test"));
        assert!(HELP_TEXT.contains("test-h3"));
        assert!(HELP_TEXT.contains("--locked"));
        assert!(HELP_TEXT.contains("masque/h3"));
        assert!(HELP_TEXT.contains("masque/test-utils"));
    }

    #[test]
    fn unknown_task_prints_help() {
        // Run the xtask binary with an unknown task via cargo, capturing stdout
        // to verify the actual help path is exercised.
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let output = Command::new("cargo")
            .current_dir(manifest_dir)
            .args(["run", "--bin", "xtask", "--", "__unknown_task__"])
            .output()
            .expect("failed to run xtask");

        assert!(output.status.success(), "xtask should exit successfully");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("ci"));
        assert!(stdout.contains("fmt"));
        assert!(stdout.contains("clippy"));
        assert!(stdout.contains("doc"));
        assert!(stdout.contains("test"));
    }

    #[test]
    fn ci_checks_slice_matches_run_ci() {
        // Ensure the list used by run_ci is the one tested here, so this test
        // fails if the two drift apart.
        let names: Vec<_> = CI_CHECKS.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names,
            vec![
                "fmt",
                "clippy",
                "clippy-h3",
                "doc",
                "doc-h3",
                "test",
                "test-h3"
            ]
        );
    }
}
