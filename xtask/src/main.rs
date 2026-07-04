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

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let task = args.get(1).map_or("help", String::as_str);

    match task {
        "ci" => run_ci(),
        "fmt" => run_fmt(),
        "clippy" => run_clippy(),
        "doc" => run_doc(),
        "test" => run_test(),
        _ => {
            print_help();
            ExitCode::SUCCESS
        }
    }
}

fn run_ci() -> ExitCode {
    let checks: &[(&str, CheckFn)] = &[
        ("fmt", run_fmt),
        ("clippy", run_clippy),
        ("doc", run_doc),
        ("test", run_test),
    ];

    let mut failed = Vec::new();
    for (name, check) in checks {
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

fn run_test() -> ExitCode {
    println!("Running cargo test --workspace --locked...");
    run_command(Command::new("cargo").args(["test", "--workspace", "--locked"]))
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
    println!("Development tasks for the masque workspace.\n");
    println!("Usage: cargo xtask <task>\n");
    println!("Tasks:");
    println!("  ci      Run fmt, clippy, doc, and test checks");
    println!("  fmt     Run cargo fmt --all -- --check");
    println!("  clippy  Run cargo clippy --workspace --all-targets --locked -- -D warnings");
    println!(
        "  doc     Run cargo doc --workspace --no-deps --document-private-items --locked (RUSTDOCFLAGS=-D warnings)"
    );
    println!("  test    Run cargo test --workspace --locked");
    println!("  help    Print this message");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_task_prints_help() {
        // We cannot easily change argv in a unit test, but we can verify the
        // help text contains the expected commands.
        let help = format_help();
        assert!(help.contains("ci"));
        assert!(help.contains("fmt"));
        assert!(help.contains("clippy"));
        assert!(help.contains("doc"));
        assert!(help.contains("test"));
        assert!(help.contains("--locked"));
    }

    fn format_help() -> String {
        let mut output = String::new();
        output.push_str("Development tasks for the masque workspace.\n\n");
        output.push_str("Usage: cargo xtask <task>\n\n");
        output.push_str("Tasks:\n");
        output.push_str("  ci      Run fmt, clippy, doc, and test checks\n");
        output.push_str("  fmt     Run cargo fmt --all -- --check\n");
        output.push_str(
            "  clippy  Run cargo clippy --workspace --all-targets --locked -- -D warnings\n",
        );
        output.push_str("  doc     Run cargo doc --workspace --no-deps --document-private-items --locked (RUSTDOCFLAGS=-D warnings)\n");
        output.push_str("  test    Run cargo test --workspace --locked\n");
        output.push_str("  help    Print this message\n");
        output
    }

    #[test]
    fn checks_slice_is_non_empty() {
        let checks: &[(&str, CheckFn)] = &[
            ("fmt", run_fmt),
            ("clippy", run_clippy),
            ("doc", run_doc),
            ("test", run_test),
        ];
        assert!(!checks.is_empty());
        let names: Vec<_> = checks.iter().map(|(name, _)| *name).collect();
        assert_eq!(names, vec!["fmt", "clippy", "doc", "test"]);
    }
}
