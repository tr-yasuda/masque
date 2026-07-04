//! Development helper tasks for the masque workspace.
//!
//! Run with:
//!
//! ```text
//! cargo xtask <task>
//! ```

use std::env;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let task = args.get(1).map_or("help", String::as_str);

    match task {
        "ci" => run_ci(),
        "fmt" => run_fmt(),
        "clippy" => run_clippy(),
        "test" => run_test(),
        _ => {
            print_help();
            ExitCode::SUCCESS
        }
    }
}

fn run_ci() -> ExitCode {
    let checks = [run_fmt, run_clippy, run_test];
    for check in &checks {
        let code = check();
        if code != ExitCode::SUCCESS {
            return code;
        }
    }
    println!("All CI checks passed.");
    ExitCode::SUCCESS
}

fn run_fmt() -> ExitCode {
    println!("Running cargo fmt --check...");
    run_command(Command::new("cargo").args(["fmt", "--all", "--", "--check"]))
}

fn run_clippy() -> ExitCode {
    println!("Running cargo clippy...");
    run_command(Command::new("cargo").args([
        "clippy",
        "--workspace",
        "--all-targets",
        "--",
        "-D",
        "warnings",
    ]))
}

fn run_test() -> ExitCode {
    println!("Running cargo test...");
    run_command(Command::new("cargo").args(["test", "--workspace"]))
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
    println!("  ci      Run fmt, clippy, and test checks");
    println!("  fmt     Run cargo fmt --check");
    println!("  clippy  Run cargo clippy with warnings as errors");
    println!("  test    Run cargo test --workspace");
    println!("  help    Print this message");
}
