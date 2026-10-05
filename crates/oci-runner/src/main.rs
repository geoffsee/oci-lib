// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use libcontainer_ffi::{Error, ErrorCode, RunRequest, Runtime, startup};

#[cfg(target_os = "linux")]
mod serve;

fn main() -> ExitCode {
    match real_main() {
        Ok(code) => exit_code(code),
        Err(err) => {
            eprintln!("{err}");
            exit_code(err.code().as_exit())
        }
    }
}

fn exit_code(code: i32) -> ExitCode {
    u8::try_from(code)
        .map(ExitCode::from)
        .unwrap_or(ExitCode::from(1))
}

fn real_main() -> Result<i32, Error> {
    // The libcontainer re-exec child is dispatched before this returns, and
    // its argv must not be parsed as a CLI.
    startup()?;
    if std::env::args().nth(1).as_deref() == Some("--engine-serve") {
        #[cfg(target_os = "linux")]
        {
            return serve::engine_serve();
        }
        #[cfg(not(target_os = "linux"))]
        {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "the engine agent runs inside the Linux guest",
                "",
            ));
        }
    }
    let cli = Cli::parse();
    match cli.command {
        Command::Diagnose => {
            let report = Runtime::diagnose()?;
            print!("{report}");
            Ok(0)
        }
        Command::Run(args) => {
            let mut request = RunRequest::new(&args.rootfs, args.command)
                .cwd(args.cwd)
                .hostname(args.hostname)
                .isolate_network(args.isolate_network);
            if let Some(root) = cli.root {
                request = request.state_root(root);
            }
            for entry in args.env {
                let (key, value) = entry.split_once('=').ok_or_else(|| {
                    Error::new(
                        ErrorCode::InvalidArgument,
                        format!("environment entry {entry} is not KEY=VALUE"),
                        "",
                    )
                })?;
                request = request.env(key, value);
            }
            let runtime = Runtime::open()?;
            let result = runtime.run(&request);
            let shut = runtime.shutdown();
            match (result, shut) {
                (Ok(code), Ok(())) => Ok(code),
                (Ok(_), Err(err)) => Err(err),
                (Err(err), Ok(())) => Err(err),
                (Err(err), Err(shut_err)) => {
                    eprintln!("shutdown: {shut_err}");
                    Err(err)
                }
            }
        }
    }
}

#[derive(Debug, Parser)]
#[command(name = "oci-runner", about = "Run a rootfs with libcontainer", version)]
struct Cli {
    /// Container state directory. On macOS the guest keeps its own directory.
    #[arg(long, global = true)]
    root: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Subcommand)]
enum Command {
    /// Print whether this host can run a container.
    Diagnose,
    /// Run a command in a rootfs and wait for it.
    Run(RunArgs),
}

#[derive(Debug, Clone, Parser)]
struct RunArgs {
    /// Directory used as the container root filesystem.
    #[arg(long)]
    rootfs: PathBuf,

    /// Working directory inside the container.
    #[arg(long, default_value = "/")]
    cwd: String,

    /// UTS hostname.
    #[arg(long, default_value = "runner")]
    hostname: String,

    /// Put the container in its own network namespace and bring up loopback.
    #[arg(long)]
    isolate_network: bool,

    /// Environment entry. Repeat for more than one.
    #[arg(long = "env", value_name = "KEY=VALUE")]
    env: Vec<String>,

    /// Command and arguments.
    #[arg(required = true, trailing_var_arg = true, num_args = 1..)]
    command: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_run_flags_and_the_command() {
        let cli = Cli::try_parse_from([
            "oci-runner",
            "--root",
            "/tmp/oci-runner-state",
            "run",
            "--rootfs",
            "/var/rootfs",
            "--cwd",
            "/tmp",
            "--hostname",
            "box",
            "--isolate-network",
            "--env",
            "FOO=bar",
            "--env",
            "BAZ=qux",
            "--",
            "/bin/echo",
            "hi",
        ])
        .unwrap();
        assert_eq!(cli.root.unwrap(), PathBuf::from("/tmp/oci-runner-state"));
        let Command::Run(args) = cli.command else {
            panic!("run");
        };
        assert_eq!(args.rootfs, PathBuf::from("/var/rootfs"));
        assert_eq!(args.cwd, "/tmp");
        assert_eq!(args.hostname, "box");
        assert!(args.isolate_network);
        assert_eq!(args.env, ["FOO=bar", "BAZ=qux"]);
        assert_eq!(args.command, ["/bin/echo", "hi"]);
    }

    #[test]
    fn diagnose_does_not_require_a_rootfs() {
        let cli = Cli::try_parse_from(["oci-runner", "diagnose"]).unwrap();
        assert!(matches!(cli.command, Command::Diagnose));
    }

    #[test]
    fn run_requires_a_command() {
        let err = Cli::try_parse_from(["oci-runner", "run", "--rootfs", "/"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }
}
