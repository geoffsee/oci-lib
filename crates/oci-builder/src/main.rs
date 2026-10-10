// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use oci_builder::{
    BuildRequest, Builder, Config, Error, ErrorCode, ImageFormat, ImageInfo, Isolation, LogLevel,
    LogRecord, PullPolicy, PushRequest, StorageDriver, startup,
};

#[cfg(target_os = "linux")]
mod serve;

fn main() -> ExitCode {
    match real_main() {
        Ok(()) => ExitCode::SUCCESS,
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

fn real_main() -> Result<(), Error> {
    // Re-exec and rootless setup look at argv before a parser can. This has
    // to happen before clap, or a helper child would be parsed as a CLI.
    startup()?;
    #[cfg(target_os = "linux")]
    if std::env::args().nth(1).as_deref() == Some("--engine-serve") {
        return serve::engine_serve();
    }
    let cli = Cli::parse();
    let command = cli.command.clone();
    let insecure = cli.insecure;
    let config = cli.to_config();
    match command {
        Command::Diagnose => {
            println!("{}", Builder::diagnose()?);
            Ok(())
        }
        command => {
            let builder = Builder::open(config)?;
            let result = dispatch(&builder, command, insecure);
            let shut = builder.shutdown();
            match (result, shut) {
                (Ok(()), shut) => shut,
                (Err(err), Ok(())) => Err(err),
                (Err(err), Err(shut_err)) => {
                    eprintln!("shutdown: {shut_err}");
                    Err(err)
                }
            }
        }
    }
}

fn dispatch(builder: &Builder, command: Command, global_insecure: bool) -> Result<(), Error> {
    match command {
        Command::Diagnose => unreachable!("diagnose does not open a store"),
        Command::Build {
            file,
            tag,
            context,
            isolation,
            format,
            pull,
            build_arg,
            label,
            no_layers,
            squash,
            no_cache,
            quiet,
            target,
            os,
            arch,
            variant,
            layers: _,
        } => {
            let dockerfile = resolve_dockerfile(&context, file)?;
            let mut request = BuildRequest::new(dockerfile, context);
            request.tag = tag;
            request.target = target;
            request.isolation = isolation.into();
            request.format = format.into();
            request.pull = pull.into();
            request.os = os;
            request.arch = arch;
            request.variant = variant;
            request.layers = !no_layers;
            request.squash = squash;
            request.no_cache = no_cache;
            request.quiet = quiet;
            request.build_args = pairs("build-arg", &build_arg)?;
            request.labels = pairs("label", &label)?;
            request.on_log = Some(std::sync::Arc::new(write_stderr));
            print_info(&builder.build(request)?);
            Ok(())
        }
        Command::Tag { image, new_name } => builder.tag(&image, &new_name),
        Command::Push {
            image,
            destination,
            username,
            password,
            password_stdin,
            insecure,
            format,
        } => {
            let password = if password_stdin {
                read_stdin_secret()?
            } else {
                password.unwrap_or_default()
            };
            let mut request = PushRequest::new(image, destination);
            request.username = username.unwrap_or_default();
            request.password = password;
            request.insecure = insecure || global_insecure;
            request.format = format.map(Into::into);
            request.on_log = Some(std::sync::Arc::new(write_stderr));
            print_info(&builder.push(request)?);
            Ok(())
        }
    }
}

fn write_stderr(record: LogRecord) {
    use std::io::Write;
    let mut err = std::io::stderr().lock();
    let _ = err.write_all(record.message.as_bytes());
}

fn print_info(info: &ImageInfo) {
    println!("image_id={}", info.image_id);
    if let Some(digest) = &info.digest {
        println!("digest={digest}");
    }
    if let Some(reference) = &info.reference {
        println!("reference={reference}");
    }
}

fn resolve_dockerfile(context: &std::path::Path, file: Option<PathBuf>) -> Result<PathBuf, Error> {
    if let Some(file) = file {
        return Ok(if file.is_absolute() {
            file
        } else {
            context.join(file)
        });
    }
    for name in ["Dockerfile", "Containerfile"] {
        let candidate = context.join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(Error::new(
        ErrorCode::InvalidArgument,
        format!("no Dockerfile or Containerfile in {}", context.display()),
        "",
    ))
}

fn pairs(kind: &str, values: &[String]) -> Result<BTreeMap<String, String>, Error> {
    let mut out = BTreeMap::new();
    for value in values {
        let Some((key, val)) = value.split_once('=') else {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("{kind} {value} is not key=value"),
                "",
            ));
        };
        if key.is_empty() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("{kind} key is empty"),
                "",
            ));
        }
        out.insert(key.to_string(), val.to_string());
    }
    Ok(out)
}

fn read_stdin_secret() -> Result<String, Error> {
    use std::io::BufRead;
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|err| {
            Error::new(
                ErrorCode::Internal,
                format!("reading --password-stdin: {err}"),
                "",
            )
        })?;
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
    Ok(line)
}

#[derive(Parser, Debug)]
#[command(
    name = "oci-builder",
    version,
    about = "Build and push OCI images with embedded Buildah",
    arg_required_else_help = true
)]
struct Cli {
    /// Storage graph root.
    #[arg(long, global = true)]
    root: Option<PathBuf>,

    /// Runtime root for transient mount state.
    #[arg(long, global = true)]
    runroot: Option<PathBuf>,

    /// Graph driver. The default is containers/storage's own choice.
    #[arg(long, global = true, value_enum)]
    storage_driver: Option<StorageDriverArg>,

    /// Graph driver option, repeated. Replaces storage.conf options when a driver is set.
    #[arg(long = "storage-opt", global = true)]
    storage_opt: Vec<String>,

    /// Signature policy.json.
    #[arg(long, global = true)]
    signature_policy: Option<PathBuf>,

    /// registries.conf.
    #[arg(long, global = true)]
    registries_conf: Option<PathBuf>,

    /// Registry auth file.
    #[arg(long, global = true)]
    auth_file: Option<PathBuf>,

    /// Allow HTTP registries and skip TLS verification.
    #[arg(long, global = true)]
    insecure: bool,

    /// Engine log level.
    #[arg(long, global = true, value_enum, default_value = "warn")]
    log_level: LogLevelArg,

    #[command(subcommand)]
    command: Command,
}

impl Cli {
    fn to_config(&self) -> Config {
        Config {
            storage_root: self.root.clone(),
            run_root: self.runroot.clone(),
            storage_driver: self.storage_driver.map(StorageDriverArg::into),
            storage_opts: self.storage_opt.clone(),
            registries_conf: self.registries_conf.clone(),
            signature_policy: self.signature_policy.clone(),
            auth_file: self.auth_file.clone(),
            insecure: self.insecure,
            log_level: self.log_level.into(),
            signing_key: None,
            signing_cert_chain: Vec::new(),
        }
    }
}

#[derive(Subcommand, Debug, Clone)]
enum Command {
    /// Report kernel, user namespace, and storage prerequisites.
    Diagnose,

    /// Build an image from a Dockerfile or Containerfile.
    Build {
        /// Dockerfile path. Defaults to Dockerfile, then Containerfile, in the context.
        #[arg(short = 'f', long = "file")]
        file: Option<PathBuf>,

        /// Name to give the built image.
        #[arg(short = 't', long = "tag")]
        tag: Option<String>,

        /// Build context directory.
        #[arg(long, default_value = ".")]
        context: PathBuf,

        #[arg(long, value_enum, default_value = "default")]
        isolation: IsolationArg,

        #[arg(long, value_enum, default_value = "oci")]
        format: FormatArg,

        #[arg(long, value_enum, default_value = "missing")]
        pull: PullArg,

        /// Build-arg `KEY=VALUE`, repeated.
        #[arg(long = "build-arg")]
        build_arg: Vec<String>,

        /// Image label `KEY=VALUE`, repeated.
        #[arg(long = "label")]
        label: Vec<String>,

        /// Commit a layer per instruction. This is the default.
        #[arg(long, overrides_with = "no_layers")]
        layers: bool,

        /// Do not commit an intermediate layer per instruction.
        #[arg(long, overrides_with = "layers")]
        no_layers: bool,

        #[arg(long)]
        squash: bool,

        #[arg(long)]
        no_cache: bool,

        #[arg(long)]
        quiet: bool,

        #[arg(long)]
        target: Option<String>,

        #[arg(long)]
        os: Option<String>,

        #[arg(long)]
        arch: Option<String>,

        #[arg(long)]
        variant: Option<String>,
    },

    /// Tag an image already present in local storage.
    Tag { image: String, new_name: String },

    /// Push an image to a registry.
    Push {
        image: String,
        destination: String,

        #[arg(long)]
        username: Option<String>,

        #[arg(long, conflicts_with = "password_stdin")]
        password: Option<String>,

        #[arg(long, conflicts_with = "password")]
        password_stdin: bool,

        #[arg(long)]
        insecure: bool,

        #[arg(long, value_enum)]
        format: Option<FormatArg>,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum StorageDriverArg {
    #[value(name = "overlay")]
    Overlay,
    #[value(name = "vfs")]
    Vfs,
}

impl From<StorageDriverArg> for StorageDriver {
    fn from(value: StorageDriverArg) -> Self {
        match value {
            StorageDriverArg::Overlay => Self::Overlay,
            StorageDriverArg::Vfs => Self::Vfs,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum LogLevelArg {
    #[value(name = "trace")]
    Trace,
    #[value(name = "debug")]
    Debug,
    #[value(name = "info")]
    Info,
    #[value(name = "warn")]
    Warn,
    #[value(name = "error")]
    Error,
}

impl From<LogLevelArg> for LogLevel {
    fn from(value: LogLevelArg) -> Self {
        match value {
            LogLevelArg::Trace => Self::Trace,
            LogLevelArg::Debug => Self::Debug,
            LogLevelArg::Info => Self::Info,
            LogLevelArg::Warn => Self::Warn,
            LogLevelArg::Error => Self::Error,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum IsolationArg {
    #[value(name = "default")]
    Default,
    #[value(name = "oci")]
    Oci,
    #[value(name = "rootless")]
    Rootless,
    #[value(name = "chroot")]
    Chroot,
}

impl From<IsolationArg> for Isolation {
    fn from(value: IsolationArg) -> Self {
        match value {
            IsolationArg::Default => Self::Default,
            IsolationArg::Oci => Self::Oci,
            IsolationArg::Rootless => Self::Rootless,
            IsolationArg::Chroot => Self::Chroot,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum FormatArg {
    #[value(name = "oci")]
    Oci,
    #[value(name = "docker")]
    Docker,
}

impl From<FormatArg> for ImageFormat {
    fn from(value: FormatArg) -> Self {
        match value {
            FormatArg::Oci => Self::Oci,
            FormatArg::Docker => Self::Docker,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum PullArg {
    #[value(name = "missing")]
    Missing,
    #[value(name = "always")]
    Always,
    #[value(name = "ifnewer")]
    IfNewer,
    #[value(name = "never")]
    Never,
}

impl From<PullArg> for PullPolicy {
    fn from(value: PullArg) -> Self {
        match value {
            PullArg::Missing => Self::IfMissing,
            PullArg::Always => Self::Always,
            PullArg::IfNewer => Self::IfNewer,
            PullArg::Never => Self::Never,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_build_and_global_flags() {
        let cli = Cli::try_parse_from([
            "oci-builder",
            "--storage-driver",
            "vfs",
            "--root",
            "/tmp/graph",
            "--insecure",
            "build",
            "-f",
            "Dockerfile",
            "-t",
            "localhost/app:latest",
            "--context",
            "ctx",
            "--build-arg",
            "FOO=bar",
            "--label",
            "a=b",
            "--no-layers",
            "--pull",
            "never",
            "--isolation",
            "chroot",
            "--format",
            "docker",
        ])
        .expect("parse");
        assert!(cli.insecure);
        assert!(matches!(cli.storage_driver, Some(StorageDriverArg::Vfs)));
        let config = cli.to_config();
        assert_eq!(config.storage_driver, Some(StorageDriver::Vfs));
        assert!(config.insecure);
        match cli.command {
            Command::Build {
                tag,
                no_layers,
                pull,
                isolation,
                format,
                build_arg,
                label,
                ..
            } => {
                assert_eq!(tag.as_deref(), Some("localhost/app:latest"));
                assert!(no_layers);
                assert!(matches!(pull, PullArg::Never));
                assert!(matches!(isolation, IsolationArg::Chroot));
                assert!(matches!(format, FormatArg::Docker));
                assert_eq!(build_arg, vec!["FOO=bar".to_string()]);
                assert_eq!(label, vec!["a=b".to_string()]);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn splits_pairs_and_rejects_a_bare_word() {
        let map = pairs("label", &["a=b".to_string(), "c=".to_string()]).unwrap();
        assert_eq!(map.get("a").map(String::as_str), Some("b"));
        assert_eq!(map.get("c").map(String::as_str), Some(""));
        let err = pairs("build-arg", &["novalue".to_string()]).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }
}
