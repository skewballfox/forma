//! Command-line interface for forma. See `docs/architecture.md` for the design.
//!
//! The binary holds no feature logic. It checks where and as whom it runs,
//! loads configuration, calls the libraries and prints what they return.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context as _, bail};
use clap::{Parser, Subcommand, ValueEnum};
use forma_config::installed::{self, InstalledPaths};
use forma_config::{HostConfig, Inputs, MateriaConfig};
use forma_host::LiveHost;
use forma_ledger::Store;
use forma_plan::{Plan, Request, Scope};
use forma_user::name::GroupName;


/// Prepares a host for materia's rootless components: accounts, a local
/// image store, signature policy and SELinux policy.
#[derive(Debug, Parser)]
#[command(name = "forma", version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("FORMA_GIT_COMMIT"), ")"))]
struct Cli {
    /// Host configuration file. Also `FORMA_CONFIG`. Default: /etc/forma/config.toml
    #[arg(short, long, global = true, value_name = "FILE")]
    config: Option<PathBuf>,
    /// Print errors only
    #[arg(short, long, global = true)]
    quiet: bool,
    /// Debug logging. Also `FORMA_DEBUG`
    #[arg(long, global = true)]
    debug: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum MateriaLock {
    /// Take materia's lock.
    Acquire,
    /// Materia runs forma and already holds its lock.
    Held,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Show what apply would do, and which actions are privileged
    Plan {
        /// Act for one component. Default: all
        component: Option<String>,
        /// Also show what --prune would remove
        #[arg(long)]
        prune: bool,
        /// Output format
        #[arg(short, long, value_enum, default_value = "text")]
        format: Format,
    },
    /// Make the host match the repository (root)
    Apply {
        /// Act for one component. Default: all
        component: Option<String>,
        /// Also remove what the repository no longer asks for
        #[arg(long)]
        prune: bool,
        /// Print the plan and stop
        #[arg(long)]
        plan: bool,
        /// Whether materia already holds its lock
        #[arg(long, value_enum, default_value = "acquire")]
        materia_lock: MateriaLock,
        /// Accept a changed base-image trust key
        #[arg(long, value_name = "FINGERPRINT")]
        approve_key: Option<String>,
    },
    /// Undo everything one component alone needs (root)
    Revert {
        /// The component
        component: String,
        /// Print the plan and stop
        #[arg(long)]
        plan: bool,
        /// Whether materia already holds its lock
        #[arg(long, value_enum, default_value = "acquire")]
        materia_lock: MateriaLock,
    },
    /// Undo everything forma has done on this host (root)
    Purge {
        /// Also delete the homes forma kept
        #[arg(long)]
        data: bool,
        /// Print the plan and stop
        #[arg(long)]
        plan: bool,
    },
    /// Work with the root ledger (root)
    Ledger {
        #[command(subcommand)]
        command: LedgerCommand,
    },
    /// Print the effective host configuration and where each value came from
    Config,
    /// Print the version and the Git commit it was built from
    Version,
}

#[derive(Debug, Subcommand)]
enum LedgerCommand {
    /// Print the ledger
    Show,
}

/// Returns why forma thinks it runs in a container, if it does.
///
/// Forma creates accounts, changes ACLs and talks to the TPM, so it works
/// on the host only (architecture 6). The checks are those of
/// `systemd-detect-virt --container`. The variable alone is not enough: it
/// is lost whenever a parent clears the environment.
fn container_marker() -> Option<String> {
    ["/run/.containerenv", "/.dockerenv"]
        .into_iter()
        .find(|marker| Path::new(marker).exists())
        .map(|marker| format!("{marker} exists"))
        .or_else(|| {
            std::env::var("container")
                .ok()
                .filter(|kind| !kind.is_empty())
                .map(|kind| format!("the environment variable container is {kind:?}"))
        })
}

fn is_root() -> bool {
    // The owner of /proc/self is the process's effective user.
    std::fs::metadata("/proc/self").is_ok_and(|metadata| std::os::unix::fs::MetadataExt::uid(&metadata) == 0)
}

/// Everything a plan needs, loaded from the host.
struct Loaded {
    config: forma_config::Config,
    installed: forma_config::Installed,
    materia: MateriaConfig,
    limits: HostConfig,
}

fn host_config(cli: &Cli) -> anyhow::Result<HostConfig> {
    let file = cli
        .config
        .clone()
        .or_else(|| std::env::var_os(forma_config::host::FILE_VARIABLE).map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(forma_config::host::DEFAULT_FILE));
    // A variable that is not Unicode cannot be a setting forma knows.
    let environment =
        std::env::vars_os().filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)));
    HostConfig::load(&file, environment).context("the host configuration is not usable")
}

fn load(cli: &Cli) -> anyhow::Result<Loaded> {
    let limits = host_config(cli)?;
    let environment =
        std::env::vars_os().filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)));
    let materia = MateriaConfig::load(&limits.materia_config_file.value, environment)
        .context("materia's configuration is not usable")?;
    let host = materia.resolve_hostname().context("cannot find this host's name")?;
    let installed = installed::scan(&InstalledPaths::from(&materia)).context("cannot read what materia installed")?;
    let group_exists = |name: &GroupName| matches!(forma_user::lookup::group(name), Ok(Some(_)));
    let config = forma_config::load(&Inputs {
        host: &host,
        repository_manifest: &materia.repository_manifest(),
        components: &installed.components,
        limits: &limits,
        groups: &group_exists,
    })
    .map_err(|errors| {
        let list: Vec<String> = errors
            .iter()
            .map(|error| format!("- {}: {error}", error.code()))
            .collect();
        anyhow::anyhow!(
            "the configuration of this host has {} error(s):\n{}",
            errors.len(),
            list.join("\n")
        )
    })?;
    Ok(Loaded {
        config,
        installed,
        materia,
        limits,
    })
}

/// Opens the root ledger for reading. Someone who cannot read it gets an
/// empty one and is told so: the plan then shows every item as new.
fn read_ledger(quiet: bool) -> anyhow::Result<Store> {
    match Store::open(forma_ledger::ROOT_LEDGER) {
        Ok(store) => Ok(store),
        Err(forma_ledger::LedgerError::Io { source, .. }) if source.kind() == std::io::ErrorKind::PermissionDenied => {
            if !quiet {
                eprintln!(
                    "warning: cannot read {}; planning as if forma had made nothing. Run as root for a true plan.",
                    forma_ledger::ROOT_LEDGER
                );
            }
            Ok(Store::in_memory())
        }
        Err(error) => Err(error.into()),
    }
}

fn plan_json(plan: &Plan) -> serde_json::Value {
    serde_json::json!({
        "steps": plan.steps.iter().map(|step| serde_json::json!({
            "action": step.action.to_string(),
            "for": step.needs.iter().collect::<Vec<_>>(),
            "root": step.action.needs_root_user(),
            "capabilities": step.action.capabilities().iter().map(|capability| capability.to_string()).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "warnings": plan.warnings,
        "problems": plan.problems.iter().map(|problem| serde_json::json!({
            "code": problem.code(),
            "message": problem.to_string(),
        })).collect::<Vec<_>>(),
    })
}

/// Prints a plan. Returns failure if the plan has problems.
fn show_plan(cli: &Cli, scope: Scope<'_>, format: Format) -> anyhow::Result<ExitCode> {
    let loaded = load(cli)?;
    if let Scope::Apply {
        component: Some(name), ..
    }
    | Scope::Revert { component: name } = scope
    {
        let known = loaded.config.component(name).is_some()
            || loaded.installed.skipped.iter().any(|skipped| skipped.name == name);
        if !known && !matches!(scope, Scope::Revert { .. }) {
            bail!("component {name} is not installed on this host");
        }
    }
    let ledger = read_ledger(cli.quiet)?;
    let host = LiveHost::read()?;
    if !cli.quiet {
        for what in host.unread() {
            eprintln!("warning: cannot read {what} without root; planning as if it were empty. Run as root for a true plan.");
        }
    }
    let plan = forma_plan::plan(
        &Request {
            config: &loaded.config,
            materia: &loaded.materia,
            limits: &loaded.limits,
            skipped: &loaded.installed.skipped,
            scope,
        },
        &ledger,
        &host,
    );
    match format {
        Format::Json => println!("{}", serde_json::to_string_pretty(&plan_json(&plan))?),
        Format::Text => print!("{plan}"),
    }
    // A component forma skipped is an error for the run as a whole, after
    // the other components were handled (architecture 2.2).
    let clean = plan.problems.is_empty() && loaded.installed.skipped.is_empty();
    Ok(if clean { ExitCode::SUCCESS } else { ExitCode::FAILURE })
}

const NOT_YET: &str = "is not implemented yet: this build can plan, and cannot change the host. \
                       Add --plan to see what it would do";

fn run(cli: &Cli) -> anyhow::Result<ExitCode> {
    match &cli.command {
        Command::Version => {
            println!("forma {} ({})", env!("CARGO_PKG_VERSION"), env!("FORMA_GIT_COMMIT"));
            Ok(ExitCode::SUCCESS)
        }
        Command::Config => {
            let config = host_config(cli)?;
            for (key, value, source) in config.entries() {
                println!("{key} = {value}  ({source})");
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Plan {
            component,
            prune,
            format,
        } => show_plan(
            cli,
            Scope::Apply {
                component: component.as_deref(),
                prune: *prune,
            },
            *format,
        ),
        Command::Apply {
            component, prune, plan, ..
        } => {
            if !*plan {
                bail!("forma apply {NOT_YET}");
            }
            show_plan(
                cli,
                Scope::Apply {
                    component: component.as_deref(),
                    prune: *prune,
                },
                Format::Text,
            )
        }
        Command::Revert { component, plan, .. } => {
            if !*plan {
                bail!("forma revert {NOT_YET}");
            }
            show_plan(cli, Scope::Revert { component }, Format::Text)
        }
        Command::Purge { data, plan } => {
            if !*plan {
                bail!("forma purge {NOT_YET}");
            }
            show_plan(cli, Scope::Purge { data: *data }, Format::Text)
        }
        Command::Ledger {
            command: LedgerCommand::Show,
        } => {
            if !is_root() {
                bail!("forma ledger show must run as root: the ledger is readable by root only");
            }
            print!("{}", Store::open(forma_ledger::ROOT_LEDGER)?.to_toml());
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    // `version` works anywhere, so a packager can run it in a build container.
    if !matches!(cli.command, Command::Version)
        && let Some(marker) = container_marker()
    {
        eprintln!(
            "error: forma runs on the host only, and this looks like a container ({marker}). \
                 Forma creates accounts, changes ACLs and uses the TPM, which a container cannot do for its host."
        );
        return ExitCode::FAILURE;
    }
    match run(&cli) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}
