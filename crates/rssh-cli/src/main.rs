use clap::{Parser, Subcommand};
use std::process::ExitCode;

mod commands;
#[cfg(feature = "tui")]
mod tui;

const VERSION: &str = "0.1.0";

#[derive(Parser)]
#[command(name = "rssh-agent")]
#[command(version = VERSION)]
#[command(about = "A secure SSH agent with encrypted key storage")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Socket path for the agent
    #[arg(long, global = true)]
    socket: Option<String>,

    /// Storage directory path
    #[arg(long, global = true)]
    dir: Option<String>,

    /// Log level
    #[arg(long, global = true, default_value = "info")]
    log_level: String,

    /// Output logs in JSON format
    #[arg(long, global = true)]
    json: bool,

    /// Also log to journald
    #[arg(long, global = true)]
    journald: bool,

    /// Quiet mode (errors only)
    #[arg(short, long, global = true)]
    quiet: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize the agent storage
    Init {
        /// Storage directory path
        #[arg(long)]
        dir: Option<String>,
    },
    /// Start the agent daemon
    Daemon {
        /// Shell style for environment output
        #[arg(short = 's', conflicts_with_all = &["csh", "fish"])]
        sh: bool,

        /// C shell style for environment output
        #[arg(short = 'c', conflicts_with_all = &["sh", "fish"])]
        csh: bool,

        /// Fish shell style for environment output
        #[arg(short = 'f', conflicts_with_all = &["sh", "csh"])]
        fish: bool,

        /// Socket path
        #[arg(long)]
        socket: Option<String>,

        /// Run in foreground
        #[arg(short = 'F', long)]
        foreground: bool,

        /// Require memory locking (fail if mlockall fails)
        #[arg(long)]
        require_mlock: bool,
    },
    /// Lock the agent
    Lock,
    /// Unlock the agent
    Unlock {
        /// Read password from file descriptor
        #[arg(long)]
        pass_fd: Option<i32>,
    },
    /// Stop the agent
    Stop {
        /// Socket path
        #[arg(long)]
        socket: Option<String>,
    },
    /// Import SSH key from disk
    Import {
        /// Path to the SSH private key file
        path: String,

        /// Description for the imported key
        #[arg(long)]
        description: Option<String>,

        /// Protect the imported key with a password
        #[arg(long)]
        protect: bool,
    },
    /// Manage keys via TUI
    #[cfg(feature = "tui")]
    Manage,
    /// Generate shell completions
    Completion {
        /// Shell to generate completions for
        shell: CompletionShell,
    },
    /// Display manual page
    Man,
}

#[derive(clap::ValueEnum, Clone)]
enum CompletionShell {
    Bash,
    Zsh,
    Fish,
    PowerShell,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Initialize logging
    if !cli.quiet {
        let log_level = if cli.json {
            "error"
        } else {
            cli.log_level.as_str()
        };

        let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level));

        if cli.json {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(env_filter)
                .init();
        } else {
            tracing_subscriber::fmt().with_env_filter(env_filter).init();
        }
    }

    // Handle version explicitly if needed
    if std::env::args().any(|arg| arg == "--version" || arg == "-V") {
        println!("rssh-agent {}", VERSION);
        return ExitCode::SUCCESS;
    }

    // Execute command
    let result = match cli.command {
        Some(Commands::Init { dir }) => commands::InitCommand::execute(dir),
        Some(Commands::Daemon {
            sh,
            csh,
            fish,
            socket,
            foreground,
            require_mlock,
        }) => {
            // Create a runtime for async operations
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(commands::DaemonCommand::execute(
                sh,
                csh,
                fish,
                socket,
                foreground,
                require_mlock,
                cli.dir,
            ))
        }
        Some(Commands::Lock) => commands::LockCommand::execute(cli.socket),
        Some(Commands::Unlock { pass_fd }) => commands::UnlockCommand::execute(cli.socket, pass_fd),
        Some(Commands::Stop { socket }) => commands::StopCommand::execute(socket.or(cli.socket)),
        Some(Commands::Import {
            path,
            description,
            protect,
        }) => commands::ImportCommand::execute(path, description, protect, cli.socket),
        #[cfg(feature = "tui")]
        Some(Commands::Manage) => commands::ManageCommand::execute(cli.socket),
        Some(Commands::Completion { shell }) => {
            use clap::CommandFactory;
            use clap_complete::{Shell, generate};

            let mut cmd = Cli::command();
            let shell = match shell {
                CompletionShell::Bash => Shell::Bash,
                CompletionShell::Zsh => Shell::Zsh,
                CompletionShell::Fish => Shell::Fish,
                CompletionShell::PowerShell => Shell::PowerShell,
            };

            generate(shell, &mut cmd, "rssh-agent", &mut std::io::stdout());
            Ok(())
        }
        Some(Commands::Man) => {
            use clap::CommandFactory;
            use clap_mangen::Man;
            use std::io::Write;

            let cmd = Cli::command();
            let man = Man::new(cmd);
            let mut buffer = Vec::new();
            if let Err(e) = man.render(&mut buffer) {
                Err(rssh_core::Error::Io(std::io::Error::other(e)))
            } else if let Err(e) = std::io::stdout().write_all(&buffer) {
                Err(rssh_core::Error::Io(e))
            } else {
                Ok(())
            }
        }
        None => {
            eprintln!("No command specified. Use --help for usage information.");
            Err(rssh_core::Error::BadArgs)
        }
    };

    match result {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {}", e);
            ExitCode::from(e.exit_code() as u8)
        }
    }
}

#[cfg(test)]
mod tests {
    use assert_cmd::Command;
    use predicates::prelude::*;

    #[test]
    fn test_version_output() {
        let mut cmd = Command::cargo_bin("rssh-agent").unwrap();
        cmd.arg("--version")
            .assert()
            .success()
            .stdout(predicate::str::contains("rssh-agent 0.1.0"));
    }

    #[test]
    fn test_help_output() {
        let mut cmd = Command::cargo_bin("rssh-agent").unwrap();
        cmd.arg("--help")
            .assert()
            .success()
            .stdout(predicate::str::contains("A secure SSH agent"));
    }
}
