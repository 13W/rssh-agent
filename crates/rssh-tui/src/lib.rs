#![allow(clippy::collapsible_if)]
#![allow(clippy::map_clone)]
#![allow(clippy::new_without_default)]

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::{Backend, CrosstermBackend},
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
};
use std::io;

#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub fingerprint: String,
    pub key_type: String,
    pub format: String,
    pub description: String,
    pub source: String, // "internal" or "external"
    pub loaded: bool,
    pub has_disk: bool,
    pub has_cert: bool,
    pub password_protected: bool, // Whether key on disk is password-protected
    pub constraints: serde_json::Value,
    pub created: Option<String>,
    pub updated: Option<String>,
}

pub struct App {
    pub keys: Vec<KeyInfo>,
    pub list_state: ListState,
    pub selected_key: Option<usize>,
    pub show_help: bool,
    pub status_message: Option<String>,
    pub input_mode: InputMode,
    pub input_buffer: String,
    pub should_quit: bool,
    pub key_being_loaded: Option<String>, // Fingerprint of key being loaded with password
    pub key_load_password: Option<String>, // Temporarily stores password for loading operations
    pub old_password_buffer: String,      // For change password workflow
    pub create_key_type: Option<String>,  // For key creation workflow
    pub create_bit_length: Option<u32>,   // For RSA key creation
    // Constraint selection state
    pub constraint_confirm: bool,
    pub constraint_lifetime: Option<String>, // User-friendly format like "2h", "1d"
    pub constraint_step: ConstraintStep,
    pub constraint_context: ConstraintContext,
    // Key password management state
    pub key_password_buffer: String, // For setting key passwords
    pub key_being_protected: Option<String>, // Fingerprint of key being password-protected
    pub import_with_password: bool,  // Whether to set password during import
}

// Constraint helper functions
impl App {
    pub fn reset_constraints(&mut self) {
        self.constraint_confirm = false;
        self.constraint_lifetime = None;
        self.constraint_step = ConstraintStep::SelectOptions;
    }

    pub fn has_constraints(&self) -> bool {
        self.constraint_confirm || self.constraint_lifetime.is_some()
    }
}

// Lifetime parsing utilities
fn parse_lifetime(input: &str) -> Result<u32, String> {
    if input.is_empty() {
        return Err("Lifetime cannot be empty".to_string());
    }

    let input = input.trim().to_lowercase();

    // Handle numeric-only input (assume seconds)
    if let Ok(secs) = input.parse::<u32>() {
        validate_lifetime_seconds(secs)?;
        return Ok(secs);
    }

    // Parse format like "2h", "30m", "1d"
    let (num_str, unit) = if input.ends_with('s') {
        (input.trim_end_matches('s'), "s")
    } else if input.ends_with('m') {
        (input.trim_end_matches('m'), "m")
    } else if input.ends_with('h') {
        (input.trim_end_matches('h'), "h")
    } else if input.ends_with('d') {
        (input.trim_end_matches('d'), "d")
    } else {
        return Err(format!(
            "Invalid format '{}'. Use format like '2h', '30m', '1d'",
            input
        ));
    };

    let num: u32 = num_str
        .parse()
        .map_err(|_| format!("Invalid number '{}' in '{}'", num_str, input))?;

    if num == 0 {
        return Err("Lifetime must be greater than 0".to_string());
    }

    let seconds = match unit {
        "s" => num,
        "m" => num * 60,
        "h" => num * 3600,
        "d" => num * 86400,
        _ => return Err(format!("Unknown unit '{}'", unit)),
    };

    validate_lifetime_seconds(seconds)?;
    Ok(seconds)
}

fn validate_lifetime_seconds(seconds: u32) -> Result<(), String> {
    const MAX_LIFETIME: u32 = 30 * 24 * 60 * 60; // 30 days
    if seconds > MAX_LIFETIME {
        return Err(format!(
            "Lifetime too long. Maximum is 30 days ({} seconds)",
            MAX_LIFETIME
        ));
    }
    Ok(())
}

#[allow(dead_code)] // Reserved for future lifetime display improvements
fn format_lifetime_friendly(seconds: u32) -> String {
    if seconds < 60 {
        format!("{}s", seconds)
    } else if seconds < 3600 {
        format!("{}m", seconds / 60)
    } else if seconds < 86400 {
        format!("{}h", seconds / 3600)
    } else {
        format!("{}d", seconds / 86400)
    }
}

#[derive(PartialEq, Clone)]
pub enum ConstraintStep {
    SelectOptions,
    InputLifetime,
}

#[derive(PartialEq, Clone)]
pub enum ConstraintContext {
    Load(String), // fingerprint
    Create,
}

#[derive(PartialEq)]
pub enum InputMode {
    Normal,
    Password,
    KeyPassword,
    Confirm,
    Description,
    ChangePasswordOld,
    ChangePasswordNew,
    Certificate,
    CreateKeyType,
    CreateBitLength,
    CreateDescription,
    ConstraintsLoad,
    ConstraintsCreate,
    LifetimeInput,
    SetKeyPassword,
    ConfirmKeyPassword,
    RemoveKeyPassword,
    ImportKeyPassword,
    ImportKeyPasswordConfirm,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        let mut list_state = ListState::default();
        list_state.select(Some(0));

        Self {
            keys: Vec::new(),
            list_state,
            selected_key: None,
            show_help: false,
            status_message: None,
            input_mode: InputMode::Normal,
            input_buffer: String::new(),
            should_quit: false,
            key_being_loaded: None,
            key_load_password: None,
            old_password_buffer: String::new(),
            create_key_type: None,
            create_bit_length: None,
            constraint_confirm: false,
            constraint_lifetime: None,
            constraint_step: ConstraintStep::SelectOptions,
            constraint_context: ConstraintContext::Create,
            key_password_buffer: String::new(),
            key_being_protected: None,
            import_with_password: false,
        }
    }

    pub fn next(&mut self) {
        if self.keys.is_empty() {
            return;
        }

        let i = match self.list_state.selected() {
            Some(i) => {
                if i >= self.keys.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.list_state.select(Some(i));
        self.selected_key = Some(i);
    }

    pub fn previous(&mut self) {
        if self.keys.is_empty() {
            return;
        }

        let i = match self.list_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.keys.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.list_state.select(Some(i));
        self.selected_key = Some(i);
    }

    pub fn set_status(&mut self, message: String) {
        self.status_message = Some(message);
    }

    pub fn clear_status(&mut self) {
        self.status_message = None;
    }
}

pub fn run_tui(socket_path: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app state
    let mut app = App::new();

    // Load initial keys
    if let Err(e) = load_keys(&mut app, socket_path.as_ref()) {
        app.set_status(format!("Failed to load keys: {}", e));
    }

    // Run the app
    let res = run_app(&mut terminal, &mut app, socket_path);

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        eprintln!("Error: {}", err);
    }

    Ok(())
}

fn run_app<B: Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    socket_path: Option<String>,
) -> io::Result<()> {
    loop {
        terminal.draw(|f| ui(f, app))?;

        if let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            match app.input_mode {
                InputMode::Normal => match key.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') => {
                        app.should_quit = true;
                    }
                    KeyCode::Char('j') | KeyCode::Down => app.next(),
                    KeyCode::Char('k') | KeyCode::Up => app.previous(),
                    KeyCode::Char('r') | KeyCode::F(5) => {
                        if let Err(e) = load_keys(app, socket_path.as_ref()) {
                            app.set_status(format!("Failed to refresh: {}", e));
                        } else {
                            app.set_status("Keys refreshed".to_string());
                        }
                    }
                    KeyCode::Char('d') | KeyCode::Delete => {
                        if let Some(idx) = app.selected_key
                            && idx < app.keys.len()
                        {
                            let key = &app.keys[idx];
                            if !key.has_disk {
                                app.set_status(
                                    "Cannot delete external keys (use ssh-add -d)".to_string(),
                                );
                            } else {
                                app.input_mode = InputMode::Confirm;
                                app.set_status(format!(
                                    "PERMANENTLY delete key {} from disk? (y/n)",
                                    key.fingerprint
                                ));
                            }
                        }
                    }
                    KeyCode::Char('l') => {
                        if let Err(e) = lock_agent(socket_path.as_ref()) {
                            app.set_status(format!("Failed to lock: {}", e));
                        } else {
                            app.set_status("Agent locked".to_string());
                            if let Err(e) = load_keys(app, socket_path.as_ref()) {
                                app.set_status(format!("Failed to refresh: {}", e));
                            }
                        }
                    }
                    KeyCode::Char('u') => {
                        app.input_mode = InputMode::Password;
                        app.input_buffer.clear();
                        app.set_status("Enter master password:".to_string());
                    }
                    KeyCode::Char('h') | KeyCode::Char('?') => {
                        app.show_help = !app.show_help;
                    }
                    KeyCode::Char('a') => {
                        app.set_status("Use ssh-add to add keys".to_string());
                    }
                    KeyCode::Char('L') => {
                        // Load selected disk key into memory with constraints
                        if let Some(idx) = app.selected_key
                            && idx < app.keys.len()
                        {
                            // Extract key info first to avoid borrow conflicts
                            let has_disk = app.keys[idx].has_disk;
                            let is_loaded = app.keys[idx].loaded;
                            let password_protected = app.keys[idx].password_protected;
                            let fingerprint = app.keys[idx].fingerprint.clone();

                            // Check if key is on disk but not loaded
                            if !has_disk {
                                app.set_status("Key is not on disk".to_string());
                            } else if is_loaded {
                                app.set_status("Key is already loaded".to_string());
                            } else if password_protected {
                                // Key is password-protected, prompt for password immediately
                                app.reset_constraints();
                                app.constraint_context =
                                    ConstraintContext::Load(fingerprint.clone());
                                app.input_mode = InputMode::KeyPassword;
                                app.input_buffer.clear();
                                app.key_being_loaded = Some(fingerprint);
                                app.set_status(
                                    "Key is password-protected. Enter password:".to_string(),
                                );
                            } else {
                                // Key is not password-protected, enter constraint dialog
                                app.reset_constraints();
                                app.constraint_context = ConstraintContext::Load(fingerprint);
                                app.input_mode = InputMode::ConstraintsLoad;
                                app.constraint_step = ConstraintStep::SelectOptions;
                                app.set_status("Configure constraints: (c)onfirm, (l)ifetime, (Enter) to load with constraints, (s)kip constraints".to_string());
                            }
                        }
                    }
                    KeyCode::Char('i') => {
                        // Import selected external key
                        if let Some(idx) = app.selected_key
                            && idx < app.keys.len()
                        {
                            let key = &app.keys[idx];
                            // Check if key is external (can be imported)
                            if key.source != "external" {
                                app.set_status(
                                    "Only external keys (added via ssh-add) can be imported"
                                        .to_string(),
                                );
                            } else {
                                // Ask if user wants password protection
                                app.set_status(
                                    "Import with password protection? (y/n/Enter=no)".to_string(),
                                );
                                app.input_mode = InputMode::Confirm;
                                app.import_with_password = false;
                            }
                        }
                    }
                    KeyCode::Char('U') => {
                        // Unload selected key from RAM (keep on disk)
                        if let Some(idx) = app.selected_key
                            && idx < app.keys.len()
                        {
                            let key = &app.keys[idx];
                            if !key.loaded {
                                app.set_status("Key is not loaded".to_string());
                            } else if let Err(e) =
                                unload_key(socket_path.as_ref(), &key.fingerprint)
                            {
                                app.set_status(format!("Failed to unload key: {}", e));
                            } else {
                                app.set_status("Key unloaded successfully".to_string());
                                if let Err(e) = load_keys(app, socket_path.as_ref()) {
                                    app.set_status(format!("Failed to refresh: {}", e));
                                }
                            }
                        }
                    }
                    KeyCode::Char('e') => {
                        // Edit description for selected key
                        if let Some(idx) = app.selected_key
                            && idx < app.keys.len()
                        {
                            let key = &app.keys[idx];
                            if !key.has_disk {
                                app.set_status(
                                    "Only stored keys can have their description changed"
                                        .to_string(),
                                );
                            } else {
                                app.input_mode = InputMode::Description;
                                app.input_buffer = key.description.clone();
                                app.set_status(format!(
                                    "Enter new description: {}",
                                    &app.input_buffer
                                ));
                            }
                        }
                    }
                    KeyCode::Char('c') => {
                        // Change master password
                        app.input_mode = InputMode::ChangePasswordOld;
                        app.input_buffer.clear();
                        app.old_password_buffer.clear();
                        app.set_status("Enter current master password:".to_string());
                    }
                    KeyCode::Char('C') => {
                        // Update certificate for selected key
                        if let Some(idx) = app.selected_key
                            && idx < app.keys.len()
                        {
                            let key = &app.keys[idx];
                            if !key.has_disk {
                                app.set_status(
                                    "Only stored keys can have certificates updated".to_string(),
                                );
                            } else {
                                app.input_mode = InputMode::Certificate;
                                app.input_buffer.clear();
                                app.set_status("Paste OpenSSH certificate (base64):".to_string());
                            }
                        }
                    }
                    KeyCode::Char('n') => {
                        // Create new key with constraints
                        app.reset_constraints();
                        app.constraint_context = ConstraintContext::Create;
                        app.input_mode = InputMode::ConstraintsCreate;
                        app.constraint_step = ConstraintStep::SelectOptions;
                        app.set_status("Configure constraints: (c)onfirm, (l)ifetime, (Enter) to continue, (s)kip constraints".to_string());
                    }
                    KeyCode::Char('P') => {
                        // Set password protection on selected key
                        if let Some(idx) = app.selected_key
                            && idx < app.keys.len()
                        {
                            let key = &app.keys[idx];
                            if !key.has_disk {
                                app.set_status(
                                    "Only stored keys can be password-protected".to_string(),
                                );
                            } else if key.password_protected {
                                app.set_status("Key is already password-protected".to_string());
                            } else {
                                app.input_mode = InputMode::SetKeyPassword;
                                app.input_buffer.clear();
                                app.key_password_buffer.clear();
                                app.key_being_protected = Some(key.fingerprint.clone());
                                app.set_status("Enter password for key protection:".to_string());
                            }
                        }
                    }
                    KeyCode::Char('R') => {
                        // Remove password protection from selected key
                        if let Some(idx) = app.selected_key
                            && idx < app.keys.len()
                        {
                            let key = &app.keys[idx];
                            if !key.has_disk {
                                app.set_status(
                                    "Only stored keys can have password protection removed"
                                        .to_string(),
                                );
                            } else if !key.password_protected {
                                app.set_status("Key is not password-protected".to_string());
                            } else {
                                app.input_mode = InputMode::RemoveKeyPassword;
                                app.input_buffer.clear();
                                app.key_being_protected = Some(key.fingerprint.clone());
                                app.set_status(format!(
                                    "Enter current password for key {}:",
                                    key.fingerprint
                                ));
                            }
                        }
                    }
                    KeyCode::Esc => {
                        app.show_help = false;
                    }
                    _ => {}
                },
                InputMode::ConstraintsLoad => match key.code {
                    KeyCode::Char('c') | KeyCode::Char('C') => {
                        app.constraint_confirm = !app.constraint_confirm;
                        let confirm_status = if app.constraint_confirm { "ON" } else { "OFF" };
                        app.set_status(format!(
                            "Confirm: {} | (c)onfirm, (l)ifetime, (Enter) to load, (s)kip",
                            confirm_status
                        ));
                    }
                    KeyCode::Char('l') | KeyCode::Char('L') => {
                        app.constraint_step = ConstraintStep::InputLifetime;
                        app.input_mode = InputMode::LifetimeInput;
                        app.input_buffer.clear();
                        app.set_status("Enter lifetime (e.g. 2h, 30m, 1d):".to_string());
                    }
                    KeyCode::Enter => {
                        // Proceed with loading the key
                        if let ConstraintContext::Load(fingerprint) = &app.constraint_context {
                            let result = load_disk_key_with_constraints(
                                socket_path.as_ref(),
                                fingerprint,
                                app.key_load_password.as_deref(),
                                app.constraint_confirm,
                                app.constraint_lifetime.as_deref(),
                            );
                            handle_load_result(app, socket_path.as_ref(), result);
                        }
                        app.input_mode = InputMode::Normal;
                        app.key_being_loaded = None;
                        app.key_load_password = None;
                    }
                    KeyCode::Char('s') | KeyCode::Char('S') => {
                        // Skip constraints, load without constraints
                        if let ConstraintContext::Load(fingerprint) = &app.constraint_context {
                            let result = load_disk_key_with_constraints(
                                socket_path.as_ref(),
                                fingerprint,
                                app.key_load_password.as_deref(),
                                false,
                                None,
                            );
                            handle_load_result(app, socket_path.as_ref(), result);
                        }
                        app.input_mode = InputMode::Normal;
                        app.key_being_loaded = None;
                        app.key_load_password = None;
                    }
                    KeyCode::Esc => {
                        app.input_mode = InputMode::Normal;
                        app.key_being_loaded = None;
                        app.key_load_password = None;
                        app.clear_status();
                    }
                    _ => {}
                },
                InputMode::ConstraintsCreate => match key.code {
                    KeyCode::Char('c') | KeyCode::Char('C') => {
                        app.constraint_confirm = !app.constraint_confirm;
                        let confirm_status = if app.constraint_confirm { "ON" } else { "OFF" };
                        app.set_status(format!(
                            "Confirm: {} | (c)onfirm, (l)ifetime, (Enter) to continue, (s)kip",
                            confirm_status
                        ));
                    }
                    KeyCode::Char('l') | KeyCode::Char('L') => {
                        app.constraint_step = ConstraintStep::InputLifetime;
                        app.input_mode = InputMode::LifetimeInput;
                        app.input_buffer.clear();
                        app.set_status("Enter lifetime (e.g. 2h, 30m, 1d):".to_string());
                    }
                    KeyCode::Enter => {
                        // Proceed to key type selection
                        app.input_mode = InputMode::CreateKeyType;
                        app.input_buffer.clear();
                        app.create_key_type = None;
                        app.create_bit_length = None;
                        app.set_status("Select key type (e)d25519 or (r)sa:".to_string());
                    }
                    KeyCode::Char('s') | KeyCode::Char('S') => {
                        // Skip constraints, go directly to key type selection
                        app.reset_constraints();
                        app.input_mode = InputMode::CreateKeyType;
                        app.input_buffer.clear();
                        app.create_key_type = None;
                        app.create_bit_length = None;
                        app.set_status("Select key type (e)d25519 or (r)sa:".to_string());
                    }
                    KeyCode::Esc => {
                        app.input_mode = InputMode::Normal;
                        app.clear_status();
                    }
                    _ => {}
                },
                InputMode::LifetimeInput => match key.code {
                    KeyCode::Enter => {
                        match parse_lifetime(&app.input_buffer) {
                            Ok(_) => {
                                app.constraint_lifetime = Some(app.input_buffer.clone());
                                app.input_buffer.clear();

                                // Return to constraint selection
                                match app.constraint_context {
                                    ConstraintContext::Load(_) => {
                                        app.input_mode = InputMode::ConstraintsLoad;
                                        app.constraint_step = ConstraintStep::SelectOptions;
                                        let lifetime_display =
                                            app.constraint_lifetime.as_ref().unwrap();
                                        let confirm_status =
                                            if app.constraint_confirm { "ON" } else { "OFF" };
                                        app.set_status(format!("Confirm: {}, Lifetime: {} | (c)onfirm, (l)ifetime, (Enter) to load, (s)kip", confirm_status, lifetime_display));
                                    }
                                    ConstraintContext::Create => {
                                        app.input_mode = InputMode::ConstraintsCreate;
                                        app.constraint_step = ConstraintStep::SelectOptions;
                                        let lifetime_display =
                                            app.constraint_lifetime.as_ref().unwrap();
                                        let confirm_status =
                                            if app.constraint_confirm { "ON" } else { "OFF" };
                                        app.set_status(format!("Confirm: {}, Lifetime: {} | (c)onfirm, (l)ifetime, (Enter) to continue, (s)kip", confirm_status, lifetime_display));
                                    }
                                }
                            }
                            Err(e) => {
                                app.set_status(format!("Invalid lifetime: {}", e));
                            }
                        }
                    }
                    KeyCode::Esc => {
                        app.input_buffer.clear();
                        match app.constraint_context {
                            ConstraintContext::Load(_) => {
                                app.input_mode = InputMode::ConstraintsLoad;
                            }
                            ConstraintContext::Create => {
                                app.input_mode = InputMode::ConstraintsCreate;
                            }
                        }
                        app.constraint_step = ConstraintStep::SelectOptions;
                        app.set_status("Configure constraints: (c)onfirm, (l)ifetime, (Enter) to continue, (s)kip constraints".to_string());
                    }
                    KeyCode::Char(c) => {
                        app.input_buffer.push(c);
                    }
                    KeyCode::Backspace => {
                        app.input_buffer.pop();
                    }
                    _ => {}
                },
                InputMode::Password => match key.code {
                    KeyCode::Enter => {
                        if let Err(e) = unlock_agent(socket_path.as_ref(), &app.input_buffer) {
                            app.set_status(format!("Failed to unlock: {}", e));
                        } else {
                            app.set_status("Agent unlocked".to_string());
                            if let Err(e) = load_keys(app, socket_path.as_ref()) {
                                app.set_status(format!("Failed to refresh: {}", e));
                            }
                        }
                        app.input_buffer.clear();
                        app.input_mode = InputMode::Normal;
                    }
                    KeyCode::Esc => {
                        app.input_buffer.clear();
                        app.input_mode = InputMode::Normal;
                        app.clear_status();
                    }
                    KeyCode::Char(c) => {
                        app.input_buffer.push(c);
                    }
                    KeyCode::Backspace => {
                        app.input_buffer.pop();
                    }
                    _ => {}
                },
                InputMode::KeyPassword => {
                    match key.code {
                        KeyCode::Enter => {
                            if let Some(ref fingerprint) = app.key_being_loaded.clone() {
                                // Store the password for later use
                                app.key_load_password = Some(app.input_buffer.clone());

                                // Check if this is a Load context that should go to constraints
                                if matches!(app.constraint_context, ConstraintContext::Load(_)) {
                                    // Go to constraints UI with the password stored
                                    app.input_mode = InputMode::ConstraintsLoad;
                                    app.constraint_step = ConstraintStep::SelectOptions;
                                    app.set_status("Constraints | (c)onfirm, (l)ifetime, (Enter) to load, (s)kip".to_string());
                                } else {
                                    // Load immediately if no constraints context
                                    let result = load_disk_key(
                                        socket_path.as_ref(),
                                        fingerprint,
                                        app.key_load_password.as_deref(),
                                    );
                                    handle_load_result(app, socket_path.as_ref(), result);
                                    app.input_mode = InputMode::Normal;
                                    app.key_being_loaded = None;
                                    app.key_load_password = None;
                                }
                            }
                            app.input_buffer.clear();
                        }
                        KeyCode::Esc => {
                            app.input_buffer.clear();
                            app.input_mode = InputMode::Normal;
                            app.key_being_loaded = None;
                            app.key_load_password = None;
                            app.clear_status();
                        }
                        KeyCode::Char(c) => {
                            app.input_buffer.push(c);
                        }
                        KeyCode::Backspace => {
                            app.input_buffer.pop();
                        }
                        _ => {}
                    }
                }
                InputMode::Confirm => match key.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') => {
                        if app
                            .status_message
                            .as_ref()
                            .is_some_and(|s| s.contains("Import with password"))
                        {
                            // Handle import with password protection
                            app.import_with_password = true;
                            app.input_mode = InputMode::ImportKeyPassword;
                            app.input_buffer.clear();
                            app.key_password_buffer.clear();
                            app.set_status("Enter password for imported key:".to_string());
                        } else if let Some(idx) = app.selected_key
                            && idx < app.keys.len()
                        {
                            // Handle key deletion
                            if let Err(e) =
                                remove_key(socket_path.as_ref(), &app.keys[idx].fingerprint)
                            {
                                app.set_status(format!("Failed to delete key: {}", e));
                            } else {
                                app.set_status("Key permanently deleted from disk".to_string());
                                if let Err(e) = load_keys(app, socket_path.as_ref()) {
                                    app.set_status(format!("Failed to refresh: {}", e));
                                }
                            }
                            app.input_mode = InputMode::Normal;
                        }
                    }
                    KeyCode::Char('n') | KeyCode::Char('N') => {
                        if app
                            .status_message
                            .as_ref()
                            .is_some_and(|s| s.contains("Import with password"))
                        {
                            // Handle import without password protection
                            if let Some(idx) = app.selected_key
                                && idx < app.keys.len()
                            {
                                let key = &app.keys[idx];
                                if let Err(e) = import_key(socket_path.as_ref(), &key.fingerprint) {
                                    app.set_status(format!("Failed to import key: {}", e));
                                } else {
                                    app.set_status("Key imported successfully".to_string());
                                    if let Err(e) = load_keys(app, socket_path.as_ref()) {
                                        app.set_status(format!("Failed to refresh: {}", e));
                                    }
                                }
                            }
                        }
                        app.input_mode = InputMode::Normal;
                    }
                    KeyCode::Enter => {
                        if app
                            .status_message
                            .as_ref()
                            .is_some_and(|s| s.contains("Import with password"))
                        {
                            // Handle import without password protection (default)
                            if let Some(idx) = app.selected_key
                                && idx < app.keys.len()
                            {
                                let key = &app.keys[idx];
                                if let Err(e) = import_key(socket_path.as_ref(), &key.fingerprint) {
                                    app.set_status(format!("Failed to import key: {}", e));
                                } else {
                                    app.set_status("Key imported successfully".to_string());
                                    if let Err(e) = load_keys(app, socket_path.as_ref()) {
                                        app.set_status(format!("Failed to refresh: {}", e));
                                    }
                                }
                            }
                        }
                        app.input_mode = InputMode::Normal;
                    }
                    KeyCode::Esc => {
                        app.input_mode = InputMode::Normal;
                        app.clear_status();
                    }
                    _ => {}
                },
                InputMode::Description => match key.code {
                    KeyCode::Enter => {
                        if let Some(idx) = app.selected_key
                            && idx < app.keys.len()
                        {
                            let key = &app.keys[idx];
                            match set_key_description(
                                socket_path.as_ref(),
                                &key.fingerprint,
                                &app.input_buffer,
                            ) {
                                Ok(()) => {
                                    app.set_status("Description updated successfully".to_string());
                                    if let Err(e) = load_keys(app, socket_path.as_ref()) {
                                        app.set_status(format!("Failed to refresh: {}", e));
                                    }
                                }
                                Err(e) => {
                                    app.set_status(format!("Failed to update description: {}", e));
                                }
                            }
                        }
                        app.input_buffer.clear();
                        app.input_mode = InputMode::Normal;
                    }
                    KeyCode::Esc => {
                        app.input_buffer.clear();
                        app.input_mode = InputMode::Normal;
                        app.clear_status();
                    }
                    KeyCode::Char(c) => {
                        app.input_buffer.push(c);
                        app.set_status(format!("Enter new description: {}", &app.input_buffer));
                    }
                    KeyCode::Backspace => {
                        app.input_buffer.pop();
                        app.set_status(format!("Enter new description: {}", &app.input_buffer));
                    }
                    _ => {}
                },
                InputMode::ChangePasswordOld => match key.code {
                    KeyCode::Enter => {
                        app.old_password_buffer = app.input_buffer.clone();
                        app.input_buffer.clear();
                        app.input_mode = InputMode::ChangePasswordNew;
                        app.set_status("Enter new master password:".to_string());
                    }
                    KeyCode::Esc => {
                        app.input_buffer.clear();
                        app.old_password_buffer.clear();
                        app.input_mode = InputMode::Normal;
                        app.clear_status();
                    }
                    KeyCode::Char(c) => {
                        app.input_buffer.push(c);
                    }
                    KeyCode::Backspace => {
                        app.input_buffer.pop();
                    }
                    _ => {}
                },
                InputMode::ChangePasswordNew => match key.code {
                    KeyCode::Enter => {
                        match change_master_password(
                            socket_path.as_ref(),
                            &app.old_password_buffer,
                            &app.input_buffer,
                        ) {
                            Ok(()) => {
                                app.set_status("Master password changed successfully".to_string());
                            }
                            Err(e) => {
                                app.set_status(format!("Failed to change password: {}", e));
                            }
                        }
                        app.input_buffer.clear();
                        app.old_password_buffer.clear();
                        app.input_mode = InputMode::Normal;
                    }
                    KeyCode::Esc => {
                        app.input_buffer.clear();
                        app.old_password_buffer.clear();
                        app.input_mode = InputMode::Normal;
                        app.clear_status();
                    }
                    KeyCode::Char(c) => {
                        app.input_buffer.push(c);
                    }
                    KeyCode::Backspace => {
                        app.input_buffer.pop();
                    }
                    _ => {}
                },
                InputMode::Certificate => match key.code {
                    KeyCode::Enter => {
                        if let Some(idx) = app.selected_key
                            && idx < app.keys.len()
                        {
                            let key = &app.keys[idx];
                            match update_certificate(
                                socket_path.as_ref(),
                                &key.fingerprint,
                                &app.input_buffer,
                            ) {
                                Ok(()) => {
                                    app.set_status("Certificate updated successfully".to_string());
                                    if let Err(e) = load_keys(app, socket_path.as_ref()) {
                                        app.set_status(format!("Failed to refresh: {}", e));
                                    }
                                }
                                Err(e) => {
                                    app.set_status(format!("Failed to update certificate: {}", e));
                                }
                            }
                        }
                        app.input_buffer.clear();
                        app.input_mode = InputMode::Normal;
                    }
                    KeyCode::Esc => {
                        app.input_buffer.clear();
                        app.input_mode = InputMode::Normal;
                        app.clear_status();
                    }
                    KeyCode::Char(c) => {
                        app.input_buffer.push(c);
                    }
                    KeyCode::Backspace => {
                        app.input_buffer.pop();
                    }
                    _ => {}
                },
                InputMode::CreateKeyType => match key.code {
                    KeyCode::Char('e') | KeyCode::Char('E') => {
                        app.create_key_type = Some("ed25519".to_string());
                        app.input_mode = InputMode::CreateDescription;
                        app.input_buffer.clear();
                        app.set_status("Enter description (optional):".to_string());
                    }
                    KeyCode::Char('r') | KeyCode::Char('R') => {
                        app.create_key_type = Some("rsa".to_string());
                        app.input_mode = InputMode::CreateBitLength;
                        app.input_buffer = "2048".to_string();
                        app.set_status("Enter bit length (2048, 3072, 4096):".to_string());
                    }
                    KeyCode::Esc => {
                        app.input_buffer.clear();
                        app.create_key_type = None;
                        app.create_bit_length = None;
                        app.input_mode = InputMode::Normal;
                        app.clear_status();
                    }
                    _ => {}
                },
                InputMode::CreateBitLength => match key.code {
                    KeyCode::Enter => match app.input_buffer.parse::<u32>() {
                        Ok(bits) if [2048, 3072, 4096, 8192].contains(&bits) => {
                            app.create_bit_length = Some(bits);
                            app.input_buffer.clear();
                            app.input_mode = InputMode::CreateDescription;
                            app.set_status("Enter description (optional):".to_string());
                        }
                        _ => {
                            app.set_status(
                                "Invalid bit length. Use 2048, 3072, 4096, or 8192".to_string(),
                            );
                        }
                    },
                    KeyCode::Esc => {
                        app.input_buffer.clear();
                        app.create_key_type = None;
                        app.create_bit_length = None;
                        app.input_mode = InputMode::Normal;
                        app.clear_status();
                    }
                    KeyCode::Char(c) if c.is_ascii_digit() => {
                        app.input_buffer.push(c);
                    }
                    KeyCode::Backspace => {
                        app.input_buffer.pop();
                    }
                    _ => {}
                },
                InputMode::CreateDescription => match key.code {
                    KeyCode::Enter => {
                        let description = if app.input_buffer.trim().is_empty() {
                            None
                        } else {
                            Some(app.input_buffer.clone())
                        };

                        if let Some(key_type) = &app.create_key_type {
                            let result = if app.has_constraints() {
                                create_key_with_constraints(
                                    socket_path.as_ref(),
                                    key_type,
                                    app.create_bit_length,
                                    description,
                                    app.constraint_confirm,
                                    app.constraint_lifetime.as_deref(),
                                )
                            } else {
                                create_key(
                                    socket_path.as_ref(),
                                    key_type,
                                    app.create_bit_length,
                                    description,
                                )
                            };

                            match result {
                                Ok(()) => {
                                    app.set_status("Key created successfully".to_string());
                                    if let Err(e) = load_keys(app, socket_path.as_ref()) {
                                        app.set_status(format!("Failed to refresh: {}", e));
                                    }
                                }
                                Err(e) => {
                                    app.set_status(format!("Failed to create key: {}", e));
                                }
                            }
                        }

                        app.input_buffer.clear();
                        app.create_key_type = None;
                        app.create_bit_length = None;
                        app.reset_constraints();
                        app.input_mode = InputMode::Normal;
                    }
                    KeyCode::Esc => {
                        app.input_buffer.clear();
                        app.create_key_type = None;
                        app.create_bit_length = None;
                        app.reset_constraints();
                        app.input_mode = InputMode::Normal;
                        app.clear_status();
                    }
                    KeyCode::Char(c) => {
                        app.input_buffer.push(c);
                    }
                    KeyCode::Backspace => {
                        app.input_buffer.pop();
                    }
                    _ => {}
                },
                InputMode::SetKeyPassword => match key.code {
                    KeyCode::Enter => {
                        if app.input_buffer.is_empty() {
                            app.set_status("Password cannot be empty".to_string());
                        } else {
                            app.key_password_buffer = app.input_buffer.clone();
                            app.input_buffer.clear();
                            app.input_mode = InputMode::ConfirmKeyPassword;
                            app.set_status("Confirm password:".to_string());
                        }
                    }
                    KeyCode::Esc => {
                        app.input_buffer.clear();
                        app.key_password_buffer.clear();
                        app.key_being_protected = None;
                        app.input_mode = InputMode::Normal;
                        app.clear_status();
                    }
                    KeyCode::Char(c) => {
                        app.input_buffer.push(c);
                    }
                    KeyCode::Backspace => {
                        app.input_buffer.pop();
                    }
                    _ => {}
                },
                InputMode::ConfirmKeyPassword => match key.code {
                    KeyCode::Enter => {
                        if app.input_buffer != app.key_password_buffer {
                            app.set_status("Passwords do not match. Try again.".to_string());
                            app.input_buffer.clear();
                            app.key_password_buffer.clear();
                            app.input_mode = InputMode::SetKeyPassword;
                            app.set_status("Enter password for key protection:".to_string());
                        } else if let Some(ref fingerprint) = app.key_being_protected.clone() {
                            match set_key_password(
                                socket_path.as_ref(),
                                fingerprint,
                                &app.input_buffer,
                            ) {
                                Ok(()) => {
                                    app.set_status(
                                        "Key password protection set successfully".to_string(),
                                    );
                                    if let Err(e) = load_keys(app, socket_path.as_ref()) {
                                        app.set_status(format!("Failed to refresh: {}", e));
                                    }
                                }
                                Err(e) => {
                                    app.set_status(format!("Failed to set key password: {}", e));
                                }
                            }
                            app.input_buffer.clear();
                            app.key_password_buffer.clear();
                            app.key_being_protected = None;
                            app.input_mode = InputMode::Normal;
                        }
                    }
                    KeyCode::Esc => {
                        app.input_buffer.clear();
                        app.key_password_buffer.clear();
                        app.key_being_protected = None;
                        app.input_mode = InputMode::Normal;
                        app.clear_status();
                    }
                    KeyCode::Char(c) => {
                        app.input_buffer.push(c);
                    }
                    KeyCode::Backspace => {
                        app.input_buffer.pop();
                    }
                    _ => {}
                },
                InputMode::RemoveKeyPassword => match key.code {
                    KeyCode::Enter => {
                        if let Some(ref fingerprint) = app.key_being_protected.clone() {
                            let current_password = app.input_buffer.clone();
                            match remove_key_password(
                                socket_path.as_ref(),
                                fingerprint,
                                &current_password,
                            ) {
                                Ok(()) => {
                                    app.set_status(
                                        "Key password protection removed successfully".to_string(),
                                    );
                                    if let Err(e) = load_keys(app, socket_path.as_ref()) {
                                        app.set_status(format!("Failed to refresh: {}", e));
                                    }
                                }
                                Err(e) => {
                                    app.set_status(format!("Failed to remove key password: {}", e));
                                }
                            }
                        }
                        app.key_being_protected = None;
                        app.input_buffer.clear();
                        app.input_mode = InputMode::Normal;
                    }
                    KeyCode::Esc => {
                        app.key_being_protected = None;
                        app.input_buffer.clear();
                        app.input_mode = InputMode::Normal;
                        app.clear_status();
                    }
                    KeyCode::Char(c) => {
                        app.input_buffer.push(c);
                    }
                    KeyCode::Backspace => {
                        app.input_buffer.pop();
                    }
                    _ => {}
                },
                InputMode::ImportKeyPassword => match key.code {
                    KeyCode::Enter => {
                        if app.input_buffer.is_empty() {
                            app.set_status("Password cannot be empty".to_string());
                        } else {
                            app.key_password_buffer = app.input_buffer.clone();
                            app.input_buffer.clear();
                            app.input_mode = InputMode::ImportKeyPasswordConfirm;
                            app.set_status("Confirm import password:".to_string());
                        }
                    }
                    KeyCode::Esc => {
                        app.input_buffer.clear();
                        app.key_password_buffer.clear();
                        app.import_with_password = false;
                        app.input_mode = InputMode::Normal;
                        app.clear_status();
                    }
                    KeyCode::Char(c) => {
                        app.input_buffer.push(c);
                    }
                    KeyCode::Backspace => {
                        app.input_buffer.pop();
                    }
                    _ => {}
                },
                InputMode::ImportKeyPasswordConfirm => match key.code {
                    KeyCode::Enter => {
                        if app.input_buffer != app.key_password_buffer {
                            app.set_status("Passwords do not match. Try again.".to_string());
                            app.input_buffer.clear();
                            app.key_password_buffer.clear();
                            app.input_mode = InputMode::ImportKeyPassword;
                            app.set_status("Enter password for imported key:".to_string());
                        } else if let Some(idx) = app.selected_key
                            && idx < app.keys.len()
                        {
                            let key = &app.keys[idx];
                            match import_key_with_password(
                                socket_path.as_ref(),
                                &key.fingerprint,
                                &app.input_buffer,
                            ) {
                                Ok(()) => {
                                    app.set_status(
                                        "Key imported with password protection successfully"
                                            .to_string(),
                                    );
                                    if let Err(e) = load_keys(app, socket_path.as_ref()) {
                                        app.set_status(format!("Failed to refresh: {}", e));
                                    }
                                }
                                Err(e) => {
                                    app.set_status(format!(
                                        "Failed to import key with password: {}",
                                        e
                                    ));
                                }
                            }
                            app.input_buffer.clear();
                            app.key_password_buffer.clear();
                            app.import_with_password = false;
                            app.input_mode = InputMode::Normal;
                        }
                    }
                    KeyCode::Esc => {
                        app.input_buffer.clear();
                        app.key_password_buffer.clear();
                        app.import_with_password = false;
                        app.input_mode = InputMode::Normal;
                        app.clear_status();
                    }
                    KeyCode::Char(c) => {
                        app.input_buffer.push(c);
                    }
                    KeyCode::Backspace => {
                        app.input_buffer.pop();
                    }
                    _ => {}
                },
            }
        }

        if app.should_quit {
            return Ok(());
        }
    }
}

fn ui(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints(
            [
                Constraint::Length(3),
                Constraint::Min(5),
                Constraint::Length(3),
            ]
            .as_ref(),
        )
        .split(f.area());

    // Title
    let title = Paragraph::new("rssh-agent Key Manager")
        .style(Style::default().fg(Color::Cyan))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, chunks[0]);

    // Keys list or help
    if app.show_help {
        let help_text = vec![
            Line::from(vec![Span::styled(
                "Key Bindings",
                Style::default().add_modifier(Modifier::BOLD),
            )]),
            Line::from(""),
            Line::from(vec![Span::styled(
                "Navigation:",
                Style::default().add_modifier(Modifier::BOLD),
            )]),
            Line::from(vec![
                Span::styled("j/↓", Style::default().fg(Color::Yellow)),
                Span::raw("    Move down"),
            ]),
            Line::from(vec![
                Span::styled("k/↑", Style::default().fg(Color::Yellow)),
                Span::raw("    Move up"),
            ]),
            Line::from(""),
            Line::from(vec![Span::styled(
                "Agent Operations:",
                Style::default().add_modifier(Modifier::BOLD),
            )]),
            Line::from(vec![
                Span::styled("l", Style::default().fg(Color::Yellow)),
                Span::raw("      Lock agent"),
            ]),
            Line::from(vec![
                Span::styled("u", Style::default().fg(Color::Yellow)),
                Span::raw("      Unlock agent"),
            ]),
            Line::from(vec![
                Span::styled("c", Style::default().fg(Color::Yellow)),
                Span::raw("      Change master password"),
            ]),
            Line::from(""),
            Line::from(vec![Span::styled(
                "Key Operations:",
                Style::default().add_modifier(Modifier::BOLD),
            )]),
            Line::from(vec![
                Span::styled("L", Style::default().fg(Color::Yellow)),
                Span::raw("      Load selected disk key into memory"),
            ]),
            Line::from(vec![
                Span::styled("U", Style::default().fg(Color::Yellow)),
                Span::raw("      Unload selected key from memory"),
            ]),
            Line::from(vec![
                Span::styled("i", Style::default().fg(Color::Yellow)),
                Span::raw("      Import external key to storage"),
            ]),
            Line::from(vec![
                Span::styled("e", Style::default().fg(Color::Yellow)),
                Span::raw("      Edit key description"),
            ]),
            Line::from(vec![
                Span::styled("C", Style::default().fg(Color::Yellow)),
                Span::raw("      Update key certificate"),
            ]),
            Line::from(vec![
                Span::styled("n", Style::default().fg(Color::Yellow)),
                Span::raw("      Create new key"),
            ]),
            Line::from(vec![
                Span::styled("P", Style::default().fg(Color::Yellow)),
                Span::raw("      Set password protection on key"),
            ]),
            Line::from(vec![
                Span::styled("R", Style::default().fg(Color::Yellow)),
                Span::raw("      Remove password protection from key"),
            ]),
            Line::from(vec![
                Span::styled("d/Del", Style::default().fg(Color::Yellow)),
                Span::raw("  Permanently delete key from disk"),
            ]),
            Line::from(""),
            Line::from(vec![Span::styled(
                "Other:",
                Style::default().add_modifier(Modifier::BOLD),
            )]),
            Line::from(vec![
                Span::styled("r/F5", Style::default().fg(Color::Yellow)),
                Span::raw("   Refresh key list"),
            ]),
            Line::from(vec![
                Span::styled("a", Style::default().fg(Color::Yellow)),
                Span::raw("      Add key (use ssh-add)"),
            ]),
            Line::from(vec![
                Span::styled("h/?", Style::default().fg(Color::Yellow)),
                Span::raw("    Toggle this help"),
            ]),
            Line::from(vec![
                Span::styled("q", Style::default().fg(Color::Yellow)),
                Span::raw("      Quit"),
            ]),
        ];
        let help = Paragraph::new(help_text)
            .block(Block::default().title("Help").borders(Borders::ALL))
            .wrap(Wrap { trim: true });
        f.render_widget(help, chunks[1]);
    } else {
        // Key list
        let keys: Vec<ListItem> = app
            .keys
            .iter()
            .map(|key| {
                let mut spans = vec![];

                // Show key status based on loaded/disk status
                let status = if key.source == "external" && key.loaded {
                    "[EXT]" // External key loaded via ssh-add
                } else if key.source == "internal" && key.loaded && key.has_disk {
                    "[INT]" // Internal key loaded and on disk
                } else if !key.loaded && key.has_disk {
                    "[DISK]" // On disk but not loaded
                } else {
                    "[???]" // Shouldn't happen
                };

                spans.push(Span::styled(
                    status,
                    Style::default().fg(match status {
                        "[EXT]" => Color::Cyan,
                        "[INT]" => Color::Green,
                        "[DISK]" => Color::Gray,
                        _ => Color::Red,
                    }),
                ));
                spans.push(Span::raw(" "));

                // Key type
                spans.push(Span::styled(
                    &key.key_type,
                    Style::default().fg(Color::Green),
                ));
                spans.push(Span::raw(" "));

                // Show shortened fingerprint
                let short_fp = if key.fingerprint.len() > 20 {
                    format!(
                        "{}...{}",
                        &key.fingerprint[0..8],
                        &key.fingerprint[key.fingerprint.len() - 8..]
                    )
                } else {
                    key.fingerprint.clone()
                };
                spans.push(Span::styled(short_fp, Style::default().fg(Color::Yellow)));

                // Show description
                if !key.description.is_empty() {
                    spans.push(Span::raw(format!(" ({})", key.description)));
                }

                // Show if has cert
                if key.has_cert {
                    spans.push(Span::styled(" [CERT]", Style::default().fg(Color::Magenta)));
                }

                // Show if password protected
                if key.password_protected {
                    spans.push(Span::styled(" [🔒]", Style::default().fg(Color::Blue)));
                }

                // Show constraints if any
                if let Some(confirm) = key.constraints.get("confirm").and_then(|v| v.as_bool())
                    && confirm
                {
                    spans.push(Span::styled(" [C]", Style::default().fg(Color::Red)));
                }

                ListItem::new(Line::from(spans))
            })
            .collect();

        let keys_list = List::new(keys)
            .block(Block::default().title("SSH Keys").borders(Borders::ALL))
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ");

        f.render_stateful_widget(keys_list, chunks[1], &mut app.list_state.clone());
    }

    // Status bar
    let status_text = if let Some(ref msg) = app.status_message {
        msg.clone()
    } else if app.input_mode == InputMode::Password {
        format!("Password: {}", "*".repeat(app.input_buffer.len()))
    } else if app.input_mode == InputMode::KeyPassword {
        format!("Key password: {}", "*".repeat(app.input_buffer.len()))
    } else if app.input_mode == InputMode::SetKeyPassword {
        format!("Set key password: {}", "*".repeat(app.input_buffer.len()))
    } else if app.input_mode == InputMode::ConfirmKeyPassword {
        format!(
            "Confirm key password: {}",
            "*".repeat(app.input_buffer.len())
        )
    } else if app.input_mode == InputMode::RemoveKeyPassword {
        format!(
            "Current key password: {}",
            "*".repeat(app.input_buffer.len())
        )
    } else if app.input_mode == InputMode::ImportKeyPassword {
        format!("Import password: {}", "*".repeat(app.input_buffer.len()))
    } else if app.input_mode == InputMode::ImportKeyPasswordConfirm {
        format!(
            "Confirm import password: {}",
            "*".repeat(app.input_buffer.len())
        )
    } else if app.input_mode == InputMode::ChangePasswordOld {
        format!("Current password: {}", "*".repeat(app.input_buffer.len()))
    } else if app.input_mode == InputMode::ChangePasswordNew {
        format!("New password: {}", "*".repeat(app.input_buffer.len()))
    } else if app.input_mode == InputMode::Description {
        format!("Description: {}", app.input_buffer)
    } else if app.input_mode == InputMode::Certificate {
        format!("Certificate: {}", app.input_buffer)
    } else if app.input_mode == InputMode::CreateKeyType {
        "Select key type (e)d25519 or (r)sa:".to_string()
    } else if app.input_mode == InputMode::CreateBitLength {
        format!("Bit length: {}", app.input_buffer)
    } else if app.input_mode == InputMode::CreateDescription {
        format!("Description: {}", app.input_buffer)
    } else {
        format!("Keys: {} | Press h for help | q to quit", app.keys.len())
    };

    let status = Paragraph::new(status_text)
        .style(Style::default().fg(Color::White))
        .alignment(Alignment::Left)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(status, chunks[2]);
}

fn load_keys(
    app: &mut App,
    socket_path: Option<&String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Send CBOR extension request to list keys
    let socket = socket_path
        .cloned()
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
        .ok_or("No socket path available")?;

    // Connect to socket and send manage.list request
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(&socket)?;

    // Build CBOR request for manage.list
    let request = rssh_proto::cbor::ExtensionRequest {
        extension: "manage.list".to_string(),
        data: vec![],
    };

    let mut cbor_data = Vec::new();
    ciborium::into_writer(&request, &mut cbor_data)?;

    // Build SSH protocol message with extension namespace
    let mut message = Vec::new();
    message.push(rssh_proto::messages::SSH_AGENTC_EXTENSION);

    // Add extension namespace
    let ext_namespace = b"rssh-agent@local";
    message.extend_from_slice(&(ext_namespace.len() as u32).to_be_bytes());
    message.extend_from_slice(ext_namespace);

    // Add CBOR data
    message.extend_from_slice(&cbor_data);

    // Add length prefix for the whole message
    let mut full_message = Vec::new();
    full_message.extend_from_slice(&(message.len() as u32).to_be_bytes());
    full_message.extend_from_slice(&message);

    stream.write_all(&full_message)?;

    // Read response
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut response = vec![0u8; len];
    stream.read_exact(&mut response)?;

    // The daemon returns SSH_AGENT_SUCCESS (6) with wire-encoded CBOR data
    if response[0] == rssh_proto::messages::SSH_AGENT_SUCCESS {
        // Skip message type and read wire-encoded string length
        let mut offset = 1;
        if response.len() < offset + 4 {
            return Err("Response too short".into());
        }

        let data_len = u32::from_be_bytes([
            response[offset],
            response[offset + 1],
            response[offset + 2],
            response[offset + 3],
        ]) as usize;
        offset += 4;

        if response.len() < offset + data_len {
            return Err("Response data truncated".into());
        }

        // Parse CBOR response from the wire-encoded string
        let cbor_data = &response[offset..offset + data_len];
        let cbor_response: rssh_proto::cbor::ExtensionResponse = ciborium::from_reader(cbor_data)?;

        if cbor_response.success {
            // Parse the ManageListResponse from CBOR data
            use rssh_proto::cbor::ManageListResponse;

            let list_response: ManageListResponse = ciborium::from_reader(&cbor_response.data[..])?;

            if !list_response.ok {
                return Err("Server returned error in manage.list response".into());
            }

            let keys_data = list_response.keys;

            app.keys = keys_data
                .into_iter()
                .map(|k| KeyInfo {
                    fingerprint: k.fp_sha256_hex,
                    key_type: k.key_type,
                    format: k.format,
                    description: k.description,
                    source: k.source,
                    loaded: k.loaded,
                    has_disk: k.has_disk,
                    has_cert: k.has_cert,
                    password_protected: k.password_protected,
                    constraints: k.constraints,
                    created: k.created,
                    updated: k.updated,
                })
                .collect();

            // Update selection
            if !app.keys.is_empty() && app.list_state.selected().is_none() {
                app.list_state.select(Some(0));
                app.selected_key = Some(0);
            }
        } else {
            return Err(format!(
                "Extension failed: {}",
                String::from_utf8_lossy(&cbor_response.data)
            )
            .into());
        }
    } else if response[0] == rssh_proto::messages::SSH_AGENT_FAILURE {
        // Agent is locked or operation failed
        return Err("Agent is locked or operation failed".into());
    } else if response[0] == rssh_proto::messages::SSH_AGENT_EXTENSION_FAILURE {
        // Extension-specific failure
        return Err("Extension operation failed".into());
    } else {
        return Err(format!("Unexpected response type: {}", response[0]).into());
    }

    Ok(())
}

fn lock_agent(socket_path: Option<&String>) -> Result<(), Box<dyn std::error::Error>> {
    let socket = socket_path
        .cloned()
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
        .ok_or("No socket path available")?;

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(&socket)?;

    // Send lock message
    let message = vec![
        0,
        0,
        0,
        1, // Length
        rssh_proto::messages::SSH_AGENTC_LOCK,
    ];

    stream.write_all(&message)?;

    // Read response
    let mut response = [0u8; 5];
    stream.read_exact(&mut response)?;

    if response[4] != rssh_proto::messages::SSH_AGENT_SUCCESS {
        return Err("Failed to lock agent".into());
    }

    Ok(())
}

fn unlock_agent(
    socket_path: Option<&String>,
    password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = socket_path
        .cloned()
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
        .ok_or("No socket path available")?;

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(&socket)?;

    // Build unlock message with password
    let password_bytes = password.as_bytes();
    let mut message = Vec::new();
    message.extend_from_slice(&((password_bytes.len() + 5) as u32).to_be_bytes());
    message.push(rssh_proto::messages::SSH_AGENTC_UNLOCK);
    message.extend_from_slice(&(password_bytes.len() as u32).to_be_bytes());
    message.extend_from_slice(password_bytes);

    stream.write_all(&message)?;

    // Read response
    let mut response = [0u8; 5];
    stream.read_exact(&mut response)?;

    if response[4] != rssh_proto::messages::SSH_AGENT_SUCCESS {
        return Err("Failed to unlock agent".into());
    }

    Ok(())
}

fn remove_key(
    socket_path: Option<&String>,
    fingerprint: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    delete_key(socket_path, fingerprint)
}

fn delete_key(
    socket_path: Option<&String>,
    fingerprint: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = socket_path
        .cloned()
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
        .ok_or("No socket path available")?;

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(&socket)?;

    // Build CBOR request for manage.delete
    use rssh_proto::cbor::ExtensionRequest;
    let delete_data = {
        #[derive(serde::Serialize)]
        struct DeleteRequest {
            fp_sha256_hex: String,
        }

        let req = DeleteRequest {
            fp_sha256_hex: fingerprint.to_string(),
        };

        let mut cbor = Vec::new();
        ciborium::into_writer(&req, &mut cbor)?;
        cbor
    };

    let request = ExtensionRequest {
        extension: "manage.delete".to_string(),
        data: delete_data,
    };

    let mut cbor_data = Vec::new();
    ciborium::into_writer(&request, &mut cbor_data)?;

    // Build SSH protocol message with extension namespace
    let mut message = Vec::new();
    message.push(rssh_proto::messages::SSH_AGENTC_EXTENSION);

    // Add extension namespace
    let ext_namespace = b"rssh-agent@local";
    message.extend_from_slice(&(ext_namespace.len() as u32).to_be_bytes());
    message.extend_from_slice(ext_namespace);

    // Add CBOR data
    message.extend_from_slice(&cbor_data);

    // Add length prefix for the whole message
    let mut full_message = Vec::new();
    full_message.extend_from_slice(&(message.len() as u32).to_be_bytes());
    full_message.extend_from_slice(&message);

    stream.write_all(&full_message)?;

    // Read response
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut response = vec![0u8; len];
    stream.read_exact(&mut response)?;

    // Check response type
    if response[0] == rssh_proto::messages::SSH_AGENT_SUCCESS {
        // Parse the CBOR response to check if it's actually successful
        let mut offset = 1;
        if response.len() < offset + 4 {
            return Err("Response too short".into());
        }

        let data_len = u32::from_be_bytes([
            response[offset],
            response[offset + 1],
            response[offset + 2],
            response[offset + 3],
        ]) as usize;
        offset += 4;

        if response.len() < offset + data_len {
            return Err("Response data truncated".into());
        }

        let cbor_data = &response[offset..offset + data_len];
        let cbor_response: rssh_proto::cbor::ExtensionResponse = ciborium::from_reader(cbor_data)?;

        if !cbor_response.success {
            // Parse the actual response data for error message
            let response_data: serde_json::Value = ciborium::from_reader(&cbor_response.data[..])?;
            if let Some(error) = response_data.get("error").and_then(|e| e.as_str()) {
                return Err(error.into());
            }
            return Err("Delete operation failed".into());
        }

        Ok(())
    } else {
        Err("Failed to delete key".into())
    }
}

fn load_disk_key(
    socket_path: Option<&String>,
    fingerprint: &str,
    key_password: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = socket_path
        .cloned()
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
        .ok_or("No socket path available")?;

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(&socket)?;

    // Build CBOR request for manage.load
    use rssh_proto::cbor::ExtensionRequest;
    let load_data = {
        #[derive(serde::Serialize)]
        struct LoadRequest {
            fp_sha256_hex: String,
            key_pass_b64: Option<String>,
        }

        let key_pass_b64 = key_password.map(|pass| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(pass.as_bytes())
        });

        let req = LoadRequest {
            fp_sha256_hex: fingerprint.to_string(),
            key_pass_b64,
        };

        let mut cbor = Vec::new();
        ciborium::into_writer(&req, &mut cbor)?;
        cbor
    };

    let request = ExtensionRequest {
        extension: "manage.load".to_string(),
        data: load_data,
    };

    let mut cbor_data = Vec::new();
    ciborium::into_writer(&request, &mut cbor_data)?;

    // Build SSH protocol message with extension namespace
    let mut message = Vec::new();
    message.push(rssh_proto::messages::SSH_AGENTC_EXTENSION);

    // Add extension namespace
    let ext_namespace = b"rssh-agent@local";
    message.extend_from_slice(&(ext_namespace.len() as u32).to_be_bytes());
    message.extend_from_slice(ext_namespace);

    // Add CBOR data
    message.extend_from_slice(&cbor_data);

    // Add length prefix for the whole message
    let mut full_message = Vec::new();
    full_message.extend_from_slice(&(message.len() as u32).to_be_bytes());
    full_message.extend_from_slice(&message);

    stream.write_all(&full_message)?;

    // Read response
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut response = vec![0u8; len];
    stream.read_exact(&mut response)?;

    // Check response type
    if response[0] == rssh_proto::messages::SSH_AGENT_SUCCESS {
        // Parse the CBOR response to check if it's actually successful
        let mut offset = 1;
        if response.len() < offset + 4 {
            return Err("Response too short".into());
        }

        let data_len = u32::from_be_bytes([
            response[offset],
            response[offset + 1],
            response[offset + 2],
            response[offset + 3],
        ]) as usize;
        offset += 4;

        if response.len() < offset + data_len {
            return Err("Response data truncated".into());
        }

        let cbor_data = &response[offset..offset + data_len];
        let cbor_response: rssh_proto::cbor::ExtensionResponse = ciborium::from_reader(cbor_data)?;

        if !cbor_response.success {
            return Err(format!(
                "Load failed: {}",
                String::from_utf8_lossy(&cbor_response.data)
            )
            .into());
        }

        Ok(())
    } else {
        Err("Failed to load key from disk".into())
    }
}

fn import_key(
    socket_path: Option<&String>,
    fingerprint: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = socket_path
        .cloned()
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
        .ok_or("No socket path available")?;

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(&socket)?;

    // Build CBOR request for manage.import
    use rssh_proto::cbor::ExtensionRequest;
    let import_data = {
        #[derive(serde::Serialize)]
        struct ImportRequest {
            fp_sha256_hex: String,
            set_key_password: bool,
            new_key_pass_b64: Option<String>,
        }

        let req = ImportRequest {
            fp_sha256_hex: fingerprint.to_string(),
            set_key_password: false,
            new_key_pass_b64: None,
        };

        let mut data = Vec::new();
        ciborium::into_writer(&req, &mut data)?;
        data
    };

    let import_request = ExtensionRequest {
        extension: "manage.import".to_string(),
        data: import_data,
    };

    // Serialize request to CBOR
    let mut cbor_data = Vec::new();
    ciborium::into_writer(&import_request, &mut cbor_data)?;

    // Build extension message
    let mut message = Vec::new();
    let ext_name = "rssh-agent@local";

    // Message length (type + name_len + name + cbor)
    let total_len = 1 + 4 + ext_name.len() + cbor_data.len();
    message.extend_from_slice(&(total_len as u32).to_be_bytes());

    // Message type: SSH_AGENTC_EXTENSION (27)
    message.push(27);

    // Extension name
    message.extend_from_slice(&(ext_name.len() as u32).to_be_bytes());
    message.extend_from_slice(ext_name.as_bytes());

    // CBOR data
    message.extend_from_slice(&cbor_data);

    // Send request
    stream.write_all(&message)?;

    // Read response length
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let response_len = u32::from_be_bytes(len_buf) as usize;

    // Read response
    let mut response = vec![0u8; response_len];
    stream.read_exact(&mut response)?;

    // Check response type
    if response[0] != rssh_proto::messages::SSH_AGENT_SUCCESS {
        return Err("Import failed".into());
    }

    // Parse CBOR response if needed
    // For now, just return success if we got SSH_AGENT_SUCCESS

    Ok(())
}

fn unload_key(
    socket_path: Option<&String>,
    fingerprint: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = socket_path
        .cloned()
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
        .ok_or("No socket path available")?;

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(&socket)?;

    // Build CBOR request for manage.unload
    use rssh_proto::cbor::ExtensionRequest;
    let unload_data = {
        #[derive(serde::Serialize)]
        struct UnloadRequest {
            fp_sha256_hex: String,
        }

        let req = UnloadRequest {
            fp_sha256_hex: fingerprint.to_string(),
        };

        let mut cbor = Vec::new();
        ciborium::into_writer(&req, &mut cbor)?;
        cbor
    };

    let request = ExtensionRequest {
        extension: "manage.unload".to_string(),
        data: unload_data,
    };

    let mut cbor_data = Vec::new();
    ciborium::into_writer(&request, &mut cbor_data)?;

    // Build SSH protocol message with extension namespace
    let mut message = Vec::new();
    message.push(rssh_proto::messages::SSH_AGENTC_EXTENSION);

    // Add extension namespace
    let ext_namespace = b"rssh-agent@local";
    message.extend_from_slice(&(ext_namespace.len() as u32).to_be_bytes());
    message.extend_from_slice(ext_namespace);

    // Add CBOR data
    message.extend_from_slice(&cbor_data);

    // Add length prefix for the whole message
    let mut full_message = Vec::new();
    full_message.extend_from_slice(&(message.len() as u32).to_be_bytes());
    full_message.extend_from_slice(&message);

    stream.write_all(&full_message)?;

    // Read response
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut response = vec![0u8; len];
    stream.read_exact(&mut response)?;

    if response[0] == rssh_proto::messages::SSH_AGENT_SUCCESS {
        Ok(())
    } else {
        Err("Failed to unload key".into())
    }
}

fn set_key_description(
    socket_path: Option<&String>,
    fingerprint: &str,
    description: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = socket_path
        .cloned()
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
        .ok_or("No socket path available")?;

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(&socket)?;

    // Build CBOR request for manage.set_desc
    use rssh_proto::cbor::ExtensionRequest;
    let set_desc_data = {
        #[derive(serde::Serialize)]
        struct SetDescRequest {
            fp_sha256_hex: String,
            description: String,
        }

        let req = SetDescRequest {
            fp_sha256_hex: fingerprint.to_string(),
            description: description.to_string(),
        };

        let mut cbor = Vec::new();
        ciborium::into_writer(&req, &mut cbor)?;
        cbor
    };

    let request = ExtensionRequest {
        extension: "manage.set_desc".to_string(),
        data: set_desc_data,
    };

    let mut cbor_data = Vec::new();
    ciborium::into_writer(&request, &mut cbor_data)?;

    // Build SSH protocol message with extension namespace
    let mut message = Vec::new();
    message.push(rssh_proto::messages::SSH_AGENTC_EXTENSION);

    // Add extension namespace
    let ext_namespace = b"rssh-agent@local";
    message.extend_from_slice(&(ext_namespace.len() as u32).to_be_bytes());
    message.extend_from_slice(ext_namespace);

    // Add CBOR data
    message.extend_from_slice(&cbor_data);

    // Add length prefix for the whole message
    let mut full_message = Vec::new();
    full_message.extend_from_slice(&(message.len() as u32).to_be_bytes());
    full_message.extend_from_slice(&message);

    stream.write_all(&full_message)?;

    // Read response
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut response = vec![0u8; len];
    stream.read_exact(&mut response)?;

    if response[0] == rssh_proto::messages::SSH_AGENT_SUCCESS {
        Ok(())
    } else {
        Err("Failed to set description".into())
    }
}

fn change_master_password(
    socket_path: Option<&String>,
    old_password: &str,
    new_password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = socket_path
        .cloned()
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
        .ok_or("No socket path available")?;

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(&socket)?;

    // Build CBOR request for manage.change_pass
    use rssh_proto::cbor::ExtensionRequest;
    let change_pass_data = {
        #[derive(serde::Serialize)]
        struct ChangePassRequest {
            old_password: String,
            new_password: String,
        }

        let req = ChangePassRequest {
            old_password: old_password.to_string(),
            new_password: new_password.to_string(),
        };

        let mut cbor = Vec::new();
        ciborium::into_writer(&req, &mut cbor)?;
        cbor
    };

    let request = ExtensionRequest {
        extension: "manage.change_pass".to_string(),
        data: change_pass_data,
    };

    let mut cbor_data = Vec::new();
    ciborium::into_writer(&request, &mut cbor_data)?;

    // Build SSH protocol message with extension namespace
    let mut message = Vec::new();
    message.push(rssh_proto::messages::SSH_AGENTC_EXTENSION);

    // Add extension namespace
    let ext_namespace = b"rssh-agent@local";
    message.extend_from_slice(&(ext_namespace.len() as u32).to_be_bytes());
    message.extend_from_slice(ext_namespace);

    // Add CBOR data
    message.extend_from_slice(&cbor_data);

    // Add length prefix for the whole message
    let mut full_message = Vec::new();
    full_message.extend_from_slice(&(message.len() as u32).to_be_bytes());
    full_message.extend_from_slice(&message);

    stream.write_all(&full_message)?;

    // Read response
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut response = vec![0u8; len];
    stream.read_exact(&mut response)?;

    if response[0] == rssh_proto::messages::SSH_AGENT_SUCCESS {
        // Parse the CBOR response to check if it's actually successful
        let mut offset = 1;
        if response.len() < offset + 4 {
            return Err("Response too short".into());
        }

        let data_len = u32::from_be_bytes([
            response[offset],
            response[offset + 1],
            response[offset + 2],
            response[offset + 3],
        ]) as usize;
        offset += 4;

        if response.len() < offset + data_len {
            return Err("Response data truncated".into());
        }

        let cbor_data = &response[offset..offset + data_len];
        let cbor_response: rssh_proto::cbor::ExtensionResponse = ciborium::from_reader(cbor_data)?;

        if !cbor_response.success {
            // Parse the actual response data for error message
            let response_data: serde_json::Value = ciborium::from_reader(&cbor_response.data[..])?;
            if let Some(error) = response_data.get("error").and_then(|e| e.as_str()) {
                return Err(error.into());
            }
            return Err("Change password operation failed".into());
        }

        Ok(())
    } else {
        Err("Failed to change master password".into())
    }
}

fn update_certificate(
    socket_path: Option<&String>,
    fingerprint: &str,
    certificate: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = socket_path
        .cloned()
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
        .ok_or("No socket path available")?;

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(&socket)?;

    // Build CBOR request for manage.update_cert
    use rssh_proto::cbor::ExtensionRequest;
    let update_cert_data = {
        #[derive(serde::Serialize)]
        struct UpdateCertRequest {
            fp_sha256_hex: String,
            cert_openssh_b64: String,
        }

        let req = UpdateCertRequest {
            fp_sha256_hex: fingerprint.to_string(),
            cert_openssh_b64: certificate.to_string(),
        };

        let mut cbor = Vec::new();
        ciborium::into_writer(&req, &mut cbor)?;
        cbor
    };

    let request = ExtensionRequest {
        extension: "manage.update_cert".to_string(),
        data: update_cert_data,
    };

    let mut cbor_data = Vec::new();
    ciborium::into_writer(&request, &mut cbor_data)?;

    // Build SSH protocol message with extension namespace
    let mut message = Vec::new();
    message.push(rssh_proto::messages::SSH_AGENTC_EXTENSION);

    // Add extension namespace
    let ext_namespace = b"rssh-agent@local";
    message.extend_from_slice(&(ext_namespace.len() as u32).to_be_bytes());
    message.extend_from_slice(ext_namespace);

    // Add CBOR data
    message.extend_from_slice(&cbor_data);

    // Add length prefix for the whole message
    let mut full_message = Vec::new();
    full_message.extend_from_slice(&(message.len() as u32).to_be_bytes());
    full_message.extend_from_slice(&message);

    stream.write_all(&full_message)?;

    // Read response
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut response = vec![0u8; len];
    stream.read_exact(&mut response)?;

    if response[0] == rssh_proto::messages::SSH_AGENT_SUCCESS {
        Ok(())
    } else {
        Err("Failed to update certificate".into())
    }
}

fn create_key(
    socket_path: Option<&String>,
    key_type: &str,
    bit_length: Option<u32>,
    description: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = socket_path
        .cloned()
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
        .ok_or("No socket path available")?;

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(&socket)?;

    // Build CBOR request for manage.create
    use rssh_proto::cbor::ExtensionRequest;
    let create_data = {
        #[derive(serde::Serialize)]
        struct CreateRequest {
            key_type: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            bit_length: Option<u32>,
            #[serde(skip_serializing_if = "Option::is_none")]
            description: Option<String>,
            load_to_ram: bool,
        }

        let req = CreateRequest {
            key_type: key_type.to_string(),
            bit_length,
            description,
            load_to_ram: true, // Always load newly created keys
        };

        let mut cbor = Vec::new();
        ciborium::into_writer(&req, &mut cbor)?;
        cbor
    };

    let request = ExtensionRequest {
        extension: "manage.create".to_string(),
        data: create_data,
    };

    let mut cbor_data = Vec::new();
    ciborium::into_writer(&request, &mut cbor_data)?;

    // Build SSH protocol message with extension namespace
    let mut message = Vec::new();
    message.push(rssh_proto::messages::SSH_AGENTC_EXTENSION);

    // Add extension namespace
    let ext_namespace = b"rssh-agent@local";
    message.extend_from_slice(&(ext_namespace.len() as u32).to_be_bytes());
    message.extend_from_slice(ext_namespace);

    // Add CBOR data
    message.extend_from_slice(&cbor_data);

    // Add length prefix for the whole message
    let mut full_message = Vec::new();
    full_message.extend_from_slice(&(message.len() as u32).to_be_bytes());
    full_message.extend_from_slice(&message);

    stream.write_all(&full_message)?;

    // Read response
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut response = vec![0u8; len];
    stream.read_exact(&mut response)?;

    if response[0] == rssh_proto::messages::SSH_AGENT_SUCCESS {
        // Parse the CBOR response to check if it's actually successful
        let mut offset = 1;
        if response.len() < offset + 4 {
            return Err("Response too short".into());
        }

        let data_len = u32::from_be_bytes([
            response[offset],
            response[offset + 1],
            response[offset + 2],
            response[offset + 3],
        ]) as usize;
        offset += 4;

        if response.len() < offset + data_len {
            return Err("Response data truncated".into());
        }

        let cbor_data = &response[offset..offset + data_len];
        let cbor_response: rssh_proto::cbor::ExtensionResponse = ciborium::from_reader(cbor_data)?;

        if !cbor_response.success {
            // Parse the actual response data for error message
            let response_data: serde_json::Value = ciborium::from_reader(&cbor_response.data[..])?;
            if let Some(error) = response_data.get("error").and_then(|e| e.as_str()) {
                return Err(error.into());
            }
            return Err("Key creation failed".into());
        }

        Ok(())
    } else {
        Err("Failed to create key".into())
    }
}

// Load key with constraints support
fn load_disk_key_with_constraints(
    socket_path: Option<&String>,
    fingerprint: &str,
    key_password: Option<&str>,
    confirm: bool,
    lifetime: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = socket_path
        .cloned()
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
        .ok_or("No socket path available")?;

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(&socket)?;

    // Build CBOR request for manage.load with constraints
    use rssh_proto::cbor::ExtensionRequest;
    let load_data = {
        #[derive(serde::Serialize)]
        struct LoadRequestWithConstraints {
            fp_sha256_hex: String,
            key_pass_b64: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            confirm: Option<bool>,
            #[serde(skip_serializing_if = "Option::is_none")]
            lifetime_seconds: Option<u32>,
        }

        let key_pass_b64 = key_password.map(|pass| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(pass.as_bytes())
        });

        let lifetime_seconds = if let Some(lifetime_str) = lifetime {
            Some(parse_lifetime(lifetime_str)?)
        } else {
            None
        };

        let req = LoadRequestWithConstraints {
            fp_sha256_hex: fingerprint.to_string(),
            key_pass_b64,
            confirm: if confirm { Some(true) } else { None },
            lifetime_seconds,
        };

        let mut cbor = Vec::new();
        ciborium::into_writer(&req, &mut cbor)?;
        cbor
    };

    let request = ExtensionRequest {
        extension: "manage.load".to_string(),
        data: load_data,
    };

    let mut cbor_data = Vec::new();
    ciborium::into_writer(&request, &mut cbor_data)?;

    // Build SSH protocol message with extension namespace
    let mut message = Vec::new();
    message.push(rssh_proto::messages::SSH_AGENTC_EXTENSION);

    // Add extension namespace
    let ext_namespace = b"rssh-agent@local";
    message.extend_from_slice(&(ext_namespace.len() as u32).to_be_bytes());
    message.extend_from_slice(ext_namespace);

    // Add CBOR data
    message.extend_from_slice(&cbor_data);

    // Add length prefix for the whole message
    let mut full_message = Vec::new();
    full_message.extend_from_slice(&(message.len() as u32).to_be_bytes());
    full_message.extend_from_slice(&message);

    stream.write_all(&full_message)?;

    // Read response
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut response = vec![0u8; len];
    stream.read_exact(&mut response)?;

    // Check response type
    if response[0] == rssh_proto::messages::SSH_AGENT_SUCCESS {
        // Parse the CBOR response to check if it's actually successful
        let mut offset = 1;
        if response.len() < offset + 4 {
            return Err("Response too short".into());
        }

        let data_len = u32::from_be_bytes([
            response[offset],
            response[offset + 1],
            response[offset + 2],
            response[offset + 3],
        ]) as usize;
        offset += 4;

        if response.len() < offset + data_len {
            return Err("Response data truncated".into());
        }

        let cbor_data = &response[offset..offset + data_len];
        let cbor_response: rssh_proto::cbor::ExtensionResponse = ciborium::from_reader(cbor_data)?;

        if !cbor_response.success {
            return Err(format!(
                "Load failed: {}",
                String::from_utf8_lossy(&cbor_response.data)
            )
            .into());
        }

        Ok(())
    } else {
        Err("Failed to load key from disk".into())
    }
}

// Create key with constraints support
fn create_key_with_constraints(
    socket_path: Option<&String>,
    key_type: &str,
    bit_length: Option<u32>,
    description: Option<String>,
    confirm: bool,
    lifetime: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = socket_path
        .cloned()
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
        .ok_or("No socket path available")?;

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(&socket)?;

    // Build CBOR request for manage.create with constraints
    use rssh_proto::cbor::ExtensionRequest;
    let create_data = {
        #[derive(serde::Serialize)]
        struct CreateRequestWithConstraints {
            key_type: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            bit_length: Option<u32>,
            #[serde(skip_serializing_if = "Option::is_none")]
            description: Option<String>,
            load_to_ram: bool,
            #[serde(skip_serializing_if = "Option::is_none")]
            confirm: Option<bool>,
            #[serde(skip_serializing_if = "Option::is_none")]
            lifetime_seconds: Option<u32>,
        }

        let lifetime_seconds = if let Some(lifetime_str) = lifetime {
            Some(parse_lifetime(lifetime_str)?)
        } else {
            None
        };

        let req = CreateRequestWithConstraints {
            key_type: key_type.to_string(),
            bit_length,
            description,
            load_to_ram: true, // Always load newly created keys
            confirm: if confirm { Some(true) } else { None },
            lifetime_seconds,
        };

        let mut cbor = Vec::new();
        ciborium::into_writer(&req, &mut cbor)?;
        cbor
    };

    let request = ExtensionRequest {
        extension: "manage.create".to_string(),
        data: create_data,
    };

    let mut cbor_data = Vec::new();
    ciborium::into_writer(&request, &mut cbor_data)?;

    // Build SSH protocol message with extension namespace
    let mut message = Vec::new();
    message.push(rssh_proto::messages::SSH_AGENTC_EXTENSION);

    // Add extension namespace
    let ext_namespace = b"rssh-agent@local";
    message.extend_from_slice(&(ext_namespace.len() as u32).to_be_bytes());
    message.extend_from_slice(ext_namespace);

    // Add CBOR data
    message.extend_from_slice(&cbor_data);

    // Add length prefix for the whole message
    let mut full_message = Vec::new();
    full_message.extend_from_slice(&(message.len() as u32).to_be_bytes());
    full_message.extend_from_slice(&message);

    stream.write_all(&full_message)?;

    // Read response
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut response = vec![0u8; len];
    stream.read_exact(&mut response)?;

    if response[0] == rssh_proto::messages::SSH_AGENT_SUCCESS {
        // Parse the CBOR response to check if it's actually successful
        let mut offset = 1;
        if response.len() < offset + 4 {
            return Err("Response too short".into());
        }

        let data_len = u32::from_be_bytes([
            response[offset],
            response[offset + 1],
            response[offset + 2],
            response[offset + 3],
        ]) as usize;
        offset += 4;

        if response.len() < offset + data_len {
            return Err("Response data truncated".into());
        }

        let cbor_data = &response[offset..offset + data_len];
        let cbor_response: rssh_proto::cbor::ExtensionResponse = ciborium::from_reader(cbor_data)?;

        if !cbor_response.success {
            // Parse the actual response data for error message
            let response_data: serde_json::Value = ciborium::from_reader(&cbor_response.data[..])?;
            if let Some(error) = response_data.get("error").and_then(|e| e.as_str()) {
                return Err(error.into());
            }
            return Err("Key creation failed".into());
        }

        Ok(())
    } else {
        Err("Failed to create key".into())
    }
}

// Helper function to handle load results consistently
fn handle_load_result(
    app: &mut App,
    socket_path: Option<&String>,
    result: Result<(), Box<dyn std::error::Error>>,
) {
    match result {
        Ok(()) => {
            app.set_status("Key loaded successfully".to_string());
            if let Err(e) = load_keys(app, socket_path) {
                app.set_status(format!("Failed to refresh: {}", e));
            }
        }
        Err(e) => {
            let error_msg = e.to_string();
            // Check if it's a password-related error and we haven't prompted yet
            if (error_msg.contains("password")
                || error_msg.contains("passphrase")
                || error_msg.contains("encrypted")
                || error_msg.contains("decrypt")
                || error_msg.contains("wrong password")
                || error_msg.contains("invalid password"))
                && app.key_being_loaded.is_none()
            {
                // Prompt for key password
                if let ConstraintContext::Load(fingerprint) = &app.constraint_context {
                    app.input_mode = InputMode::KeyPassword;
                    app.input_buffer.clear();
                    app.key_being_loaded = Some(fingerprint.clone());
                    app.set_status(
                        "Wrong password or key is password-protected. Enter password:".to_string(),
                    );
                } else {
                    app.set_status(format!("Failed to load key: {}", e));
                }
            } else {
                app.set_status(format!("Failed to load key: {}", e));
            }
        }
    }
}

fn set_key_password(
    socket_path: Option<&String>,
    fingerprint: &str,
    password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = socket_path
        .cloned()
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
        .ok_or("No socket path available")?;

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(&socket)?;

    // Build CBOR request for manage.set_password
    use rssh_proto::cbor::ExtensionRequest;
    let request_data = {
        #[derive(serde::Serialize)]
        struct SetPasswordRequest {
            fp_sha256_hex: String,
            set_password_protection: bool,
            new_key_pass_b64: String,
        }

        let req = SetPasswordRequest {
            fp_sha256_hex: fingerprint.to_string(),
            set_password_protection: true,
            new_key_pass_b64: {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(password.as_bytes())
            },
        };

        let mut data = Vec::new();
        ciborium::into_writer(&req, &mut data)?;
        data
    };

    let request = ExtensionRequest {
        extension: "manage.set_password".to_string(),
        data: request_data,
    };

    let mut cbor_data = Vec::new();
    ciborium::into_writer(&request, &mut cbor_data)?;

    // Build SSH protocol message with extension namespace
    let mut message = Vec::new();
    message.push(rssh_proto::messages::SSH_AGENTC_EXTENSION);

    // Add extension namespace
    let ext_namespace = b"rssh-agent@local";
    message.extend_from_slice(&(ext_namespace.len() as u32).to_be_bytes());
    message.extend_from_slice(ext_namespace);

    // Add CBOR data
    message.extend_from_slice(&cbor_data);

    // Add length prefix for the whole message
    let mut full_message = Vec::new();
    full_message.extend_from_slice(&(message.len() as u32).to_be_bytes());
    full_message.extend_from_slice(&message);

    stream.write_all(&full_message)?;

    // Read response
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut response = vec![0u8; len];
    stream.read_exact(&mut response)?;

    // Check response type
    if response[0] == rssh_proto::messages::SSH_AGENT_SUCCESS {
        // Parse the CBOR response to check if it's actually successful
        let mut offset = 1;
        if response.len() < offset + 4 {
            return Err("Response too short".into());
        }

        let data_len = u32::from_be_bytes([
            response[offset],
            response[offset + 1],
            response[offset + 2],
            response[offset + 3],
        ]) as usize;
        offset += 4;

        if response.len() < offset + data_len {
            return Err("Response data truncated".into());
        }

        let cbor_data = &response[offset..offset + data_len];
        let cbor_response: rssh_proto::cbor::ExtensionResponse = ciborium::from_reader(cbor_data)?;

        if !cbor_response.success {
            return Err(format!(
                "Set password failed: {}",
                String::from_utf8_lossy(&cbor_response.data)
            )
            .into());
        }

        Ok(())
    } else {
        Err("Failed to set key password".into())
    }
}

fn remove_key_password(
    socket_path: Option<&String>,
    fingerprint: &str,
    current_password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = socket_path
        .cloned()
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
        .ok_or("No socket path available")?;

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(&socket)?;

    // Build CBOR request for manage.set_password with set_password_protection=false
    use rssh_proto::cbor::ExtensionRequest;
    let request_data = {
        #[derive(serde::Serialize)]
        struct RemovePasswordRequest {
            fp_sha256_hex: String,
            set_password_protection: bool,
            new_key_pass_b64: Option<String>,
            current_key_pass_b64: Option<String>,
        }

        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
        let current_pass_b64 = BASE64.encode(current_password.as_bytes());

        let req = RemovePasswordRequest {
            fp_sha256_hex: fingerprint.to_string(),
            set_password_protection: false,
            new_key_pass_b64: None,
            current_key_pass_b64: Some(current_pass_b64),
        };

        let mut data = Vec::new();
        ciborium::into_writer(&req, &mut data)?;
        data
    };

    let request = ExtensionRequest {
        extension: "manage.set_password".to_string(),
        data: request_data,
    };

    let mut cbor_data = Vec::new();
    ciborium::into_writer(&request, &mut cbor_data)?;

    // Build SSH protocol message with extension namespace
    let mut message = Vec::new();
    message.push(rssh_proto::messages::SSH_AGENTC_EXTENSION);

    // Add extension namespace
    let ext_namespace = b"rssh-agent@local";
    message.extend_from_slice(&(ext_namespace.len() as u32).to_be_bytes());
    message.extend_from_slice(ext_namespace);

    // Add CBOR data
    message.extend_from_slice(&cbor_data);

    // Add length prefix for the whole message
    let mut full_message = Vec::new();
    full_message.extend_from_slice(&(message.len() as u32).to_be_bytes());
    full_message.extend_from_slice(&message);

    stream.write_all(&full_message)?;

    // Read response
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut response = vec![0u8; len];
    stream.read_exact(&mut response)?;

    // Check response type
    if response[0] == rssh_proto::messages::SSH_AGENT_SUCCESS {
        // Parse the CBOR response to check if it's actually successful
        let mut offset = 1;
        if response.len() < offset + 4 {
            return Err("Response too short".into());
        }

        let data_len = u32::from_be_bytes([
            response[offset],
            response[offset + 1],
            response[offset + 2],
            response[offset + 3],
        ]) as usize;
        offset += 4;

        if response.len() < offset + data_len {
            return Err("Response data truncated".into());
        }

        let cbor_data = &response[offset..offset + data_len];
        let cbor_response: rssh_proto::cbor::ExtensionResponse = ciborium::from_reader(cbor_data)?;

        if !cbor_response.success {
            return Err(format!(
                "Remove password failed: {}",
                String::from_utf8_lossy(&cbor_response.data)
            )
            .into());
        }

        Ok(())
    } else {
        Err("Failed to remove key password".into())
    }
}

fn import_key_with_password(
    socket_path: Option<&String>,
    fingerprint: &str,
    password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = socket_path
        .cloned()
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
        .ok_or("No socket path available")?;

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(&socket)?;

    // Build CBOR request for manage.import with password protection
    use rssh_proto::cbor::ExtensionRequest;
    let import_data = {
        #[derive(serde::Serialize)]
        struct ImportWithPasswordRequest {
            fp_sha256_hex: String,
            set_key_password: bool,
            new_key_pass_b64: String,
        }

        let req = ImportWithPasswordRequest {
            fp_sha256_hex: fingerprint.to_string(),
            set_key_password: true,
            new_key_pass_b64: {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(password.as_bytes())
            },
        };

        let mut data = Vec::new();
        ciborium::into_writer(&req, &mut data)?;
        data
    };

    let request = ExtensionRequest {
        extension: "manage.import".to_string(),
        data: import_data,
    };

    let mut cbor_data = Vec::new();
    ciborium::into_writer(&request, &mut cbor_data)?;

    // Build extension message
    let mut message = Vec::new();
    let ext_name = "rssh-agent@local";

    // Message length (type + name_len + name + cbor)
    let total_len = 1 + 4 + ext_name.len() + cbor_data.len();
    message.extend_from_slice(&(total_len as u32).to_be_bytes());

    // Message type: SSH_AGENTC_EXTENSION (27)
    message.push(27);

    // Extension name
    message.extend_from_slice(&(ext_name.len() as u32).to_be_bytes());
    message.extend_from_slice(ext_name.as_bytes());

    // CBOR data
    message.extend_from_slice(&cbor_data);

    // Send request
    stream.write_all(&message)?;

    // Read response length
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let response_len = u32::from_be_bytes(len_buf) as usize;

    // Read response
    let mut response = vec![0u8; response_len];
    stream.read_exact(&mut response)?;

    // Check response type
    if response[0] != rssh_proto::messages::SSH_AGENT_SUCCESS {
        return Err("Import with password failed".into());
    }

    Ok(())
}
