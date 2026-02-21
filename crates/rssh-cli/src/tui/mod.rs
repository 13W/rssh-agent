#![allow(clippy::collapsible_if)]
#![allow(clippy::map_clone)]
#![allow(clippy::new_without_default)]

pub mod modals;
pub mod widgets;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
};
use std::io;

pub use rssh_types::ManagedKey as KeyInfo;

use modals::{
    ActiveModal, ModalEvent,
    AuthenticationState, DescriptionState, PasswordChangeState, ConfirmationState,
    ExpirationState, RemovePasswordState, KeyPasswordState, SetKeyPasswordState,
    CreateKeyState, ImportKeyState, DeleteConfirmState,
};
use modals::create_key::KeyTypeOption;

// ─── Supporting enums ──────────────────────────────────────────────────────

/// Which frame currently has focus
#[derive(PartialEq, Clone, Debug)]
pub enum ActiveFrame {
    KeysList,
    InfoPanel,
}

/// Content shown in the info panel
#[derive(PartialEq, Clone, Debug)]
pub enum InfoPanelContent {
    KeyDetails,
    Help,
}

/// Fields that can be selected in the key details panel
#[derive(PartialEq, Clone, Debug)]
pub enum InfoPanelField {
    Description,
    Password,
    Confirmation,
    Expiration,
}

/// Status message type
#[derive(PartialEq, Clone, Debug)]
pub enum StatusType {
    Success,
    Error,
    Info,
}

/// Whether the app is in normal mode or update-certificate inline mode.
#[derive(PartialEq, Clone, Debug)]
enum AppMode {
    Normal,
    /// Paste certificate in-place (inline, not a modal)
    UpdateCertificate { fingerprint: String, buffer: String },
}

/// Constraint option for confirmation settings
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ConstraintOption {
    #[default]
    None,
    Notification,
    Confirmation,
}

impl From<(bool, bool)> for ConstraintOption {
    fn from((confirm, notify): (bool, bool)) -> Self {
        match (confirm, notify) {
            (true, _) => ConstraintOption::Confirmation,
            (false, true) => ConstraintOption::Notification,
            (false, false) => ConstraintOption::None,
        }
    }
}

impl ConstraintOption {
    pub fn to_bools(self) -> (bool, bool) {
        match self {
            ConstraintOption::None => (false, false),
            ConstraintOption::Notification => (false, true),
            ConstraintOption::Confirmation => (true, false),
        }
    }

}

// ─── App struct (12 fields) ────────────────────────────────────────────────

pub struct App {
    pub keys: Vec<KeyInfo>,
    pub list_state: ListState,
    pub selected_key: Option<usize>,
    pub status_message: Option<String>,
    pub status_type: StatusType,
    pub active_frame: ActiveFrame,
    pub info_panel_content: InfoPanelContent,
    pub selected_info_field: InfoPanelField,
    pub should_quit: bool,
    pub modal: Option<ActiveModal>,
    /// Inline (non-modal) app modes
    mode: AppMode,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        Self {
            keys: Vec::new(),
            list_state: ListState::default(),
            selected_key: None,
            status_message: None,
            status_type: StatusType::Info,
            active_frame: ActiveFrame::KeysList,
            info_panel_content: InfoPanelContent::KeyDetails,
            selected_info_field: InfoPanelField::Description,
            should_quit: false,
            modal: None,
            mode: AppMode::Normal,
        }
    }

    pub fn next(&mut self) {
        if self.keys.is_empty() {
            return;
        }
        let i = match self.list_state.selected() {
            Some(i) => {
                if i >= self.keys.len() - 1 { 0 } else { i + 1 }
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
                if i == 0 { self.keys.len() - 1 } else { i - 1 }
            }
            None => 0,
        };
        self.list_state.select(Some(i));
        self.selected_key = Some(i);
    }

    pub fn set_status(&mut self, message: String) {
        self.status_message = Some(message);
        self.status_type = StatusType::Info;
    }

    pub fn set_status_with_type(&mut self, message: String, status_type: StatusType) {
        self.status_message = Some(message);
        self.status_type = status_type;
    }

    pub fn next_frame(&mut self) {
        self.active_frame = match self.active_frame {
            ActiveFrame::KeysList => ActiveFrame::InfoPanel,
            ActiveFrame::InfoPanel => ActiveFrame::KeysList,
        };
    }

    pub fn toggle_info_panel_content(&mut self) {
        self.info_panel_content = match self.info_panel_content {
            InfoPanelContent::KeyDetails => InfoPanelContent::Help,
            InfoPanelContent::Help => InfoPanelContent::KeyDetails,
        };
    }

    pub fn close_modal(&mut self) {
        self.modal = None;
    }

}

// ─── Entry point ──────────────────────────────────────────────────────────

pub fn run_tui(socket_path: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();
    // Start with authentication modal
    app.modal = Some(ActiveModal::Authentication(AuthenticationState::new()));

    let res = run_app(&mut terminal, &mut app, socket_path);

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

// ─── Main event loop ──────────────────────────────────────────────────────

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
            if let Some(ref mut modal) = app.modal {
                let event = modals::handle_modal_key(modal, key.code);
                handle_modal_event(app, event, socket_path.as_ref());
            } else {
                handle_normal_key(app, key.code, socket_path.as_ref());
            }
        }

        if app.should_quit {
            return Ok(());
        }
    }
}

// ─── Modal event dispatch ─────────────────────────────────────────────────

fn handle_modal_event(
    app: &mut App,
    event: ModalEvent,
    socket_path: Option<&String>,
) {
    match event {
        ModalEvent::None => {}
        ModalEvent::Cancel => {
            app.close_modal();
        }
        ModalEvent::ResetTimer => {
            // Only used by ExpirationState
            if let Some(ActiveModal::Expiration(ref state)) = app.modal {
                let fp = state.fp.clone();
                let default_lifetime = state.default_lifetime.value.trim().to_string();

                if let Some(idx) = app.selected_key {
                    if idx < app.keys.len() && app.keys[idx].loaded {
                        let current_confirm = app.keys[idx]
                            .constraints.get("confirm").and_then(|v| v.as_bool()).unwrap_or(false);
                        let current_notify = app.keys[idx]
                            .constraints.get("notification").and_then(|v| v.as_bool()).unwrap_or(false);

                        let lifetime_str = if default_lifetime.is_empty() { None } else { Some(default_lifetime.as_str()) };
                        match set_constraints(socket_path, &fp, current_confirm, current_notify, lifetime_str) {
                            Ok(()) => {
                                let msg = if default_lifetime.is_empty() {
                                    "Timer removed".to_string()
                                } else {
                                    format!("Timer reset to {}", default_lifetime)
                                };
                                app.set_status(msg);
                                let _ = load_keys(app, socket_path);
                            }
                            Err(e) => {
                                if let Some(ActiveModal::Expiration(ref mut s)) = app.modal {
                                    s.error = Some(format!("Failed to reset timer: {}", e));
                                }
                                return;
                            }
                        }
                        app.close_modal();
                    } else if let Some(ActiveModal::Expiration(ref mut s)) = app.modal {
                        s.error = Some("Key must be loaded to reset timer".to_string());
                    }
                }
            }
        }
        ModalEvent::Confirm => {
            // Take the modal out so we can destructure it
            let modal = app.modal.take();
            match modal {
                Some(ActiveModal::Authentication(state)) => {
                    let pw = state.password.value.clone();
                    match unlock_agent(socket_path, &pw) {
                        Ok(()) => {
                            if let Err(e) = load_keys(app, socket_path) {
                                app.set_status(format!("Failed to load keys: {}", e));
                            } else {
                                app.set_status("Authentication successful".to_string());
                            }
                        }
                        Err(e) => {
                            let mut new_state = AuthenticationState::new();
                            new_state.error = Some(format!("Authentication failed: {}", e));
                            app.modal = Some(ActiveModal::Authentication(new_state));
                        }
                    }
                }
                Some(ActiveModal::Description(state)) => {
                    let fp = state.fp.clone();
                    let desc = state.input.value.trim().to_string();
                    match set_key_description(socket_path, &fp, &desc) {
                        Ok(()) => {
                            app.set_status("Description updated".to_string());
                            let _ = load_keys(app, socket_path);
                        }
                        Err(e) => {
                            let mut new_state = DescriptionState::new(fp.clone(), desc.clone());
                            new_state.error = Some(format!("Failed to update description: {}", e));
                            app.modal = Some(ActiveModal::Description(new_state));
                        }
                    }
                }
                Some(ActiveModal::PasswordChange(state)) => {
                    let fp = state.fp.clone();
                    let new_pw = state.new_password.value.clone();
                    match set_key_password(socket_path, &fp, &new_pw) {
                        Ok(()) => {
                            app.set_status("Password updated".to_string());
                            let _ = load_keys(app, socket_path);
                        }
                        Err(e) => {
                            let mut new_state = PasswordChangeState::new(fp.clone(), state.was_protected);
                            new_state.error = Some(format!("Failed to change password: {}", e));
                            app.modal = Some(ActiveModal::PasswordChange(new_state));
                        }
                    }
                }
                Some(ActiveModal::Confirmation(state)) => {
                    let fp = state.fp.clone();
                    let key_loaded = state.key_loaded;

                    // Update runtime constraints if key is loaded
                    if key_loaded {
                        let (confirm, notify) = state.runtime_selector.value().to_bools();
                        // Preserve existing runtime lifetime
                        let current_lifetime = if let Some(idx) = app.selected_key {
                            if idx < app.keys.len() {
                                app.keys[idx]
                                    .constraints
                                    .get("lifetime_expires_at")
                                    .and_then(|v| v.as_str())
                                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                                    .and_then(|expires_at| {
                                        let secs = (expires_at.with_timezone(&chrono::Utc)
                                            - chrono::Utc::now())
                                        .num_seconds();
                                        if secs > 0 { Some(format!("{}s", secs)) } else { None }
                                    })
                            } else {
                                None
                            }
                        } else {
                            None
                        };

                        if let Err(e) = set_constraints(socket_path, &fp, confirm, notify, current_lifetime.as_deref()) {
                            let mut new_state = ConfirmationState::new(
                                fp.clone(), key_loaded,
                                *state.runtime_selector.value(), *state.default_selector.value(),
                            );
                            new_state.error = Some(format!("Failed to update runtime constraints: {}", e));
                            app.modal = Some(ActiveModal::Confirmation(new_state));
                            return;
                        }
                    }

                    // Update default constraints
                    let (def_confirm, def_notify) = state.default_selector.value().to_bools();
                    // Preserve existing default lifetime
                    let current_default_lifetime = if let Some(idx) = app.selected_key {
                        if idx < app.keys.len() {
                            app.keys[idx]
                                .default_constraints
                                .as_ref()
                                .and_then(|dc| dc.get("default_lifetime_seconds"))
                                .and_then(|v| v.as_u64())
                                .filter(|&s| s > 0)
                                .map(|s| format_lifetime_friendly(s as u32))
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    match set_default_constraints(socket_path, &fp, def_confirm, def_notify, current_default_lifetime.as_deref()) {
                        Ok(()) => {
                            app.set_status("Confirmation settings updated".to_string());
                            let _ = load_keys(app, socket_path);
                        }
                        Err(e) => {
                            let mut new_state = ConfirmationState::new(
                                fp.clone(), key_loaded,
                                *state.runtime_selector.value(), *state.default_selector.value(),
                            );
                            new_state.error = Some(format!("Failed to update default constraints: {}", e));
                            app.modal = Some(ActiveModal::Confirmation(new_state));
                        }
                    }
                }
                Some(ActiveModal::Expiration(state)) => {
                    let fp = state.fp.clone();
                    let lifetime_str = state.default_lifetime.value.trim().to_string();
                    let lifetime = if lifetime_str.is_empty() { None } else { Some(lifetime_str.as_str()) };

                    // Preserve existing confirm/notify settings
                    let (current_confirm, current_notify) = if let Some(idx) = app.selected_key {
                        if idx < app.keys.len() {
                            if let Some(ref defaults) = app.keys[idx].default_constraints {
                                let c = defaults.get("default_confirm").and_then(|v: &serde_json::Value| v.as_bool()).unwrap_or(false);
                                let n = defaults.get("default_notification").and_then(|v| v.as_bool()).unwrap_or(false);
                                (c, n)
                            } else { (false, false) }
                        } else { (false, false) }
                    } else { (false, false) };

                    match set_default_constraints(socket_path, &fp, current_confirm, current_notify, lifetime) {
                        Ok(()) => {
                            app.set_status("Expiration settings updated".to_string());
                            let _ = load_keys(app, socket_path);
                        }
                        Err(e) => {
                            let mut new_state = ExpirationState::new(fp.clone(), state.key_loaded, state.current_timer_display.clone(), lifetime_str.clone());
                            new_state.error = Some(format!("Failed to update expiration settings: {}", e));
                            app.modal = Some(ActiveModal::Expiration(new_state));
                        }
                    }
                }
                Some(ActiveModal::RemovePassword(state)) => {
                    let fp = state.fp.clone();
                    let pw = state.password.value.clone();
                    match remove_key_password(socket_path, &fp, &pw) {
                        Ok(()) => {
                            app.set_status("Password protection removed".to_string());
                            let _ = load_keys(app, socket_path);
                        }
                        Err(e) => {
                            let mut new_state = RemovePasswordState::new(fp.clone());
                            new_state.error = Some(format!("Failed to remove password: {}", e));
                            app.modal = Some(ActiveModal::RemovePassword(new_state));
                        }
                    }
                }
                Some(ActiveModal::KeyPassword(state)) => {
                    let fp = state.fp.clone();

                    // Find default constraints for this key
                    let default_constraints = app
                        .keys
                        .iter()
                        .find(|k| k.fp_sha256_hex == fp)
                        .and_then(|k| k.default_constraints.clone());

                    let confirm = default_constraints.as_ref()
                        .and_then(|d| d.get("confirm")).and_then(|v| v.as_bool()).unwrap_or(false);
                    let notification = default_constraints.as_ref()
                        .and_then(|d| d.get("notification")).and_then(|v| v.as_bool()).unwrap_or(false);
                    let lifetime = default_constraints.as_ref()
                        .and_then(|d| d.get("lifetime")).and_then(|v| v.as_str());

                    let pw_str; // Keep alive
                    let pw_opt_final = if state.password.value.is_empty() {
                        None
                    } else {
                        pw_str = state.password.value.clone();
                        Some(pw_str.as_str())
                    };

                    match load_disk_key_with_constraints(socket_path, &fp, pw_opt_final, confirm, notification, lifetime) {
                        Ok(()) => {
                            app.set_status(format!("Key {} loaded into memory", fp));
                            let _ = load_keys(app, socket_path);
                        }
                        Err(e) => {
                            let mut new_state = KeyPasswordState::new(fp.clone());
                            new_state.error = Some(format!("Failed to load key: {}", e));
                            app.modal = Some(ActiveModal::KeyPassword(new_state));
                        }
                    }
                }
                Some(ActiveModal::SetKeyPassword(state)) => {
                    let fp = state.fp.clone();
                    let pw = state.new_password.value.clone();
                    match set_key_password(socket_path, &fp, &pw) {
                        Ok(()) => {
                            app.set_status("Password protection enabled".to_string());
                            let _ = load_keys(app, socket_path);
                        }
                        Err(e) => {
                            let mut new_state = SetKeyPasswordState::new(fp.clone());
                            new_state.error = Some(format!("Failed to set password: {}", e));
                            app.modal = Some(ActiveModal::SetKeyPassword(new_state));
                        }
                    }
                }
                Some(ActiveModal::CreateKey(state)) => {
                    let key_type = match state.key_type_selector.value() {
                        KeyTypeOption::Ed25519 => "ed25519".to_string(),
                        KeyTypeOption::Rsa => "rsa".to_string(),
                    };
                    let bit_length = if *state.key_type_selector.value() == KeyTypeOption::Rsa {
                        state.bit_length.value.parse::<u32>().ok()
                    } else {
                        None
                    };
                    let description = if state.description.value.trim().is_empty() {
                        None
                    } else {
                        Some(state.description.value.trim().to_string())
                    };

                    match create_key_with_constraints(socket_path, &key_type, bit_length, description, false, false, None) {
                        Ok(()) => {
                            let label = if key_type == "ed25519" { "Ed25519" } else { "RSA" };
                            let bit_info = bit_length.map(|b| format!(" ({})", b)).unwrap_or_default();
                            app.set_status(format!("{}{} key created successfully", label, bit_info));
                            let _ = load_keys(app, socket_path);
                        }
                        Err(e) => {
                            let mut new_state = CreateKeyState::new();
                            new_state.key_type_selector.set_value(state.key_type_selector.value());
                            new_state.error = Some(format!("Failed to create key: {}", e));
                            app.modal = Some(ActiveModal::CreateKey(new_state));
                        }
                    }
                }
                Some(ActiveModal::ImportKey(state)) => {
                    let fp = state.fp.clone();
                    let description = if state.description.value.trim().is_empty() {
                        None
                    } else {
                        Some(state.description.value.trim().to_string())
                    };
                    let pw_owned;
                    let password_opt = if *state.password_toggle.value() {
                        pw_owned = state.password.value.clone();
                        Some(pw_owned.as_str())
                    } else {
                        None
                    };

                    match import_key(socket_path, &fp, description, password_opt) {
                        Ok(()) => {
                            app.set_status("Key imported successfully".to_string());
                            let _ = load_keys(app, socket_path);
                        }
                        Err(e) => {
                            let mut new_state = ImportKeyState::new(fp.clone());
                            new_state.error = Some(format!("Import failed: {}", e));
                            app.modal = Some(ActiveModal::ImportKey(new_state));
                        }
                    }
                }
                Some(ActiveModal::DeleteConfirm(state)) => {
                    let fp = state.fp.clone();
                    match delete_key(socket_path, &fp) {
                        Ok(()) => {
                            app.set_status(format!("Key {} permanently deleted", fp));
                            let _ = load_keys(app, socket_path);
                        }
                        Err(e) => {
                            app.set_status(format!("Failed to delete key: {}", e));
                        }
                    }
                }
                None => {}
            }
        }
    }
}

// ─── Normal-mode key handling ─────────────────────────────────────────────

fn handle_normal_key(app: &mut App, code: KeyCode, socket_path: Option<&String>) {
    // Handle inline UpdateCertificate mode first
    if let AppMode::UpdateCertificate { ref mut buffer, fingerprint: _ } = app.mode {
        match code {
            KeyCode::Enter => {
                let cert_data = buffer.trim().to_string();
                if cert_data.is_empty() {
                    app.set_status("Certificate data cannot be empty".to_string());
                } else {
                    let fp = if let AppMode::UpdateCertificate { ref fingerprint, .. } = app.mode {
                        fingerprint.clone()
                    } else {
                        return;
                    };
                    match update_certificate(socket_path, &fp, &cert_data) {
                        Ok(()) => {
                            app.set_status(format!("Certificate updated for key {}", fp));
                            let _ = load_keys(app, socket_path);
                        }
                        Err(e) => {
                            app.set_status(format!("Failed to update certificate: {}", e));
                        }
                    }
                }
                app.mode = AppMode::Normal;
            }
            KeyCode::Esc => {
                app.mode = AppMode::Normal;
                app.set_status("Certificate update cancelled".to_string());
            }
            KeyCode::Char(c) => {
                buffer.push(c);
            }
            KeyCode::Backspace => {
                buffer.pop();
            }
            _ => {}
        }
        return;
    }

    // Normal mode
    match code {
        KeyCode::Char('q') | KeyCode::Char('Q') => {
            app.should_quit = true;
        }
        KeyCode::Down => {
            if app.active_frame == ActiveFrame::KeysList {
                app.next();
            } else {
                app.selected_info_field = match app.selected_info_field {
                    InfoPanelField::Description => InfoPanelField::Password,
                    InfoPanelField::Password => InfoPanelField::Confirmation,
                    InfoPanelField::Confirmation => InfoPanelField::Expiration,
                    InfoPanelField::Expiration => InfoPanelField::Description,
                };
            }
        }
        KeyCode::Up => {
            if app.active_frame == ActiveFrame::KeysList {
                app.previous();
            } else {
                app.selected_info_field = match app.selected_info_field {
                    InfoPanelField::Description => InfoPanelField::Expiration,
                    InfoPanelField::Password => InfoPanelField::Description,
                    InfoPanelField::Confirmation => InfoPanelField::Password,
                    InfoPanelField::Expiration => InfoPanelField::Confirmation,
                };
            }
        }
        KeyCode::Enter => {
            if app.active_frame == ActiveFrame::InfoPanel {
                if let Some(idx) = app.selected_key {
                    if idx < app.keys.len() {
                        let key = &app.keys[idx];
                        match app.selected_info_field {
                            InfoPanelField::Description => {
                                if !key.has_disk {
                                    app.set_status("External keys cannot be edited".to_string());
                                } else {
                                    let fp = key.fp_sha256_hex.clone();
                                    let desc = key.description.clone();
                                    app.modal = Some(ActiveModal::Description(
                                        DescriptionState::new(fp, desc),
                                    ));
                                }
                            }
                            InfoPanelField::Password => {
                                if !key.has_disk {
                                    app.set_status("Only stored keys can have their password changed".to_string());
                                } else {
                                    let fp = key.fp_sha256_hex.clone();
                                    let was_protected = key.password_protected;
                                    app.modal = Some(ActiveModal::PasswordChange(
                                        PasswordChangeState::new(fp, was_protected),
                                    ));
                                }
                            }
                            InfoPanelField::Confirmation => {
                                open_confirmation_modal(app);
                            }
                            InfoPanelField::Expiration => {
                                open_expiration_modal(app);
                            }
                        }
                    }
                }
            }
        }
        KeyCode::Tab => {
            app.next_frame();
        }
        KeyCode::Char('?') => {
            app.toggle_info_panel_content();
        }
        KeyCode::Char('r') | KeyCode::F(5) => {
            match load_keys(app, socket_path) {
                Ok(()) => app.set_status_with_type("Keys refreshed".to_string(), StatusType::Success),
                Err(e) => app.set_status_with_type(format!("Failed to refresh: {}", e), StatusType::Error),
            }
        }
        KeyCode::Char('d') | KeyCode::Delete => {
            if let Some(idx) = app.selected_key {
                if idx < app.keys.len() {
                    let key = &app.keys[idx];
                    if !key.has_disk {
                        app.set_status("Cannot delete external keys (use ssh-add -d)".to_string());
                    } else {
                        let fp = key.fp_sha256_hex.clone();
                        let desc = key.description.clone();
                        app.modal = Some(ActiveModal::DeleteConfirm(DeleteConfirmState::new(fp, if desc.is_empty() { None } else { Some(desc) })));
                    }
                }
            }
        }
        KeyCode::Char('L') => {
            if let Some(idx) = app.selected_key {
                if idx < app.keys.len() {
                    let has_disk = app.keys[idx].has_disk;
                    let is_loaded = app.keys[idx].loaded;
                    let password_protected = app.keys[idx].password_protected;
                    let fingerprint = app.keys[idx].fp_sha256_hex.clone();
                    let default_constraints = app.keys[idx].default_constraints.clone();

                    if !has_disk {
                        app.set_status("Key is not on disk".to_string());
                    } else if is_loaded {
                        app.set_status("Key is already loaded".to_string());
                    } else if password_protected {
                        app.modal = Some(ActiveModal::KeyPassword(
                            KeyPasswordState::new(fingerprint),
                        ));
                        app.set_status("Enter key password:".to_string());
                    } else {
                        let confirm = default_constraints.as_ref()
                            .and_then(|d| d.get("confirm")).and_then(|v| v.as_bool()).unwrap_or(false);
                        let notification = default_constraints.as_ref()
                            .and_then(|d| d.get("notification")).and_then(|v| v.as_bool()).unwrap_or(false);
                        let lifetime = default_constraints.as_ref()
                            .and_then(|d| d.get("lifetime")).and_then(|v| v.as_str());

                        match load_disk_key_with_constraints(socket_path, &fingerprint, None, confirm, notification, lifetime) {
                            Ok(()) => {
                                app.set_status(format!("Key {} loaded into memory", fingerprint));
                                let _ = load_keys(app, socket_path);
                            }
                            Err(e) => {
                                app.set_status(format!("Failed to load key: {}", e));
                            }
                        }
                    }
                }
            }
        }
        KeyCode::Char('U') => {
            if let Some(idx) = app.selected_key {
                if idx < app.keys.len() {
                    let key = &app.keys[idx];
                    if key.loaded {
                        let fp = key.fp_sha256_hex.clone();
                        match unload_key(socket_path, &fp) {
                            Ok(()) => {
                                app.set_status(format!("Key {} unloaded from memory", fp));
                                let _ = load_keys(app, socket_path);
                            }
                            Err(e) => {
                                app.set_status(format!("Failed to unload key: {}", e));
                            }
                        }
                    } else {
                        app.set_status("Key is not loaded in memory".to_string());
                    }
                }
            }
        }
        KeyCode::Char('i') => {
            if let Some(idx) = app.selected_key {
                if idx < app.keys.len() {
                    let key = &app.keys[idx];
                    if key.has_disk {
                        app.set_status("Key is already stored on disk".to_string());
                    } else if !key.loaded {
                        app.set_status("Key must be loaded in memory to import".to_string());
                    } else {
                        let fp = key.fp_sha256_hex.clone();
                        app.modal = Some(ActiveModal::ImportKey(ImportKeyState::new(fp)));
                    }
                }
            } else {
                app.set_status("Select an external key to import".to_string());
            }
        }
        KeyCode::Char('n') => {
            app.modal = Some(ActiveModal::CreateKey(CreateKeyState::new()));
        }
        KeyCode::Char('P') => {
            if let Some(idx) = app.selected_key {
                if idx < app.keys.len() {
                    let key = &app.keys[idx];
                    if !key.has_disk {
                        app.set_status("Only stored keys can be password-protected".to_string());
                    } else if key.password_protected {
                        app.set_status("Key is already password-protected".to_string());
                    } else {
                        let fp = key.fp_sha256_hex.clone();
                        app.modal = Some(ActiveModal::SetKeyPassword(SetKeyPasswordState::new(fp)));
                    }
                }
            }
        }
        KeyCode::Char('R') => {
            if let Some(idx) = app.selected_key {
                if idx < app.keys.len() {
                    let key = &app.keys[idx];
                    if !key.has_disk {
                        app.set_status("Only stored keys can have password protection removed".to_string());
                    } else if !key.password_protected {
                        app.set_status("Key is not password-protected".to_string());
                    } else {
                        let fp = key.fp_sha256_hex.clone();
                        app.modal = Some(ActiveModal::RemovePassword(RemovePasswordState::new(fp)));
                    }
                }
            }
        }
        KeyCode::Char('l') => {
            match lock_agent(socket_path) {
                Ok(()) => {
                    app.keys.clear();
                    app.selected_key = None;
                    app.list_state.select(None);
                    let mut auth = AuthenticationState::new();
                    auth.error = None;
                    app.modal = Some(ActiveModal::Authentication(auth));
                    app.set_status("Agent locked. Please authenticate to continue.".to_string());
                }
                Err(e) => {
                    app.set_status(format!("Failed to lock agent: {}", e));
                }
            }
        }
        KeyCode::Char('e') => {
            if let Some(idx) = app.selected_key {
                if idx < app.keys.len() {
                    let key = &app.keys[idx];
                    if !key.has_disk {
                        app.set_status("External keys cannot be edited (use original ssh-add)".to_string());
                    } else {
                        let fp = key.fp_sha256_hex.clone();
                        let desc = key.description.clone();
                        app.modal = Some(ActiveModal::Description(DescriptionState::new(fp, desc)));
                    }
                }
            }
        }
        KeyCode::Char('C') => {
            if let Some(idx) = app.selected_key {
                if idx < app.keys.len() {
                    let key = &app.keys[idx];
                    if !key.has_disk {
                        app.set_status("Only stored keys can have certificates updated".to_string());
                    } else {
                        let fp = key.fp_sha256_hex.clone();
                        app.mode = AppMode::UpdateCertificate {
                            fingerprint: fp,
                            buffer: String::new(),
                        };
                        app.set_status("Paste OpenSSH certificate (base64), then press Enter:".to_string());
                    }
                }
            }
        }
        _ => {}
    }
}

fn open_confirmation_modal(app: &mut App) {
    if let Some(idx) = app.selected_key {
        if idx < app.keys.len() {
            let key = &app.keys[idx];
            let fp = key.fp_sha256_hex.clone();
            let key_loaded = key.loaded;

            let runtime_constraint = if key_loaded {
                let confirm = key.constraints.get("confirm").and_then(|v| v.as_bool()).unwrap_or(false);
                let notify = key.constraints.get("notification").and_then(|v| v.as_bool()).unwrap_or(false);
                ConstraintOption::from((confirm, notify))
            } else {
                ConstraintOption::None
            };

            let default_constraint = if let Some(ref defaults) = key.default_constraints {
                let confirm = defaults.get("default_confirm").and_then(|v| v.as_bool()).unwrap_or(false);
                let notify = defaults.get("default_notification").and_then(|v| v.as_bool()).unwrap_or(false);
                ConstraintOption::from((confirm, notify))
            } else {
                ConstraintOption::None
            };

            app.modal = Some(ActiveModal::Confirmation(ConfirmationState::new(
                fp, key_loaded, runtime_constraint, default_constraint,
            )));
        }
    }
}

fn open_expiration_modal(app: &mut App) {
    if let Some(idx) = app.selected_key {
        if idx < app.keys.len() {
            let key = &app.keys[idx];
            let fp = key.fp_sha256_hex.clone();
            let key_loaded = key.loaded;

            let current_timer_display = calculate_remaining_lifetime(&key.constraints);

            let default_lifetime_str = key
                .default_constraints
                .as_ref()
                .and_then(|c| c.get("lifetime"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            app.modal = Some(ActiveModal::Expiration(ExpirationState::new(
                fp,
                key_loaded,
                current_timer_display,
                default_lifetime_str,
            )));
        }
    }
}

// ─── UI rendering ─────────────────────────────────────────────────────────

fn ui(f: &mut Frame, app: &App) {
    let size = f.area();

    // Main 3-panel layout
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(10),   // Main content
            Constraint::Length(3), // Status bar
        ])
        .split(size);

    let content_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(60),
            Constraint::Percentage(40),
        ])
        .split(main_chunks[0]);

    render_keys_list(f, app, content_chunks[0]);
    render_info_panel(f, app, content_chunks[1]);
    render_status_bar(f, app, main_chunks[1]);

    // Overlay active modal
    if let Some(ref modal) = app.modal {
        modals::render_modal(modal, f, size);
    }
}

// ─── Render helpers ────────────────────────────────────────────────────────

fn render_keys_list(f: &mut Frame, app: &App, area: Rect) {
    let keys: Vec<ListItem> = app
        .keys
        .iter()
        .map(|key| {
            let mut spans = Vec::new();

            let (loaded_icon, loaded_color) = get_loaded_icon(&key.source, key.loaded);
            spans.push(Span::styled(loaded_icon, Style::default().fg(loaded_color)));
            spans.push(Span::raw(" "));

            if let Some((protected_icon, protected_color)) = get_protected_icon(key.password_protected) {
                spans.push(Span::styled(protected_icon, Style::default().fg(protected_color)));
            } else {
                spans.push(Span::raw("  "));
            }
            spans.push(Span::raw(" "));

            let (confirm, notification) = get_constraint_state(key);
            let (conf_icon, conf_color) = get_confirmation_notification_icon(confirm, notification);
            spans.push(Span::styled(conf_icon, Style::default().fg(conf_color)));
            spans.push(Span::raw(" "));

            if let Some((ttl_display, ttl_color)) = get_ttl_display(key) {
                spans.push(Span::styled(ttl_display, Style::default().fg(ttl_color)));
                spans.push(Span::raw(" "));
            } else {
                spans.push(Span::raw("   "));
            }

            let short_fingerprint = format_short_fingerprint(&key.fp_sha256_hex);
            spans.push(Span::styled(
                short_fingerprint,
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
            ));

            if !key.description.is_empty() {
                spans.push(Span::raw(" "));
                spans.push(Span::styled(
                    key.description.clone(),
                    Style::default().fg(Color::Gray).add_modifier(Modifier::ITALIC),
                ));
            }

            ListItem::new(Line::from(spans))
        })
        .collect();

    let title = if app.active_frame == ActiveFrame::KeysList {
        "SSH Keys [FOCUSED]"
    } else {
        "SSH Keys"
    };

    let keys_list = List::new(keys)
        .block(Block::default().title(title).borders(Borders::ALL))
        .highlight_style(
            Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD),
        );

    if app.active_frame == ActiveFrame::KeysList {
        f.render_stateful_widget(keys_list, area, &mut app.list_state.clone());
    } else {
        f.render_widget(keys_list, area);
    }
}

fn render_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let status_text = app.status_message.as_deref().unwrap_or("Ready");
    let (status_color, border_color) = match app.status_type {
        StatusType::Success => (Color::Green, Color::Green),
        StatusType::Error => (Color::Red, Color::Red),
        StatusType::Info => (Color::White, Color::White),
    };
    f.render_widget(
        Paragraph::new(status_text)
            .block(
                Block::default()
                    .title("Status")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(border_color)),
            )
            .style(Style::default().fg(status_color)),
        area,
    );
}

fn render_info_panel(f: &mut Frame, app: &App, area: Rect) {
    match app.info_panel_content {
        InfoPanelContent::KeyDetails => render_key_details_panel(f, app, area),
        InfoPanelContent::Help => render_help_panel(f, app, area),
    }
}

fn render_key_details_panel(f: &mut Frame, app: &App, area: Rect) {
    let title = if app.active_frame == ActiveFrame::InfoPanel {
        "Key Details [FOCUSED]"
    } else {
        "Key Details"
    };

    if let Some(selected_idx) = app.selected_key {
        if let Some(key) = app.keys.get(selected_idx) {
            let mut details = Vec::new();

            details.push(Line::from(vec![Span::styled(
                "Key Details",
                Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            )]));
            details.push(Line::from(""));

            // Description field
            let description_style = if app.active_frame == ActiveFrame::InfoPanel
                && app.selected_info_field == InfoPanelField::Description
            {
                Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let description_text = if key.description.is_empty() {
                "[No description]"
            } else {
                &key.description
            };
            details.push(Line::from(vec![
                Span::styled("Description:     ", Style::default().add_modifier(Modifier::BOLD)),
                Span::styled(description_text, description_style),
            ]));

            // Password field
            let password_style = if app.active_frame == ActiveFrame::InfoPanel
                && app.selected_info_field == InfoPanelField::Password
            {
                Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let password_status = if key.password_protected { "Protected" } else { "Not protected" };
            details.push(Line::from(vec![
                Span::styled("Password:        ", Style::default().add_modifier(Modifier::BOLD)),
                Span::styled(
                    password_status,
                    password_style.fg(if key.password_protected { Color::Yellow } else { Color::Green }),
                ),
            ]));

            // Created / Updated
            if let Some(created) = &key.created {
                details.push(Line::from(vec![
                    Span::styled("Created:         ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(format_datetime(created)),
                ]));
            }
            if let Some(updated) = &key.updated {
                details.push(Line::from(vec![
                    Span::styled("Updated:         ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(format_datetime(updated)),
                ]));
            }

            // Confirmation field
            let confirmation_style = if app.active_frame == ActiveFrame::InfoPanel
                && app.selected_info_field == InfoPanelField::Confirmation
            {
                Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let current_confirm = key.constraints.get("confirm").and_then(|v| v.as_bool()).unwrap_or(false);
            let current_notification = key.constraints.get("notification").and_then(|v| v.as_bool()).unwrap_or(false);
            let confirmation_text = match (current_confirm, current_notification) {
                (true, _) => "Confirm",
                (false, true) => "Notify",
                _ => "None",
            };
            let default_text = if let Some(default_constraints) = &key.default_constraints {
                let dc = default_constraints.get("default_confirm").and_then(|v| v.as_bool()).unwrap_or(false);
                let dn = default_constraints.get("default_notification").and_then(|v| v.as_bool()).unwrap_or(false);
                match (dc, dn) {
                    (true, _) => " (default: Confirm)",
                    (false, true) => " (default: Notify)",
                    (false, false) => " (default: None)",
                }
            } else {
                ""
            };
            details.push(Line::from(vec![
                Span::styled("Confirmation:    ", Style::default().add_modifier(Modifier::BOLD)),
                Span::styled(confirmation_text, confirmation_style),
                Span::styled(default_text, Style::default().fg(Color::DarkGray)),
            ]));

            // Expiration field
            let expiration_style = if app.active_frame == ActiveFrame::InfoPanel
                && app.selected_info_field == InfoPanelField::Expiration
            {
                Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let lifetime_text = if let Some(remaining) = calculate_remaining_lifetime(&key.constraints) {
                if remaining == "EXPIRED" { remaining } else { format!("{} remaining", remaining) }
            } else {
                "None".to_string()
            };
            let mut lifetime_spans = vec![
                Span::styled("Expiration:      ", Style::default().add_modifier(Modifier::BOLD)),
                Span::styled(&lifetime_text, expiration_style),
            ];
            if let Some(default_seconds) = key
                .default_constraints
                .as_ref()
                .and_then(|dc| dc.get("default_lifetime_seconds"))
                .and_then(|v| v.as_u64())
            {
                lifetime_spans.push(Span::styled(
                    format!(" (default: {})", format_lifetime_friendly(default_seconds as u32)),
                    Style::default().fg(Color::DarkGray),
                ));
            }
            details.push(Line::from(lifetime_spans));
            details.push(Line::from(""));

            // Technical Details
            details.push(Line::from(vec![Span::styled(
                "Technical Details",
                Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            )]));
            details.push(Line::from(""));
            details.push(Line::from(vec![
                Span::styled("Fingerprint: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(&key.fp_sha256_hex),
            ]));
            details.push(Line::from(vec![
                Span::styled("Type: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(&key.key_type),
            ]));
            details.push(Line::from(vec![
                Span::styled("Format: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(&key.format),
            ]));
            details.push(Line::from(vec![
                Span::styled("Source: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::styled(
                    &key.source,
                    Style::default().fg(match key.source.as_str() {
                        "disk" => Color::Green,
                        "external" => Color::Yellow,
                        _ => Color::White,
                    }),
                ),
            ]));
            details.push(Line::from(vec![
                Span::styled("Status: ", Style::default().add_modifier(Modifier::BOLD)),
                if key.loaded {
                    Span::styled("Loaded", Style::default().fg(Color::Green))
                } else {
                    Span::styled("Not Loaded", Style::default().fg(Color::Red))
                },
            ]));
            if key.has_cert {
                details.push(Line::from(vec![
                    Span::styled("Certificate: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled("Present", Style::default().fg(Color::Green)),
                ]));
            }

            if app.active_frame == ActiveFrame::InfoPanel {
                details.push(Line::from(""));
                details.push(Line::from(vec![
                    Span::styled("Navigate: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled("Up/Down arrows", Style::default().fg(Color::Cyan)),
                ]));
            }

            f.render_widget(
                Paragraph::new(details)
                    .block(Block::default().title(title).borders(Borders::ALL))
                    .wrap(Wrap { trim: true }),
                area,
            );
            return;
        }
    }

    f.render_widget(
        Paragraph::new("No key selected")
            .block(Block::default().title(title).borders(Borders::ALL)),
        area,
    );
}

fn render_help_panel(f: &mut Frame, app: &App, area: Rect) {
    let title = if app.active_frame == ActiveFrame::InfoPanel {
        "Help [FOCUSED]"
    } else {
        "Help"
    };

    let help_text = vec![
        Line::from(vec![Span::styled("Navigation:", Style::default().add_modifier(Modifier::BOLD))]),
        Line::from("↓/↑    - Move down/up"),
        Line::from("Tab    - Switch frames"),
        Line::from("?      - Toggle help/details"),
        Line::from(""),
        Line::from(vec![Span::styled("Key Management:", Style::default().add_modifier(Modifier::BOLD))]),
        Line::from("L - Load disk key"),
        Line::from("U - Unload key from memory"),
        Line::from("i - Import external key"),
        Line::from("n - Create new key"),
        Line::from(""),
        Line::from(vec![Span::styled("Key Operations:", Style::default().add_modifier(Modifier::BOLD))]),
        Line::from("e - Edit description"),
        Line::from("C - Update certificate"),
        Line::from("P - Set password protection"),
        Line::from("R - Remove password protection"),
        Line::from("d - Delete key (PERMANENT)"),
        Line::from(""),
        Line::from(vec![Span::styled("Agent Control:", Style::default().add_modifier(Modifier::BOLD))]),
        Line::from("r/F5 - Refresh key list"),
        Line::from("l    - Lock agent"),
        Line::from("q    - Quit"),
    ];

    f.render_widget(
        Paragraph::new(help_text)
            .block(Block::default().title(title).borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}

// ─── Utility functions ─────────────────────────────────────────────────────

fn parse_lifetime(input: &str) -> Result<u32, String> {
    if input.is_empty() {
        return Err("Lifetime cannot be empty".to_string());
    }
    let input = input.trim().to_lowercase();
    if let Ok(secs) = input.parse::<u32>() {
        validate_lifetime_seconds(secs)?;
        return Ok(secs);
    }
    let (num_str, unit) = if input.ends_with('s') {
        (input.trim_end_matches('s'), "s")
    } else if input.ends_with('m') {
        (input.trim_end_matches('m'), "m")
    } else if input.ends_with('h') {
        (input.trim_end_matches('h'), "h")
    } else if input.ends_with('d') {
        (input.trim_end_matches('d'), "d")
    } else {
        return Err(format!("Invalid format '{}'. Use format like '2h', '30m', '1d'", input));
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
    const MAX_LIFETIME: u32 = 30 * 24 * 60 * 60;
    if seconds > MAX_LIFETIME {
        return Err(format!("Lifetime too long. Maximum is 30 days ({} seconds)", MAX_LIFETIME));
    }
    Ok(())
}

#[allow(dead_code)]
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

fn calculate_remaining_lifetime(constraints: &serde_json::Value) -> Option<String> {
    if let Some(lifetime_expires_at) = constraints.get("lifetime_expires_at") {
        if let Some(expires_str) = lifetime_expires_at.as_str() {
            if let Ok(expires_at) = chrono::DateTime::parse_from_rfc3339(expires_str) {
                let now = chrono::Utc::now();
                let expires_utc = expires_at.with_timezone(&chrono::Utc);
                if expires_utc > now {
                    let total_seconds = (expires_utc - now).num_seconds();
                    if total_seconds <= 0 {
                        return Some("EXPIRED".to_string());
                    }
                    if total_seconds >= 86400 {
                        let days = total_seconds / 86400;
                        let hours = (total_seconds % 86400) / 3600;
                        return Some(if hours > 0 { format!("{}d{}h", days, hours) } else { format!("{}d", days) });
                    } else if total_seconds >= 3600 {
                        let hours = total_seconds / 3600;
                        let minutes = (total_seconds % 3600) / 60;
                        return Some(if minutes > 0 { format!("{}h{}m", hours, minutes) } else { format!("{}h", hours) });
                    } else if total_seconds >= 60 {
                        let minutes = total_seconds / 60;
                        let seconds = total_seconds % 60;
                        return Some(if seconds > 0 { format!("{}m{}s", minutes, seconds) } else { format!("{}m", minutes) });
                    } else {
                        return Some(format!("{}s", total_seconds));
                    }
                } else {
                    return Some("EXPIRED".to_string());
                }
            }
        }
    }
    None
}

fn get_loaded_icon(source: &str, loaded: bool) -> (String, Color) {
    match source {
        "external" => ("↗".to_string(), Color::Blue),
        _ => {
            if loaded { ("●".to_string(), Color::Green) } else { ("○".to_string(), Color::Gray) }
        }
    }
}

fn get_protected_icon(password_protected: bool) -> Option<(&'static str, Color)> {
    if password_protected {
        Some(("🔐", Color::Green))
    } else {
        None
    }
}

fn get_confirmation_notification_icon(confirm: bool, notification: bool) -> (String, Color) {
    if confirm {
        ("⚠".to_string(), Color::Yellow)
    } else if notification {
        ("✉".to_string(), Color::Cyan)
    } else {
        (" ".to_string(), Color::White)
    }
}

fn get_constraint_state(key: &KeyInfo) -> (bool, bool) {
    if !key.constraints.is_null() && key.constraints.as_object().is_some_and(|o| !o.is_empty()) {
        let confirm = key.constraints.get("confirm").and_then(|v| v.as_bool()).unwrap_or(false);
        let notification = key.constraints.get("notification").and_then(|v| v.as_bool()).unwrap_or(false);
        return (confirm, notification);
    }
    if key.has_disk {
        if let Some(default_constraints) = &key.default_constraints {
            let dc = default_constraints.get("default_confirm").and_then(|v| v.as_bool()).unwrap_or(false);
            let dn = default_constraints.get("default_notification").and_then(|v| v.as_bool()).unwrap_or(false);
            return (dc, dn);
        }
    }
    (false, false)
}

fn get_ttl_display(key: &KeyInfo) -> Option<(&'static str, Color)> {
    if !key.constraints.is_null() && key.constraints.as_object().is_some_and(|o| !o.is_empty()) {
        if let Some(lifetime_remaining) = calculate_remaining_lifetime(&key.constraints) {
            let color = if lifetime_remaining == "EXPIRED" {
                Color::Red
            } else if lifetime_remaining.contains('s') && !lifetime_remaining.contains('m')
                && !lifetime_remaining.contains('h') && !lifetime_remaining.contains('d')
            {
                Color::Yellow
            } else {
                Color::Green
            };
            return Some(("⏳", color));
        }
    }
    if key.has_disk {
        if let Some(default_constraints) = &key.default_constraints {
            if default_constraints
                .get("default_lifetime_seconds")
                .and_then(|v| v.as_u64())
                .is_some()
            {
                let color = if key.loaded { Color::Green } else { Color::Gray };
                return Some(("⏳", color));
            }
        }
    }
    None
}

fn format_short_fingerprint(fingerprint: &str) -> String {
    let clean = fingerprint.strip_prefix("SHA256:").unwrap_or(fingerprint);
    let len = clean.len();
    if len <= 20 {
        clean.to_string()
    } else {
        format!("{}...{}", &clean[..8], &clean[len - 8..])
    }
}

fn format_datetime(datetime_str: &str) -> String {
    if datetime_str.len() <= 16 {
        return datetime_str.to_string();
    }
    if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(datetime_str) {
        parsed.format("%Y-%m-%d %H:%M").to_string()
    } else if datetime_str.contains('T') {
        let parts: Vec<&str> = datetime_str.split('T').collect();
        if parts.len() == 2 {
            let date = parts[0];
            let time_part = parts[1].split('.').next().unwrap_or(parts[1]);
            let time = if time_part.len() >= 5 { &time_part[..5] } else { time_part };
            format!("{} {}", date, time)
        } else {
            datetime_str.to_string()
        }
    } else {
        datetime_str.to_string()
    }
}

// ─── Socket/API functions ──────────────────────────────────────────────────

fn load_keys(
    app: &mut App,
    socket_path: Option<&String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = socket_path
        .cloned()
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
        .ok_or("No socket path available")?;

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(&socket)?;

    let request = rssh_proto::cbor::ExtensionRequest {
        extension: "manage.list".to_string(),
        data: vec![],
    };

    let mut cbor_data = Vec::new();
    ciborium::into_writer(&request, &mut cbor_data)?;

    let mut message = Vec::new();
    message.push(rssh_proto::messages::SSH_AGENTC_EXTENSION);
    let ext_namespace = b"rssh-agent@local";
    message.extend_from_slice(&(ext_namespace.len() as u32).to_be_bytes());
    message.extend_from_slice(ext_namespace);
    message.extend_from_slice(&cbor_data);

    let mut full_message = Vec::new();
    full_message.extend_from_slice(&(message.len() as u32).to_be_bytes());
    full_message.extend_from_slice(&message);

    stream.write_all(&full_message)?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut response = vec![0u8; len];
    stream.read_exact(&mut response)?;

    if response[0] == rssh_proto::messages::SSH_AGENT_SUCCESS {
        let mut offset = 1;
        if response.len() < offset + 4 {
            return Err("Response too short".into());
        }
        let data_len = u32::from_be_bytes([
            response[offset], response[offset + 1],
            response[offset + 2], response[offset + 3],
        ]) as usize;
        offset += 4;
        if response.len() < offset + data_len {
            return Err("Response data truncated".into());
        }
        let cbor_data = &response[offset..offset + data_len];
        let cbor_response: rssh_proto::cbor::ExtensionResponse = ciborium::from_reader(cbor_data)?;

        if cbor_response.success {
            use rssh_proto::cbor::ManageListResponse;
            let list_response: ManageListResponse = ciborium::from_reader(&cbor_response.data[..])?;
            if !list_response.ok {
                return Err("Server returned error in manage.list response".into());
            }

            let selected_fingerprint = app
                .selected_key
                .and_then(|idx| app.keys.get(idx))
                .map(|key| key.fp_sha256_hex.clone());

            let mut keys: Vec<KeyInfo> = list_response.keys;
            keys.sort_by(|a, b| a.description.cmp(&b.description));
            app.keys = keys;

            if !app.keys.is_empty() {
                let selected_idx = if let Some(fp) = selected_fingerprint {
                    app.keys.iter().position(|k| k.fp_sha256_hex == fp).unwrap_or(0)
                } else {
                    0
                };
                app.list_state.select(Some(selected_idx));
                app.selected_key = Some(selected_idx);
            } else {
                app.list_state.select(None);
                app.selected_key = None;
            }
        } else {
            return Err(cbor_error_msg(&cbor_response.data).into());
        }
    } else if response[0] == rssh_proto::messages::SSH_AGENT_FAILURE {
        return Err("Agent is locked or operation failed".into());
    } else if response[0] == rssh_proto::messages::SSH_AGENT_EXTENSION_FAILURE {
        return Err("Extension operation failed".into());
    } else {
        return Err(format!("Unexpected response type: {}", response[0]).into());
    }

    Ok(())
}

fn lock_agent(socket_path: Option<&String>) -> Result<(), Box<dyn std::error::Error>> {
    let socket = socket_path.cloned()
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
        .ok_or("No socket path available")?;

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(&socket)?;
    let mut message = Vec::new();
    message.push(rssh_proto::messages::SSH_AGENTC_LOCK);
    message.extend_from_slice(&[0, 0, 0, 0]);

    let mut full_message = Vec::new();
    full_message.extend_from_slice(&(message.len() as u32).to_be_bytes());
    full_message.extend_from_slice(&message);
    stream.write_all(&full_message)?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut response = vec![0u8; len];
    stream.read_exact(&mut response)?;

    if response[0] != rssh_proto::messages::SSH_AGENT_SUCCESS {
        return Err("Failed to lock agent".into());
    }
    Ok(())
}

fn unlock_agent(
    socket_path: Option<&String>,
    password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = socket_path.cloned()
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
        .ok_or("No socket path available")?;

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(&socket)?;
    let password_bytes = password.as_bytes();
    let mut message = Vec::new();
    message.extend_from_slice(&((password_bytes.len() + 5) as u32).to_be_bytes());
    message.push(rssh_proto::messages::SSH_AGENTC_UNLOCK);
    message.extend_from_slice(&(password_bytes.len() as u32).to_be_bytes());
    message.extend_from_slice(password_bytes);
    stream.write_all(&message)?;

    let mut response = [0u8; 5];
    stream.read_exact(&mut response)?;

    if response[4] != rssh_proto::messages::SSH_AGENT_SUCCESS {
        return Err("Failed to unlock agent".into());
    }
    Ok(())
}

fn delete_key(
    socket_path: Option<&String>,
    fingerprint: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = socket_path.cloned()
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
        .ok_or("No socket path available")?;

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(&socket)?;

    use rssh_proto::cbor::ExtensionRequest;
    let delete_data = {
        #[derive(serde::Serialize)]
        struct DeleteRequest { fp_sha256_hex: String }
        let mut cbor = Vec::new();
        ciborium::into_writer(&DeleteRequest { fp_sha256_hex: fingerprint.to_string() }, &mut cbor)?;
        cbor
    };

    let request = ExtensionRequest { extension: "manage.delete".to_string(), data: delete_data };
    let mut cbor_data = Vec::new();
    ciborium::into_writer(&request, &mut cbor_data)?;

    let mut message = Vec::new();
    message.push(rssh_proto::messages::SSH_AGENTC_EXTENSION);
    let ext_namespace = b"rssh-agent@local";
    message.extend_from_slice(&(ext_namespace.len() as u32).to_be_bytes());
    message.extend_from_slice(ext_namespace);
    message.extend_from_slice(&cbor_data);

    let mut full_message = Vec::new();
    full_message.extend_from_slice(&(message.len() as u32).to_be_bytes());
    full_message.extend_from_slice(&message);
    stream.write_all(&full_message)?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut response = vec![0u8; len];
    stream.read_exact(&mut response)?;

    if response[0] == rssh_proto::messages::SSH_AGENT_SUCCESS {
        let mut offset = 1;
        if response.len() < offset + 4 { return Err("Response too short".into()); }
        let data_len = u32::from_be_bytes([
            response[offset], response[offset + 1],
            response[offset + 2], response[offset + 3],
        ]) as usize;
        offset += 4;
        if response.len() < offset + data_len { return Err("Response data truncated".into()); }
        let cbor_data = &response[offset..offset + data_len];
        let cbor_response: rssh_proto::cbor::ExtensionResponse = ciborium::from_reader(cbor_data)?;
        if !cbor_response.success {
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

fn unload_key(
    socket_path: Option<&String>,
    fingerprint: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = socket_path.cloned()
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
        .ok_or("No socket path available")?;

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(&socket)?;

    use rssh_proto::cbor::ExtensionRequest;
    let unload_data = {
        #[derive(serde::Serialize)]
        struct UnloadRequest { fp_sha256_hex: String }
        let mut cbor = Vec::new();
        ciborium::into_writer(&UnloadRequest { fp_sha256_hex: fingerprint.to_string() }, &mut cbor)?;
        cbor
    };
    let request = ExtensionRequest { extension: "manage.unload".to_string(), data: unload_data };
    let mut cbor_data = Vec::new();
    ciborium::into_writer(&request, &mut cbor_data)?;

    let mut message = Vec::new();
    message.push(rssh_proto::messages::SSH_AGENTC_EXTENSION);
    let ext_namespace = b"rssh-agent@local";
    message.extend_from_slice(&(ext_namespace.len() as u32).to_be_bytes());
    message.extend_from_slice(ext_namespace);
    message.extend_from_slice(&cbor_data);

    let mut full_message = Vec::new();
    full_message.extend_from_slice(&(message.len() as u32).to_be_bytes());
    full_message.extend_from_slice(&message);
    stream.write_all(&full_message)?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut response = vec![0u8; len];
    stream.read_exact(&mut response)?;

    if response[0] == rssh_proto::messages::SSH_AGENT_SUCCESS { Ok(()) } else { Err("Failed to unload key".into()) }
}

fn set_key_description(
    socket_path: Option<&String>,
    fingerprint: &str,
    description: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = socket_path.cloned()
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
        .ok_or("No socket path available")?;

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(&socket)?;

    use rssh_proto::cbor::ExtensionRequest;
    let set_desc_data = {
        #[derive(serde::Serialize)]
        struct SetDescRequest { fp_sha256_hex: String, description: String }
        let mut cbor = Vec::new();
        ciborium::into_writer(&SetDescRequest {
            fp_sha256_hex: fingerprint.to_string(),
            description: description.to_string(),
        }, &mut cbor)?;
        cbor
    };
    let request = ExtensionRequest { extension: "manage.set_desc".to_string(), data: set_desc_data };
    let mut cbor_data = Vec::new();
    ciborium::into_writer(&request, &mut cbor_data)?;

    let mut message = Vec::new();
    message.push(rssh_proto::messages::SSH_AGENTC_EXTENSION);
    let ext_namespace = b"rssh-agent@local";
    message.extend_from_slice(&(ext_namespace.len() as u32).to_be_bytes());
    message.extend_from_slice(ext_namespace);
    message.extend_from_slice(&cbor_data);

    let mut full_message = Vec::new();
    full_message.extend_from_slice(&(message.len() as u32).to_be_bytes());
    full_message.extend_from_slice(&message);
    stream.write_all(&full_message)?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut response = vec![0u8; len];
    stream.read_exact(&mut response)?;

    if response[0] == rssh_proto::messages::SSH_AGENT_SUCCESS { Ok(()) } else { Err("Failed to set description".into()) }
}

fn update_certificate(
    socket_path: Option<&String>,
    fingerprint: &str,
    certificate: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = socket_path.cloned()
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
        .ok_or("No socket path available")?;

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(&socket)?;

    use rssh_proto::cbor::ExtensionRequest;
    let update_cert_data = {
        #[derive(serde::Serialize)]
        struct UpdateCertRequest { fp_sha256_hex: String, cert_openssh_b64: String }
        let mut cbor = Vec::new();
        ciborium::into_writer(&UpdateCertRequest {
            fp_sha256_hex: fingerprint.to_string(),
            cert_openssh_b64: certificate.to_string(),
        }, &mut cbor)?;
        cbor
    };
    let request = ExtensionRequest { extension: "manage.update_cert".to_string(), data: update_cert_data };
    let mut cbor_data = Vec::new();
    ciborium::into_writer(&request, &mut cbor_data)?;

    let mut message = Vec::new();
    message.push(rssh_proto::messages::SSH_AGENTC_EXTENSION);
    let ext_namespace = b"rssh-agent@local";
    message.extend_from_slice(&(ext_namespace.len() as u32).to_be_bytes());
    message.extend_from_slice(ext_namespace);
    message.extend_from_slice(&cbor_data);

    let mut full_message = Vec::new();
    full_message.extend_from_slice(&(message.len() as u32).to_be_bytes());
    full_message.extend_from_slice(&message);
    stream.write_all(&full_message)?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut response = vec![0u8; len];
    stream.read_exact(&mut response)?;

    if response[0] == rssh_proto::messages::SSH_AGENT_SUCCESS { Ok(()) } else { Err("Failed to update certificate".into()) }
}

fn load_disk_key_with_constraints(
    socket_path: Option<&String>,
    fingerprint: &str,
    key_password: Option<&str>,
    confirm: bool,
    notification: bool,
    lifetime: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = socket_path.cloned()
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
        .ok_or("No socket path available")?;

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(&socket)?;

    use rssh_proto::cbor::ExtensionRequest;
    let load_data = {
        #[derive(serde::Serialize)]
        struct LoadRequestWithConstraints {
            fp_sha256_hex: String,
            key_pass_b64: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            confirm: Option<bool>,
            #[serde(skip_serializing_if = "Option::is_none")]
            notification: Option<bool>,
            #[serde(skip_serializing_if = "Option::is_none")]
            lifetime_seconds: Option<u32>,
        }
        let key_pass_b64 = key_password.map(|pass| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(pass.as_bytes())
        });
        let lifetime_seconds = if let Some(s) = lifetime { Some(parse_lifetime(s)?) } else { None };
        let req = LoadRequestWithConstraints {
            fp_sha256_hex: fingerprint.to_string(),
            key_pass_b64,
            confirm: if confirm { Some(true) } else { None },
            notification: if notification { Some(true) } else { None },
            lifetime_seconds,
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&req, &mut cbor)?;
        cbor
    };

    let request = ExtensionRequest { extension: "manage.load".to_string(), data: load_data };
    let mut cbor_data = Vec::new();
    ciborium::into_writer(&request, &mut cbor_data)?;

    let mut message = Vec::new();
    message.push(rssh_proto::messages::SSH_AGENTC_EXTENSION);
    let ext_namespace = b"rssh-agent@local";
    message.extend_from_slice(&(ext_namespace.len() as u32).to_be_bytes());
    message.extend_from_slice(ext_namespace);
    message.extend_from_slice(&cbor_data);

    let mut full_message = Vec::new();
    full_message.extend_from_slice(&(message.len() as u32).to_be_bytes());
    full_message.extend_from_slice(&message);
    stream.write_all(&full_message)?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut response = vec![0u8; len];
    stream.read_exact(&mut response)?;

    if response[0] == rssh_proto::messages::SSH_AGENT_SUCCESS {
        let mut offset = 1;
        if response.len() < offset + 4 { return Err("Response too short".into()); }
        let data_len = u32::from_be_bytes([
            response[offset], response[offset + 1],
            response[offset + 2], response[offset + 3],
        ]) as usize;
        offset += 4;
        if response.len() < offset + data_len { return Err("Response data truncated".into()); }
        let cbor_data = &response[offset..offset + data_len];
        let cbor_response: rssh_proto::cbor::ExtensionResponse = ciborium::from_reader(cbor_data)?;
        if !cbor_response.success { return Err(cbor_error_msg(&cbor_response.data).into()); }
        Ok(())
    } else {
        Err("Failed to load key from disk".into())
    }
}

fn create_key_with_constraints(
    socket_path: Option<&String>,
    key_type: &str,
    bit_length: Option<u32>,
    description: Option<String>,
    confirm: bool,
    notification: bool,
    lifetime: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = socket_path.cloned()
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
        .ok_or("No socket path available")?;

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(&socket)?;

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
            notification: Option<bool>,
            #[serde(skip_serializing_if = "Option::is_none")]
            lifetime_seconds: Option<u32>,
        }
        let lifetime_seconds = if let Some(s) = lifetime { Some(parse_lifetime(s)?) } else { None };
        let req = CreateRequestWithConstraints {
            key_type: key_type.to_string(),
            bit_length,
            description,
            load_to_ram: true,
            confirm: if confirm { Some(true) } else { None },
            notification: if notification { Some(true) } else { None },
            lifetime_seconds,
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&req, &mut cbor)?;
        cbor
    };

    let request = ExtensionRequest { extension: "manage.create".to_string(), data: create_data };
    let mut cbor_data = Vec::new();
    ciborium::into_writer(&request, &mut cbor_data)?;

    let mut message = Vec::new();
    message.push(rssh_proto::messages::SSH_AGENTC_EXTENSION);
    let ext_namespace = b"rssh-agent@local";
    message.extend_from_slice(&(ext_namespace.len() as u32).to_be_bytes());
    message.extend_from_slice(ext_namespace);
    message.extend_from_slice(&cbor_data);

    let mut full_message = Vec::new();
    full_message.extend_from_slice(&(message.len() as u32).to_be_bytes());
    full_message.extend_from_slice(&message);
    stream.write_all(&full_message)?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut response = vec![0u8; len];
    stream.read_exact(&mut response)?;

    if response[0] == rssh_proto::messages::SSH_AGENT_SUCCESS {
        let mut offset = 1;
        if response.len() < offset + 4 { return Err("Response too short".into()); }
        let data_len = u32::from_be_bytes([
            response[offset], response[offset + 1],
            response[offset + 2], response[offset + 3],
        ]) as usize;
        offset += 4;
        if response.len() < offset + data_len { return Err("Response data truncated".into()); }
        let cbor_data = &response[offset..offset + data_len];
        let cbor_response: rssh_proto::cbor::ExtensionResponse = ciborium::from_reader(cbor_data)?;
        if !cbor_response.success {
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

fn set_key_password(
    socket_path: Option<&String>,
    fingerprint: &str,
    password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = socket_path.cloned()
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
        .ok_or("No socket path available")?;

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(&socket)?;

    use rssh_proto::cbor::ExtensionRequest;
    let request_data = {
        #[derive(serde::Serialize)]
        struct SetPasswordRequest {
            fp_sha256_hex: String,
            set_password_protection: bool,
            new_key_pass_b64: String,
        }
        let mut data = Vec::new();
        ciborium::into_writer(&SetPasswordRequest {
            fp_sha256_hex: fingerprint.to_string(),
            set_password_protection: true,
            new_key_pass_b64: {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(password.as_bytes())
            },
        }, &mut data)?;
        data
    };

    let request = ExtensionRequest { extension: "manage.set_password".to_string(), data: request_data };
    let mut cbor_data = Vec::new();
    ciborium::into_writer(&request, &mut cbor_data)?;

    let mut message = Vec::new();
    message.push(rssh_proto::messages::SSH_AGENTC_EXTENSION);
    let ext_namespace = b"rssh-agent@local";
    message.extend_from_slice(&(ext_namespace.len() as u32).to_be_bytes());
    message.extend_from_slice(ext_namespace);
    message.extend_from_slice(&cbor_data);

    let mut full_message = Vec::new();
    full_message.extend_from_slice(&(message.len() as u32).to_be_bytes());
    full_message.extend_from_slice(&message);
    stream.write_all(&full_message)?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut response = vec![0u8; len];
    stream.read_exact(&mut response)?;

    if response.is_empty() { return Err("Empty response from agent".into()); }

    if response[0] == rssh_proto::messages::SSH_AGENT_SUCCESS {
        let mut offset = 1;
        if response.len() < offset + 4 { return Err("Response too short".into()); }
        let data_len = u32::from_be_bytes([
            response[offset], response[offset + 1],
            response[offset + 2], response[offset + 3],
        ]) as usize;
        offset += 4;
        if response.len() < offset + data_len { return Err("Response data truncated".into()); }
        let cbor_data = &response[offset..offset + data_len];
        let cbor_response: rssh_proto::cbor::ExtensionResponse = ciborium::from_reader(cbor_data)?;
        if !cbor_response.success { return Err(cbor_error_msg(&cbor_response.data).into()); }
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
    let socket = socket_path.cloned()
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
        .ok_or("No socket path available")?;

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(&socket)?;

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
        let mut data = Vec::new();
        ciborium::into_writer(&RemovePasswordRequest {
            fp_sha256_hex: fingerprint.to_string(),
            set_password_protection: false,
            new_key_pass_b64: None,
            current_key_pass_b64: Some(BASE64.encode(current_password.as_bytes())),
        }, &mut data)?;
        data
    };

    let request = ExtensionRequest { extension: "manage.set_password".to_string(), data: request_data };
    let mut cbor_data = Vec::new();
    ciborium::into_writer(&request, &mut cbor_data)?;

    let mut message = Vec::new();
    message.push(rssh_proto::messages::SSH_AGENTC_EXTENSION);
    let ext_namespace = b"rssh-agent@local";
    message.extend_from_slice(&(ext_namespace.len() as u32).to_be_bytes());
    message.extend_from_slice(ext_namespace);
    message.extend_from_slice(&cbor_data);

    let mut full_message = Vec::new();
    full_message.extend_from_slice(&(message.len() as u32).to_be_bytes());
    full_message.extend_from_slice(&message);
    stream.write_all(&full_message)?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut response = vec![0u8; len];
    stream.read_exact(&mut response)?;

    if response[0] == rssh_proto::messages::SSH_AGENT_SUCCESS {
        let mut offset = 1;
        if response.len() < offset + 4 { return Err("Response too short".into()); }
        let data_len = u32::from_be_bytes([
            response[offset], response[offset + 1],
            response[offset + 2], response[offset + 3],
        ]) as usize;
        offset += 4;
        if response.len() < offset + data_len { return Err("Response data truncated".into()); }
        let cbor_data = &response[offset..offset + data_len];
        let cbor_response: rssh_proto::cbor::ExtensionResponse = ciborium::from_reader(cbor_data)?;
        if !cbor_response.success { return Err(cbor_error_msg(&cbor_response.data).into()); }
        Ok(())
    } else {
        Err("Failed to remove key password".into())
    }
}

fn import_key(
    socket_path: Option<&String>,
    fingerprint: &str,
    description: Option<String>,
    password: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = socket_path.cloned()
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
        .ok_or("No socket path available")?;

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(&socket)?;

    use rssh_proto::cbor::ExtensionRequest;
    let import_data = {
        #[derive(serde::Serialize)]
        struct ImportRequest {
            fp_sha256_hex: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            description: Option<String>,
            set_key_password: bool,
            #[serde(skip_serializing_if = "Option::is_none")]
            new_key_pass_b64: Option<String>,
        }
        let (set_key_password, new_key_pass_b64) = if let Some(pass) = password {
            use base64::Engine;
            (true, Some(base64::engine::general_purpose::STANDARD.encode(pass.as_bytes())))
        } else {
            (false, None)
        };
        let mut data = Vec::new();
        ciborium::into_writer(&ImportRequest {
            fp_sha256_hex: fingerprint.to_string(),
            description,
            set_key_password,
            new_key_pass_b64,
        }, &mut data)?;
        data
    };

    let request = ExtensionRequest { extension: "manage.import".to_string(), data: import_data };
    let mut cbor_data = Vec::new();
    ciborium::into_writer(&request, &mut cbor_data)?;

    let ext_name = "rssh-agent@local";
    let total_len = 1 + 4 + ext_name.len() + cbor_data.len();
    let mut message = Vec::new();
    message.extend_from_slice(&(total_len as u32).to_be_bytes());
    message.push(27); // SSH_AGENTC_EXTENSION
    message.extend_from_slice(&(ext_name.len() as u32).to_be_bytes());
    message.extend_from_slice(ext_name.as_bytes());
    message.extend_from_slice(&cbor_data);
    stream.write_all(&message)?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let response_len = u32::from_be_bytes(len_buf) as usize;
    let mut response = vec![0u8; response_len];
    stream.read_exact(&mut response)?;

    if response[0] != rssh_proto::messages::SSH_AGENT_SUCCESS {
        return Err("Import failed".into());
    }
    Ok(())
}

fn set_constraints(
    socket_path: Option<&String>,
    fingerprint: &str,
    confirm: bool,
    notification: bool,
    lifetime: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = socket_path.cloned()
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
        .ok_or("No socket path available")?;

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(&socket)?;

    use rssh_proto::cbor::ExtensionRequest;
    let set_constraints_data = {
        #[derive(serde::Serialize)]
        struct SetConstraintsRequest {
            fp_sha256_hex: String,
            confirm: bool,
            notification: bool,
            #[serde(skip_serializing_if = "Option::is_none")]
            lifetime_seconds: Option<u64>,
        }
        let lifetime_seconds = if let Some(s) = lifetime { Some(parse_lifetime(s)? as u64) } else { None };
        let mut cbor = Vec::new();
        ciborium::into_writer(&SetConstraintsRequest {
            fp_sha256_hex: fingerprint.to_string(),
            confirm, notification, lifetime_seconds,
        }, &mut cbor)?;
        cbor
    };

    let request = ExtensionRequest { extension: "manage.set_constraints".to_string(), data: set_constraints_data };
    let mut cbor_data = Vec::new();
    ciborium::into_writer(&request, &mut cbor_data)?;

    let mut message = Vec::new();
    message.push(rssh_proto::messages::SSH_AGENTC_EXTENSION);
    let ext_namespace = b"rssh-agent@local";
    message.extend_from_slice(&(ext_namespace.len() as u32).to_be_bytes());
    message.extend_from_slice(ext_namespace);
    message.extend_from_slice(&cbor_data);

    let mut full_message = Vec::new();
    full_message.extend_from_slice(&(message.len() as u32).to_be_bytes());
    full_message.extend_from_slice(&message);
    stream.write_all(&full_message)?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut response = vec![0u8; len];
    stream.read_exact(&mut response)?;

    if response[0] == rssh_proto::messages::SSH_AGENT_SUCCESS {
        let mut offset = 1;
        if response.len() < offset + 4 { return Err("Response too short".into()); }
        let data_len = u32::from_be_bytes([
            response[offset], response[offset + 1],
            response[offset + 2], response[offset + 3],
        ]) as usize;
        offset += 4;
        if response.len() < offset + data_len { return Err("Response data truncated".into()); }
        let cbor_data = &response[offset..offset + data_len];
        let cbor_response: rssh_proto::cbor::ExtensionResponse = ciborium::from_reader(cbor_data)?;
        if !cbor_response.success { return Err(cbor_error_msg(&cbor_response.data).into()); }
        Ok(())
    } else {
        Err("Failed to set constraints".into())
    }
}

fn set_default_constraints(
    socket_path: Option<&String>,
    fingerprint: &str,
    default_confirm: bool,
    default_notification: bool,
    default_lifetime: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = socket_path.cloned()
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
        .ok_or("No socket path available")?;

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(&socket)?;

    use rssh_proto::cbor::ExtensionRequest;
    let set_defaults_data = {
        #[derive(serde::Serialize)]
        struct SetDefaultConstraintsRequest {
            fp_sha256_hex: String,
            default_confirm: bool,
            default_notification: bool,
            #[serde(skip_serializing_if = "Option::is_none")]
            default_lifetime_seconds: Option<u64>,
        }
        let default_lifetime_seconds = if let Some(s) = default_lifetime { Some(parse_lifetime(s)? as u64) } else { None };
        let mut cbor = Vec::new();
        ciborium::into_writer(&SetDefaultConstraintsRequest {
            fp_sha256_hex: fingerprint.to_string(),
            default_confirm, default_notification, default_lifetime_seconds,
        }, &mut cbor)?;
        cbor
    };

    let request = ExtensionRequest { extension: "manage.set_default_constraints".to_string(), data: set_defaults_data };
    let mut cbor_data = Vec::new();
    ciborium::into_writer(&request, &mut cbor_data)?;

    let mut message = Vec::new();
    message.push(rssh_proto::messages::SSH_AGENTC_EXTENSION);
    let ext_namespace = b"rssh-agent@local";
    message.extend_from_slice(&(ext_namespace.len() as u32).to_be_bytes());
    message.extend_from_slice(ext_namespace);
    message.extend_from_slice(&cbor_data);

    let mut full_message = Vec::new();
    full_message.extend_from_slice(&(message.len() as u32).to_be_bytes());
    full_message.extend_from_slice(&message);
    stream.write_all(&full_message)?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut response = vec![0u8; len];
    stream.read_exact(&mut response)?;

    if response[0] == rssh_proto::messages::SSH_AGENT_SUCCESS {
        let mut offset = 1;
        if response.len() < offset + 4 { return Err("Response too short".into()); }
        let data_len = u32::from_be_bytes([
            response[offset], response[offset + 1],
            response[offset + 2], response[offset + 3],
        ]) as usize;
        offset += 4;
        if response.len() < offset + data_len { return Err("Response data truncated".into()); }
        let cbor_data = &response[offset..offset + data_len];
        let cbor_response: rssh_proto::cbor::ExtensionResponse = ciborium::from_reader(cbor_data)?;
        if !cbor_response.success { return Err(cbor_error_msg(&cbor_response.data).into()); }
        Ok(())
    } else {
        Err("Failed to set default constraints".into())
    }
}

fn cbor_error_msg(data: &[u8]) -> String {
    ciborium::from_reader::<serde_json::Value, _>(data)
        .ok()
        .and_then(|v| {
            v.get("error")
                .and_then(|e| e.get("msg"))
                .and_then(|m| m.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| "Unknown error".to_string())
}
