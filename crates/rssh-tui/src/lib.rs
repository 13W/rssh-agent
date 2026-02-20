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
    layout::{Alignment, Constraint, Direction, Layout, Position, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
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
    /// Default constraints for this key (only present for disk-stored keys)
    pub default_constraints: Option<serde_json::Value>, // Object with default_confirm and default_lifetime_seconds
    pub created: Option<String>,
    pub updated: Option<String>,
}

pub struct App {
    pub keys: Vec<KeyInfo>,
    pub list_state: ListState,
    pub selected_key: Option<usize>,
    pub status_message: Option<String>,
    pub input_mode: InputMode,
    pub input_buffer: String,
    pub should_quit: bool,
    pub key_being_loaded: Option<String>, // Fingerprint of key being loaded with password
    pub key_load_password: Option<String>, // Temporarily stores password for loading operations
    pub create_key_type: Option<String>,  // For key creation workflow
    pub create_bit_length: Option<u32>,   // For RSA key creation
    // Unified create key modal state
    pub create_key_selected_type: usize,   // 0=Ed25519, 1=RSA
    pub create_key_bit_length_str: String, // RSA bit length as string for input
    pub create_key_description: String,    // Key description input
    // Authentication state
    pub auth_password: String, // Password buffer for authentication modal
    pub auth_error: Option<String>, // Authentication error message
    // Constraint selection state
    pub constraint_confirm: bool,
    pub constraint_notification: bool,
    pub constraint_lifetime: Option<String>, // User-friendly format like "2h", "1d"
    pub constraint_step: ConstraintStep,
    pub constraint_context: ConstraintContext,
    // Key password management state
    pub key_password_buffer: String, // For setting key passwords
    pub key_being_protected: Option<String>, // Fingerprint of key being password-protected
    pub import_with_password: bool,  // Whether to set password during import
    // Default constraints management state
    pub default_constraint_confirm: bool, // For editing default constraints
    pub default_constraint_notification: bool, // For editing default notification constraint
    pub default_constraint_lifetime: Option<String>, // User-friendly format for default constraints
    pub key_setting_defaults: Option<String>, // Fingerprint of key having defaults set
    // 3-frame UI state
    pub active_frame: ActiveFrame, // Which frame currently has focus
    pub info_panel_content: InfoPanelContent, // What to show in the info panel
    pub status_type: StatusType,   // Type of status message for styling
    // Info panel field selection state
    pub selected_info_field: InfoPanelField, // Which field is currently selected in info panel

    // Modal state
    pub modal_input_buffer: String,  // Input buffer for modal fields
    pub modal_input_buffer2: String, // Second input buffer (e.g., confirm password)
    pub modal_input_buffer3: String, // Third input buffer (e.g., old password)
    pub modal_selected_field: usize, // Which field is selected in modal
    pub modal_error: Option<String>, // Error message for modal validation
    pub modal_key_fingerprint: Option<String>, // Which key the modal is editing

    // Modal-specific state - updated for radio button model
    pub modal_constraint_runtime: ConstraintOption, // Runtime constraint setting
    pub modal_constraint_default: ConstraintOption, // Default constraint setting
    pub modal_lifetime_runtime: String,             // Runtime lifetime setting
    pub modal_lifetime_default: String,             // Default lifetime setting
}

// Constraint helper functions
impl App {
    pub fn reset_constraints(&mut self) {
        self.constraint_confirm = false;
        self.constraint_notification = false;
        self.constraint_lifetime = None;
        self.constraint_step = ConstraintStep::SelectOptions;
    }

    /// Load constraints from defaults or reset to system defaults
    pub fn load_constraints_from_defaults(
        &mut self,
        default_constraints: Option<serde_json::Value>,
    ) {
        if let Some(ref defaults) = default_constraints {
            // Pre-populate with stored defaults
            self.constraint_confirm = defaults
                .get("default_confirm")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            self.constraint_notification = defaults
                .get("default_notification")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            self.constraint_lifetime = defaults
                .get("default_lifetime_seconds")
                .and_then(|v| v.as_u64())
                .filter(|&seconds| seconds > 0)
                .map(|seconds| format_lifetime_friendly(seconds as u32));
        } else {
            // No defaults, use system defaults
            self.constraint_confirm = false;
            self.constraint_notification = false;
            self.constraint_lifetime = None;
        }
        self.constraint_step = ConstraintStep::SelectOptions;
    }

    pub fn has_constraints(&self) -> bool {
        self.constraint_confirm
            || self.constraint_notification
            || self.constraint_lifetime.is_some()
    }

    /// Get current runtime constraint values for a loaded key
    pub fn get_current_runtime_constraints(&self, key_idx: usize) -> (bool, bool, Option<String>) {
        if key_idx >= self.keys.len() {
            return (false, false, None);
        }

        let key = &self.keys[key_idx];
        let confirm = key
            .constraints
            .get("confirm")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let notification = key
            .constraints
            .get("notification")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let lifetime = key
            .constraints
            .get("lifetime_seconds")
            .and_then(|v| v.as_u64())
            .filter(|&seconds| seconds > 0)
            .map(|seconds| format_lifetime_friendly(seconds as u32));

        (confirm, notification, lifetime)
    }

    /// Get current default constraint values for a key
    pub fn get_current_default_constraints(&self, key_idx: usize) -> (bool, bool, Option<String>) {
        if key_idx >= self.keys.len() {
            return (false, false, None);
        }

        let key = &self.keys[key_idx];
        if let Some(ref defaults) = key.default_constraints {
            let confirm = defaults
                .get("default_confirm")
                .and_then(|v: &serde_json::Value| v.as_bool())
                .unwrap_or(false);
            let notification = defaults
                .get("default_notification")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let lifetime = defaults
                .get("default_lifetime_seconds")
                .and_then(|v| v.as_u64())
                .filter(|&seconds| seconds > 0)
                .map(|seconds| format_lifetime_friendly(seconds as u32));

            (confirm, notification, lifetime)
        } else {
            (false, false, None)
        }
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

/// Calculate remaining lifetime for a key based on its constraints
fn calculate_remaining_lifetime(constraints: &serde_json::Value) -> Option<String> {
    if let Some(lifetime_expires_at) = constraints.get("lifetime_expires_at") {
        if let Some(expires_str) = lifetime_expires_at.as_str() {
            // Parse the ISO timestamp
            if let Ok(expires_at) = chrono::DateTime::parse_from_rfc3339(expires_str) {
                let now = chrono::Utc::now();
                let expires_utc = expires_at.with_timezone(&chrono::Utc);

                if expires_utc > now {
                    let duration = expires_utc - now;
                    let total_seconds = duration.num_seconds();

                    if total_seconds <= 0 {
                        return Some("EXPIRED".to_string());
                    }

                    // Format the remaining time
                    if total_seconds >= 86400 {
                        let days = total_seconds / 86400;
                        let hours = (total_seconds % 86400) / 3600;
                        if hours > 0 {
                            return Some(format!("{}d{}h", days, hours));
                        } else {
                            return Some(format!("{}d", days));
                        }
                    } else if total_seconds >= 3600 {
                        let hours = total_seconds / 3600;
                        let minutes = (total_seconds % 3600) / 60;
                        if minutes > 0 {
                            return Some(format!("{}h{}m", hours, minutes));
                        } else {
                            return Some(format!("{}h", hours));
                        }
                    } else if total_seconds >= 60 {
                        let minutes = total_seconds / 60;
                        let seconds = total_seconds % 60;
                        if seconds > 0 {
                            return Some(format!("{}m{}s", minutes, seconds));
                        } else {
                            return Some(format!("{}m", minutes));
                        }
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

#[derive(PartialEq, Clone)]
pub enum ConstraintStep {
    SelectOptions,
    InputLifetime,
}
/// Constraint option for confirmation settings
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstraintOption {
    None,         // No constraints applied
    Notification, // Show info-only notifications
    Confirmation, // Require user approval
}

impl Default for ConstraintOption {
    fn default() -> Self {
        ConstraintOption::None
    }
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

    pub fn as_str(self) -> &'static str {
        match self {
            ConstraintOption::None => "None",
            ConstraintOption::Notification => "Notification",
            ConstraintOption::Confirmation => "Confirmation",
        }
    }
}

#[derive(PartialEq, Clone)]
pub enum ConstraintContext {
    None,
    Load(String), // fingerprint
    Create,
    SetDefaults(String), // fingerprint for setting default constraints
}

#[derive(PartialEq)]
pub enum InputMode {
    AuthenticationRequired, // New state for startup authentication
    Normal,
    Password,
    Confirm,
    Description,
    Certificate,
    CreateKeyType,
    CreateBitLength,
    CreateDescription,
    SetKeyPassword,
    ConfirmKeyPassword,
    ImportKeyPassword,
    ImportKeyPasswordConfirm,
    DefaultConstraints,
    DefaultLifetimeInput,
    // Modal states
    DescriptionEditModal,
    PasswordChangeModal,
    ConfirmationSettingsModal,
    ExpirationSettingsModal,
    RemovePasswordModal,
    KeyPasswordModal,    // New modal state for key password input
    SetKeyPasswordModal, // Modal for setting/changing key passwords with three fields
    // Unified create key modal
    CreateKeyModal, // Unified modal for key creation (type, bit length, description)
    // Legacy create key modals (kept for backward compatibility during transition)
    CreateKeyTypeModal,        // Modal for selecting key type (Ed25519/RSA)
    CreateKeyBitLengthModal,   // Modal for selecting RSA bit length
    CreateKeyDescriptionModal, // Modal for entering key description
}
/// Represents which frame currently has focus
#[derive(PartialEq, Clone, Debug)]
pub enum ActiveFrame {
    KeysList,
    InfoPanel,
}

/// Represents the type of content displayed in the info panel
#[derive(PartialEq, Clone, Debug)]
pub enum InfoPanelContent {
    KeyDetails, // Show details of selected key
    Help,       // Show help/keybindings
}
/// Represents the fields that can be selected in the key details panel
#[derive(PartialEq, Clone, Debug)]
pub enum InfoPanelField {
    Description,
    Password,
    Confirmation,
    Expiration,
}

/// Represents different status message types for the status bar
#[derive(PartialEq, Clone, Debug)]
pub enum StatusType {
    Success,
    Error,
    Info,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        let list_state = ListState::default();
        // Don't select anything initially - let load_keys handle it

        Self {
            keys: Vec::new(),
            list_state,
            selected_key: None,
            status_message: None,
            input_mode: InputMode::AuthenticationRequired, // Start with authentication modal
            input_buffer: String::new(),
            should_quit: false,
            key_being_loaded: None,
            key_load_password: None,
            create_key_type: None,
            create_bit_length: None,
            // Initialize unified create key modal state
            create_key_selected_type: 0, // Default to Ed25519
            create_key_bit_length_str: "2048".to_string(), // Default RSA bit length
            create_key_description: String::new(),
            // Initialize authentication state
            auth_password: String::new(),
            auth_error: None,
            constraint_confirm: false,
            constraint_notification: false,
            constraint_lifetime: None,
            constraint_step: ConstraintStep::SelectOptions,
            constraint_context: ConstraintContext::Create,
            key_password_buffer: String::new(),
            key_being_protected: None,
            import_with_password: false,
            default_constraint_confirm: false,
            default_constraint_notification: false,
            default_constraint_lifetime: None,
            key_setting_defaults: None,
            // Initialize 3-frame UI state
            active_frame: ActiveFrame::KeysList, // Start with focus on keys list
            info_panel_content: InfoPanelContent::KeyDetails, // Show key details by default
            status_type: StatusType::Info,       // Default status type
            // Initialize info panel field selection
            selected_info_field: InfoPanelField::Description, // Start with description field selected

            // Initialize modal state
            modal_input_buffer: String::new(),
            modal_input_buffer2: String::new(),
            modal_input_buffer3: String::new(),
            modal_selected_field: 0,
            modal_error: None,
            modal_key_fingerprint: None,

            // Initialize modal-specific state - updated for radio button model
            modal_constraint_runtime: ConstraintOption::None,
            modal_constraint_default: ConstraintOption::None,
            modal_lifetime_runtime: String::new(),
            modal_lifetime_default: String::new(),
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

    /// Switch focus to the next frame
    pub fn next_frame(&mut self) {
        self.active_frame = match self.active_frame {
            ActiveFrame::KeysList => ActiveFrame::InfoPanel,
            ActiveFrame::InfoPanel => ActiveFrame::KeysList,
        };
    }

    /// Clear modal state and return to normal mode
    pub fn close_modal(&mut self) {
        self.input_mode = InputMode::Normal;
        self.modal_input_buffer.clear();
        self.modal_input_buffer2.clear();
        self.modal_input_buffer3.clear();
        self.modal_selected_field = 0;
        self.modal_error = None;
        self.modal_key_fingerprint = None;

        // Clear modal-specific state - updated for new ConstraintOption model
        self.modal_constraint_runtime = ConstraintOption::None;
        self.modal_constraint_default = ConstraintOption::None;
        self.modal_lifetime_runtime.clear();
        self.modal_lifetime_default.clear();
    }

    /// Open description edit modal for the selected key
    pub fn open_description_modal(&mut self) {
        if let Some(idx) = self.selected_key {
            if idx < self.keys.len() {
                let key = &self.keys[idx];
                self.input_mode = InputMode::DescriptionEditModal;
                self.modal_key_fingerprint = Some(key.fingerprint.clone());
                self.modal_input_buffer = key.description.clone();
                self.modal_selected_field = 0;
                self.modal_error = None;
            }
        }
    }

    /// Open password change modal for the selected key  
    pub fn open_password_modal(&mut self) {
        if let Some(idx) = self.selected_key {
            if idx < self.keys.len() {
                let key = &self.keys[idx];
                if !key.has_disk {
                    self.set_status("Only stored keys can have their password changed".to_string());
                    return;
                }

                self.input_mode = InputMode::PasswordChangeModal;
                self.modal_key_fingerprint = Some(key.fingerprint.clone());
                self.modal_input_buffer.clear(); // Old password
                self.modal_input_buffer2.clear(); // New password 
                self.modal_input_buffer3.clear(); // Confirm password
                self.modal_selected_field = 0; // Always start at first field
                self.modal_error = None;
            }
        }
    }

    pub fn open_confirmation_modal(&mut self) {
        if let Some(idx) = self.selected_key {
            if idx < self.keys.len() {
                let key = &self.keys[idx];
                self.input_mode = InputMode::ConfirmationSettingsModal;
                self.modal_key_fingerprint = Some(key.fingerprint.clone());
                self.modal_selected_field = 0;
                self.modal_error = None;

                // Load current runtime settings
                if key.loaded {
                    // Get runtime constraints from key
                    let confirm_runtime = key
                        .constraints
                        .get("confirm")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let notify_runtime = key
                        .constraints
                        .get("notification")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);

                    self.modal_constraint_runtime =
                        ConstraintOption::from((confirm_runtime, notify_runtime));
                } else {
                    self.modal_constraint_runtime = ConstraintOption::None;
                }

                // Load default constraints from key - FIX: Use correct field names
                if let Some(defaults) = &key.default_constraints {
                    let confirm_default = defaults
                        .get("default_confirm")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let notify_default = defaults
                        .get("default_notification")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);

                    self.modal_constraint_default =
                        ConstraintOption::from((confirm_default, notify_default));
                } else {
                    // System default: no constraints (consistent with keyfile.rs defaults)
                    self.modal_constraint_default = ConstraintOption::None;
                }
            }
        }
    }

    /// Open expiration settings modal for the selected key
    pub fn open_expiration_modal(&mut self) {
        if let Some(idx) = self.selected_key {
            if idx < self.keys.len() {
                let key = &self.keys[idx];
                self.input_mode = InputMode::ExpirationSettingsModal;
                self.modal_key_fingerprint = Some(key.fingerprint.clone());
                self.modal_selected_field = 0;
                self.modal_error = None;

                // Load current default lifetime
                self.modal_lifetime_default = key
                    .default_constraints
                    .as_ref()
                    .and_then(|c| c.get("lifetime"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
            }
        }
    }

    /// Navigate to the next field in the current modal
    pub fn modal_next_field(&mut self) {
        match self.input_mode {
            InputMode::DescriptionEditModal => {
                // Only one field, no navigation needed
            }
            InputMode::PasswordChangeModal => {
                if let Some(idx) = self.selected_key {
                    if idx < self.keys.len() {
                        let key = &self.keys[idx];
                        let max_field = if key.password_protected { 2 } else { 1 }; // 0,1,2 if protected, 0,1 if not
                        if self.modal_selected_field < max_field {
                            self.modal_selected_field += 1;
                        }
                    }
                }
            }
            InputMode::ConfirmationSettingsModal => {
                // Navigate through radio options
                let max_field = if self
                    .selected_key
                    .and_then(|idx| self.keys.get(idx))
                    .map(|k| k.loaded)
                    .unwrap_or(false)
                {
                    3
                } else {
                    1
                }; // 4 fields if loaded, 2 if not
                if self.modal_selected_field < max_field {
                    self.modal_selected_field += 1;
                }
            }
            InputMode::ExpirationSettingsModal => {
                // Navigate through available fields
                let max_field = 1; // Input field and buttons
                if self.modal_selected_field < max_field {
                    self.modal_selected_field += 1;
                }
            }
            InputMode::SetKeyPasswordModal => {
                // Navigate between new password and confirm password fields (cycle)
                let max_field = 1; // 0: new password, 1: confirm password
                if self.modal_selected_field < max_field {
                    self.modal_selected_field += 1;
                } else {
                    self.modal_selected_field = 0; // Cycle back to first field
                }
            }
            _ => {}
        }
    }

    /// Navigate to the previous field in the current modal
    pub fn modal_previous_field(&mut self) {
        match self.input_mode {
            InputMode::SetKeyPasswordModal => {
                // Navigate backward between new password and confirm password fields (cycle)
                if self.modal_selected_field > 0 {
                    self.modal_selected_field -= 1;
                } else {
                    self.modal_selected_field = 1; // Cycle back to last field (confirm password)
                }
            }
            _ => {
                // Default behavior for other modals
                if self.modal_selected_field > 0 {
                    self.modal_selected_field -= 1;
                }
            }
        }
    }

    /// Switch focus to the previous frame
    pub fn previous_frame(&mut self) {
        self.active_frame = match self.active_frame {
            ActiveFrame::KeysList => ActiveFrame::InfoPanel,
            ActiveFrame::InfoPanel => ActiveFrame::KeysList,
        };
    }

    /// Set the focus to a specific frame
    pub fn set_active_frame(&mut self, frame: ActiveFrame) {
        self.active_frame = frame;
    }

    /// Toggle between key details and help in the info panel
    pub fn toggle_info_panel_content(&mut self) {
        self.info_panel_content = match self.info_panel_content {
            InfoPanelContent::KeyDetails => InfoPanelContent::Help,
            InfoPanelContent::Help => InfoPanelContent::KeyDetails,
        };
    }

    /// Set status message with type for appropriate styling
    pub fn set_status_with_type(&mut self, message: String, status_type: StatusType) {
        self.status_message = Some(message);
        self.status_type = status_type;
    }
}

pub fn run_tui(socket_path: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app state - starts with authentication modal
    let mut app = App::new();

    // Don't load keys initially - wait for authentication
    // The authentication modal will trigger key loading on successful unlock

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
                InputMode::AuthenticationRequired => match key.code {
                    KeyCode::Enter => {
                        // Attempt authentication
                        if app.auth_password.is_empty() {
                            app.auth_error = Some("Password cannot be empty".to_string());
                        } else {
                            match unlock_agent(socket_path.as_ref(), &app.auth_password) {
                                Ok(()) => {
                                    // Authentication successful
                                    app.input_mode = InputMode::Normal;
                                    app.auth_password.clear();
                                    app.auth_error = None;

                                    // Load keys after successful authentication
                                    if let Err(e) = load_keys(app, socket_path.as_ref()) {
                                        app.set_status(format!("Failed to load keys: {}", e));
                                    } else {
                                        app.set_status("Authentication successful".to_string());
                                    }
                                }
                                Err(e) => {
                                    // Authentication failed
                                    app.auth_error = Some(format!("Authentication failed: {}", e));
                                    app.auth_password.clear();
                                }
                            }
                        }
                    }
                    KeyCode::Esc => {
                        // Exit application
                        app.should_quit = true;
                    }
                    KeyCode::Char(c) => {
                        // Add character to password buffer
                        app.auth_password.push(c);
                        app.auth_error = None; // Clear error on input
                    }
                    KeyCode::Backspace => {
                        // Remove character from password buffer
                        app.auth_password.pop();
                        app.auth_error = None; // Clear error on input
                    }
                    _ => {}
                },
                InputMode::Normal => match key.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') => {
                        app.should_quit = true;
                    }
                    KeyCode::Char('j') | KeyCode::Down => {
                        if app.active_frame == ActiveFrame::KeysList {
                            app.next();
                        } else if app.active_frame == ActiveFrame::InfoPanel {
                            // Navigate to next field in info panel
                            app.selected_info_field = match app.selected_info_field {
                                InfoPanelField::Description => InfoPanelField::Password,
                                InfoPanelField::Password => InfoPanelField::Confirmation,
                                InfoPanelField::Confirmation => InfoPanelField::Expiration,
                                InfoPanelField::Expiration => InfoPanelField::Description, // Wrap around
                            };
                        }
                    }
                    KeyCode::Char('k') | KeyCode::Up => {
                        if app.active_frame == ActiveFrame::KeysList {
                            app.previous();
                        } else if app.active_frame == ActiveFrame::InfoPanel {
                            // Navigate to previous field in info panel
                            app.selected_info_field = match app.selected_info_field {
                                InfoPanelField::Description => InfoPanelField::Expiration, // Wrap around
                                InfoPanelField::Password => InfoPanelField::Description,
                                InfoPanelField::Confirmation => InfoPanelField::Password,
                                InfoPanelField::Expiration => InfoPanelField::Confirmation,
                            };
                        }
                    }
                    KeyCode::Enter => {
                        // Handle Enter key in info panel to open modals
                        if app.active_frame == ActiveFrame::InfoPanel && app.selected_key.is_some()
                        {
                            match app.selected_info_field {
                                InfoPanelField::Description => {
                                    app.open_description_modal();
                                }
                                InfoPanelField::Password => {
                                    app.open_password_modal();
                                }
                                InfoPanelField::Confirmation => {
                                    app.open_confirmation_modal();
                                }
                                InfoPanelField::Expiration => {
                                    app.open_expiration_modal();
                                }
                            }
                        }
                    }
                    KeyCode::Char('r') | KeyCode::F(5) => {
                        if let Err(e) = load_keys(app, socket_path.as_ref()) {
                            app.set_status_with_type(
                                format!("Failed to refresh: {}", e),
                                StatusType::Error,
                            );
                        } else {
                            app.set_status_with_type(
                                "Keys refreshed".to_string(),
                                StatusType::Success,
                            );
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
                    KeyCode::Tab => {
                        app.next_frame();
                    }
                    KeyCode::Char('h') | KeyCode::Char('?') => {
                        app.toggle_info_panel_content();
                    }
                    KeyCode::Char('L') => {
                        // Load selected disk key into memory directly with default constraints
                        if let Some(idx) = app.selected_key
                            && idx < app.keys.len()
                        {
                            // Extract key info first to avoid borrow conflicts
                            let has_disk = app.keys[idx].has_disk;
                            let is_loaded = app.keys[idx].loaded;
                            let password_protected = app.keys[idx].password_protected;
                            let fingerprint = app.keys[idx].fingerprint.clone();
                            let default_constraints = app.keys[idx].default_constraints.clone();

                            // Check if key is on disk but not loaded
                            if !has_disk {
                                app.set_status("Key is not on disk".to_string());
                            } else if is_loaded {
                                app.set_status("Key is already loaded".to_string());
                            } else if password_protected {
                                // Key is password-protected, prompt for password
                                app.input_mode = InputMode::KeyPasswordModal;
                                app.input_buffer.clear();
                                app.key_being_loaded = Some(fingerprint);
                                app.set_status("Enter key password:".to_string());
                            } else {
                                // Key is not password-protected, load directly with default constraints
                                let confirm = default_constraints
                                    .as_ref()
                                    .and_then(|d| d.get("confirm"))
                                    .and_then(|v| v.as_bool())
                                    .unwrap_or(false);
                                let notification = default_constraints
                                    .as_ref()
                                    .and_then(|d| d.get("notification"))
                                    .and_then(|v| v.as_bool())
                                    .unwrap_or(false);
                                let lifetime = default_constraints
                                    .as_ref()
                                    .and_then(|d| d.get("lifetime"))
                                    .and_then(|v| v.as_str());

                                let result = load_disk_key_with_constraints(
                                    socket_path.as_ref(),
                                    &fingerprint,
                                    None,
                                    confirm,
                                    notification,
                                    lifetime,
                                );

                                match result {
                                    Ok(()) => {
                                        app.set_status(format!(
                                            "Key {} loaded into memory",
                                            fingerprint
                                        ));
                                        // Refresh the keys list
                                        if let Err(e) = load_keys(app, socket_path.as_ref()) {
                                            app.set_status(format!(
                                                "Failed to refresh keys: {}",
                                                e
                                            ));
                                        }
                                    }
                                    Err(e) => {
                                        app.set_status(format!("Failed to load key: {}", e));
                                    }
                                }
                            }
                        }
                    }
                    KeyCode::Char('U') => {
                        // Unload selected key from memory
                        if let Some(idx) = app.selected_key
                            && idx < app.keys.len()
                        {
                            let key = &app.keys[idx];
                            if key.loaded {
                                let fingerprint = key.fingerprint.clone();
                                if let Err(e) = unload_key(socket_path.as_ref(), &fingerprint) {
                                    app.set_status(format!("Failed to unload key: {}", e));
                                } else {
                                    app.set_status(format!(
                                        "Key {} unloaded from memory",
                                        fingerprint
                                    ));
                                    // Refresh the keys list
                                    if let Err(e) = load_keys(app, socket_path.as_ref()) {
                                        app.set_status(format!("Failed to refresh keys: {}", e));
                                    }
                                }
                            } else {
                                app.set_status("Key is not loaded in memory".to_string());
                            }
                        }
                    }
                    KeyCode::Char('i') => {
                        // Import key
                        if let Err(e) = load_keys(app, socket_path.as_ref()) {
                            app.set_status(format!("Failed to load keys before import: {}", e));
                        } else {
                            app.input_mode = InputMode::Certificate;
                            app.input_buffer.clear();
                            app.set_status("Paste OpenSSH certificate (base64):".to_string());
                        }
                    }
                    KeyCode::Char('n') => {
                        // Create new key - open unified modal
                        app.input_mode = InputMode::CreateKeyModal;
                        app.modal_selected_field = 0; // Start with key type selection
                        app.modal_error = None;
                        app.create_key_type = None;
                        app.create_bit_length = None;
                        // Initialize unified modal state
                        app.create_key_selected_type = 0; // Default to Ed25519
                        app.create_key_bit_length_str = "2048".to_string();
                        app.create_key_description.clear();
                        app.set_status("Creating new key...".to_string());
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
                                // Open the compact set password modal
                                app.input_mode = InputMode::SetKeyPasswordModal;
                                app.modal_key_fingerprint = Some(key.fingerprint.clone());
                                app.modal_input_buffer.clear(); // New password
                                app.modal_input_buffer2.clear(); // Confirm password
                                app.modal_selected_field = 0; // Start with new password field
                                app.modal_error = None;
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
                                // Open password removal modal
                                app.input_mode = InputMode::RemovePasswordModal;
                                app.key_being_protected = Some(key.fingerprint.clone());
                                app.modal_key_fingerprint = Some(key.fingerprint.clone());
                                app.modal_input_buffer.clear(); // Clear password input buffer
                                app.modal_error = None; // Clear any previous errors
                            }
                        }
                    }
                    KeyCode::Char('l') => {
                        // Lock the agent
                        if let Err(e) = lock_agent(socket_path.as_ref()) {
                            app.set_status(format!("Failed to lock agent: {}", e));
                        } else {
                            // Clear keys and show authentication screen
                            app.keys.clear();
                            app.selected_key = None;
                            app.list_state.select(None);
                            app.input_mode = InputMode::AuthenticationRequired;
                            app.auth_password.clear();
                            app.auth_error = None;
                            app.set_status(
                                "Agent locked. Please authenticate to continue.".to_string(),
                            );
                        }
                    }
                    KeyCode::Char('e') => {
                        // Edit description of selected key
                        if let Some(idx) = app.selected_key
                            && idx < app.keys.len()
                        {
                            let key = &app.keys[idx];
                            if !key.has_disk {
                                app.set_status(
                                    "External keys cannot be edited (use original ssh-add)"
                                        .to_string(),
                                );
                            } else {
                                app.input_mode = InputMode::Description;
                                app.input_buffer = key.description.clone();
                                app.set_status("Edit description:".to_string());
                            }
                        }
                    }
                    _ => {}
                },
                InputMode::Password => match key.code {
                    KeyCode::Enter => {
                        // Check password length
                        if app.input_buffer.len() < 12 {
                            app.set_status("Password must be at least 12 characters".to_string());
                        } else {
                            // First time entering password - store it and ask for confirmation
                            app.key_load_password = Some(app.input_buffer.clone());
                            app.input_buffer.clear();
                            app.input_mode = InputMode::KeyPasswordModal;
                            app.set_status("Confirm password:".to_string());
                        }
                    }
                    KeyCode::Esc => {
                        app.input_mode = InputMode::Normal;
                        app.input_buffer.clear();
                        app.key_load_password = None;
                        app.set_status("".to_string());
                    }
                    KeyCode::Char(c) => {
                        app.input_buffer.push(c);
                    }
                    KeyCode::Backspace => {
                        app.input_buffer.pop();
                    }
                    _ => {}
                },
                InputMode::KeyPasswordModal => match key.code {
                    KeyCode::Enter => {
                        // Load the key with the entered password and default constraints
                        if let Some(fingerprint) = &app.key_being_loaded {
                            let password = if app.input_buffer.is_empty() {
                                None
                            } else {
                                Some(app.input_buffer.as_str())
                            };

                            // Find the key to get its default constraints
                            let default_constraints = app
                                .keys
                                .iter()
                                .find(|k| k.fingerprint == *fingerprint)
                                .and_then(|k| k.default_constraints.clone());

                            let confirm = default_constraints
                                .as_ref()
                                .and_then(|d| d.get("confirm"))
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);
                            let notification = default_constraints
                                .as_ref()
                                .and_then(|d| d.get("notification"))
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);
                            let lifetime = default_constraints
                                .as_ref()
                                .and_then(|d| d.get("lifetime"))
                                .and_then(|v| v.as_str());

                            let result = load_disk_key_with_constraints(
                                socket_path.as_ref(),
                                fingerprint,
                                password,
                                confirm,
                                notification,
                                lifetime,
                            );

                            match result {
                                Ok(()) => {
                                    app.modal_error = None; // Clear any modal errors
                                    app.set_status(format!(
                                        "Key {} loaded into memory",
                                        fingerprint
                                    ));
                                    // Refresh the keys list
                                    if let Err(e) = load_keys(app, socket_path.as_ref()) {
                                        app.set_status(format!("Failed to refresh keys: {}", e));
                                    }
                                }
                                Err(e) => {
                                    app.modal_error = Some(format!("Failed to load key: {}", e));
                                    // Don't exit modal on error, let user retry
                                    continue;
                                }
                            }
                        }
                        app.input_mode = InputMode::Normal;
                        app.input_buffer.clear();
                        app.key_being_loaded = None;
                    }
                    KeyCode::Esc => {
                        app.input_mode = InputMode::Normal;
                        app.input_buffer.clear();
                        app.key_being_loaded = None;
                        app.modal_error = None; // Clear modal errors
                        app.set_status("".to_string());
                    }
                    KeyCode::Char(c) => {
                        app.modal_error = None; // Clear error when user starts typing
                        app.input_buffer.push(c);
                    }
                    KeyCode::Backspace => {
                        app.modal_error = None; // Clear error when user edits
                        app.input_buffer.pop();
                    }
                    _ => {}
                },
                InputMode::Confirm => match key.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') => {
                        if let Some(idx) = app.selected_key
                            && idx < app.keys.len()
                        {
                            let fingerprint = app.keys[idx].fingerprint.clone();
                            if let Err(e) = delete_key(socket_path.as_ref(), &fingerprint) {
                                app.set_status(format!("Failed to delete key: {}", e));
                            } else {
                                app.set_status(format!("Key {} permanently deleted", fingerprint));
                                // Refresh the keys list
                                if let Err(e) = load_keys(app, socket_path.as_ref()) {
                                    app.set_status(format!("Failed to refresh keys: {}", e));
                                }
                            }
                        }
                        app.input_mode = InputMode::Normal;
                    }
                    KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                        app.input_mode = InputMode::Normal;
                        app.set_status("Delete cancelled".to_string());
                    }
                    _ => {}
                },
                InputMode::Description => match key.code {
                    KeyCode::Enter => {
                        if let Some(idx) = app.selected_key
                            && idx < app.keys.len()
                        {
                            let fingerprint = app.keys[idx].fingerprint.clone();
                            let new_description = if app.input_buffer.trim().is_empty() {
                                None
                            } else {
                                Some(app.input_buffer.trim().to_string())
                            };

                            if let Err(e) = set_key_description(
                                socket_path.as_ref(),
                                &fingerprint,
                                new_description.as_deref().unwrap_or(""),
                            ) {
                                app.set_status(format!("Failed to update description: {}", e));
                            } else {
                                app.set_status("Description updated".to_string());
                                // Refresh the keys list
                                if let Err(e) = load_keys(app, socket_path.as_ref()) {
                                    app.set_status(format!("Failed to refresh keys: {}", e));
                                }
                            }
                        }
                        app.input_mode = InputMode::Normal;
                        app.input_buffer.clear();
                    }
                    KeyCode::Esc => {
                        app.input_mode = InputMode::Normal;
                        app.input_buffer.clear();
                        app.set_status("".to_string());
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
                        // Import the certificate
                        let cert_data = app.input_buffer.trim();
                        if cert_data.is_empty() {
                            app.set_status("Certificate data cannot be empty".to_string());
                        } else {
                            // Import with password option dialog
                            app.import_with_password = false; // Default to no password
                            app.input_mode = InputMode::ImportKeyPassword;
                            app.key_password_buffer.clear();
                            app.set_status(
                                "Protect imported key with password? (y)es, (n)o, (ESC) cancel"
                                    .to_string(),
                            );
                        }
                    }
                    KeyCode::Esc => {
                        app.input_mode = InputMode::Normal;
                        app.input_buffer.clear();
                        app.set_status("Import cancelled".to_string());
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
                        app.set_status("Enter key description (optional):".to_string());
                    }
                    KeyCode::Char('r') | KeyCode::Char('R') => {
                        app.create_key_type = Some("rsa".to_string());
                        app.input_mode = InputMode::CreateBitLength;
                        app.input_buffer = "2048".to_string(); // Default
                        app.set_status("RSA key size (2048, 3072, 4096):".to_string());
                    }
                    KeyCode::Esc => {
                        app.input_mode = InputMode::Normal;
                        app.create_key_type = None;
                        app.set_status("Key creation cancelled".to_string());
                    }
                    _ => {}
                },
                InputMode::CreateBitLength => match key.code {
                    KeyCode::Enter => match app.input_buffer.parse::<u32>() {
                        Ok(bits) if bits >= 2048 && bits <= 8192 => {
                            app.create_bit_length = Some(bits);
                            app.input_mode = InputMode::CreateDescription;
                            app.input_buffer.clear();
                            app.set_status("Enter key description (optional):".to_string());
                        }
                        _ => {
                            app.set_status("Invalid bit length. Use 2048-8192.".to_string());
                        }
                    },
                    KeyCode::Esc => {
                        app.input_mode = InputMode::Normal;
                        app.create_key_type = None;
                        app.create_bit_length = None;
                        app.input_buffer.clear();
                        app.set_status("Key creation cancelled".to_string());
                    }
                    KeyCode::Char(c) if c.is_ascii_digit() => {
                        if app.input_buffer.len() < 4 {
                            // Limit to 4 digits
                            app.input_buffer.push(c);
                        }
                    }
                    KeyCode::Backspace => {
                        app.input_buffer.pop();
                    }
                    _ => {}
                },
                InputMode::CreateDescription => match key.code {
                    KeyCode::Enter => {
                        // Create the key
                        let description = if app.input_buffer.trim().is_empty() {
                            None
                        } else {
                            Some(app.input_buffer.trim().to_string())
                        };

                        if let (Some(key_type), bit_length) =
                            (&app.create_key_type, app.create_bit_length)
                        {
                            let result =
                                create_key(socket_path.as_ref(), key_type, bit_length, description);
                            match result {
                                Ok(()) => {
                                    app.set_status("Key created successfully".to_string());
                                    // Refresh the keys list
                                    if let Err(e) = load_keys(app, socket_path.as_ref()) {
                                        app.set_status(format!("Failed to refresh keys: {}", e));
                                    }
                                }
                                Err(e) => {
                                    app.set_status(format!("Failed to create key: {}", e));
                                }
                            }
                        }

                        // Reset state
                        app.input_mode = InputMode::Normal;
                        app.input_buffer.clear();
                        app.create_key_type = None;
                        app.create_bit_length = None;
                    }
                    KeyCode::Esc => {
                        app.input_mode = InputMode::Normal;
                        app.input_buffer.clear();
                        app.create_key_type = None;
                        app.create_bit_length = None;
                        app.set_status("Key creation cancelled".to_string());
                    }
                    KeyCode::Char(c) => {
                        app.input_buffer.push(c);
                    }
                    KeyCode::Backspace => {
                        app.input_buffer.pop();
                    }
                    _ => {}
                },
                // Note: SetKeyPassword and ConfirmKeyPassword modes are deprecated
                // in favor of the new SetKeyPasswordModal which provides a compact UI
                InputMode::SetKeyPassword | InputMode::ConfirmKeyPassword => {
                    // Redirect to new modal system - this shouldn't happen in normal flow
                    // since we now trigger SetKeyPasswordModal directly, but keeping for safety
                    app.set_status("Please use the 'P' key to set password protection".to_string());
                    app.input_mode = InputMode::Normal;
                }
                InputMode::ImportKeyPassword => match key.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') => {
                        app.import_with_password = true;
                        app.key_password_buffer.clear();
                        app.input_mode = InputMode::ImportKeyPasswordConfirm;
                        app.set_status("Enter password for imported key:".to_string());
                    }
                    KeyCode::Char('n') | KeyCode::Char('N') => {
                        // Import without password
                        app.import_with_password = false;
                        let result = import_key_with_password(
                            socket_path.as_ref(),
                            &app.input_buffer,
                            "", // No password
                        );
                        match result {
                            Ok(()) => {
                                app.set_status("Key imported successfully".to_string());
                                // Refresh keys
                                if let Err(e) = load_keys(app, socket_path.as_ref()) {
                                    app.set_status(format!("Failed to refresh keys: {}", e));
                                }
                            }
                            Err(e) => {
                                app.set_status(format!("Failed to import key: {}", e));
                            }
                        }
                        app.input_mode = InputMode::Normal;
                        app.input_buffer.clear();
                    }
                    KeyCode::Esc => {
                        app.input_mode = InputMode::Normal;
                        app.input_buffer.clear();
                        app.set_status("Import cancelled".to_string());
                    }
                    _ => {}
                },
                InputMode::ImportKeyPasswordConfirm => match key.code {
                    KeyCode::Enter => {
                        if app.input_buffer.len() < 8 {
                            app.set_status("Password must be at least 8 characters".to_string());
                        } else if let Some(idx) = app.selected_key
                            && idx < app.keys.len()
                        {
                            let result = import_key_with_password(
                                socket_path.as_ref(),
                                // Get the certificate data from the previous input
                                &app.input_buffer, // This should be the certificate, not the password
                                &app.key_password_buffer, // This should be the password
                            );
                            match result {
                                Ok(()) => {
                                    app.set_status(
                                        "Key imported successfully with password protection"
                                            .to_string(),
                                    );
                                    // Refresh keys
                                    if let Err(e) = load_keys(app, socket_path.as_ref()) {
                                        app.set_status(format!("Failed to refresh keys: {}", e));
                                    }
                                }
                                Err(e) => {
                                    app.set_status(format!("Failed to import key: {}", e));
                                }
                            }
                        }
                        app.input_mode = InputMode::Normal;
                        app.input_buffer.clear();
                        app.key_password_buffer.clear();
                        app.import_with_password = false;
                    }
                    KeyCode::Esc => {
                        app.input_mode = InputMode::Normal;
                        app.input_buffer.clear();
                        app.key_password_buffer.clear();
                        app.import_with_password = false;
                        app.set_status("Import cancelled".to_string());
                    }
                    KeyCode::Char(c) => {
                        app.key_password_buffer.push(c);
                    }
                    KeyCode::Backspace => {
                        app.key_password_buffer.pop();
                    }
                    _ => {}
                },
                InputMode::DefaultConstraints => match key.code {
                    KeyCode::Char('c') | KeyCode::Char('C') => {
                        app.default_constraint_confirm = !app.default_constraint_confirm;
                        let confirm_status = if app.default_constraint_confirm {
                            "ON"
                        } else {
                            "OFF"
                        };
                        let notification_status = if app.default_constraint_notification {
                            "ON"
                        } else {
                            "OFF"
                        };
                        app.set_status(format!(
                            "Default: Confirm({}), Notification({}), Lifetime({}). (c)onfirm, (n)otification, (l)ifetime, (Enter) save",
                            confirm_status,
                            notification_status,
                            app.default_constraint_lifetime.as_deref().unwrap_or("none")
                        ));
                    }
                    KeyCode::Char('n') | KeyCode::Char('N') => {
                        app.default_constraint_notification = !app.default_constraint_notification;
                        let confirm_status = if app.default_constraint_confirm {
                            "ON"
                        } else {
                            "OFF"
                        };
                        let notification_status = if app.default_constraint_notification {
                            "ON"
                        } else {
                            "OFF"
                        };
                        app.set_status(format!(
                            "Default: Confirm({}), Notification({}), Lifetime({}). (c)onfirm, (n)otification, (l)ifetime, (Enter) save",
                            confirm_status,
                            notification_status,
                            app.default_constraint_lifetime.as_deref().unwrap_or("none")
                        ));
                    }
                    KeyCode::Char('l') | KeyCode::Char('L') => {
                        app.input_mode = InputMode::DefaultLifetimeInput;
                        app.input_buffer.clear();
                        app.set_status("Enter default lifetime (e.g. 2h, 30m, 1d):".to_string());
                    }
                    KeyCode::Enter => {
                        // Save default constraints
                        if let Some(ref fingerprint) = app.key_setting_defaults {
                            let result = set_default_constraints(
                                socket_path.as_ref(),
                                fingerprint,
                                app.default_constraint_confirm,
                                app.default_constraint_notification,
                                app.default_constraint_lifetime.as_deref(),
                            );
                            match result {
                                Ok(()) => {
                                    app.set_status("Default constraints saved".to_string());
                                    // Refresh keys
                                    if let Err(e) = load_keys(app, socket_path.as_ref()) {
                                        app.set_status(format!("Failed to refresh keys: {}", e));
                                    }
                                }
                                Err(e) => {
                                    app.set_status(format!("Failed to save constraints: {}", e));
                                }
                            }
                        }
                        app.input_mode = InputMode::Normal;
                        app.key_setting_defaults = None;
                    }
                    KeyCode::Esc => {
                        app.input_mode = InputMode::Normal;
                        app.key_setting_defaults = None;
                        app.set_status("Default constraints cancelled".to_string());
                    }
                    _ => {}
                },
                InputMode::DefaultLifetimeInput => match key.code {
                    KeyCode::Enter => {
                        if app.input_buffer.is_empty() {
                            // Empty means no default lifetime
                            app.default_constraint_lifetime = None;
                        } else {
                            match parse_lifetime(&app.input_buffer) {
                                Ok(_) => {
                                    app.default_constraint_lifetime =
                                        Some(app.input_buffer.clone());
                                }
                                Err(e) => {
                                    app.set_status(format!("Invalid lifetime format: {}", e));
                                    continue;
                                }
                            }
                        }

                        app.input_buffer.clear();
                        app.input_mode = InputMode::DefaultConstraints;

                        let confirm_status = if app.default_constraint_confirm {
                            "ON"
                        } else {
                            "OFF"
                        };
                        let notification_status = if app.default_constraint_notification {
                            "ON"
                        } else {
                            "OFF"
                        };
                        app.set_status(format!(
                            "Default: Confirm({}), Notification({}), Lifetime({}). (c)onfirm, (n)otification, (l)ifetime, (Enter) save",
                            confirm_status,
                            notification_status,
                            app.default_constraint_lifetime.as_deref().unwrap_or("none")
                        ));
                    }
                    KeyCode::Esc => {
                        app.input_buffer.clear();
                        app.input_mode = InputMode::DefaultConstraints;
                        let confirm_status = if app.default_constraint_confirm {
                            "ON"
                        } else {
                            "OFF"
                        };
                        let notification_status = if app.default_constraint_notification {
                            "ON"
                        } else {
                            "OFF"
                        };
                        app.set_status(format!(
                            "Default: Confirm({}), Notification({}), Lifetime({}). (c)onfirm, (n)otification, (l)ifetime, (Enter) save",
                            confirm_status,
                            notification_status,
                            app.default_constraint_lifetime.as_deref().unwrap_or("none")
                        ));
                    }
                    KeyCode::Char(c) => {
                        app.input_buffer.push(c);
                    }
                    KeyCode::Backspace => {
                        app.input_buffer.pop();
                    }
                    _ => {}
                },
                // Modal input handling
                InputMode::DescriptionEditModal => match key.code {
                    KeyCode::Enter => {
                        // Save description
                        if let Some(ref fingerprint) = app.modal_key_fingerprint {
                            let new_description = if app.modal_input_buffer.trim().is_empty() {
                                None
                            } else {
                                Some(app.modal_input_buffer.trim().to_string())
                            };

                            match set_key_description(
                                socket_path.as_ref(),
                                fingerprint,
                                new_description.as_deref().unwrap_or(""),
                            ) {
                                Ok(()) => {
                                    app.set_status("Description updated".to_string());
                                    // Refresh the keys list
                                    if let Err(e) = load_keys(app, socket_path.as_ref()) {
                                        app.set_status(format!("Failed to refresh keys: {}", e));
                                    }
                                }
                                Err(e) => {
                                    app.modal_error =
                                        Some(format!("Failed to update description: {}", e));
                                    continue;
                                }
                            }
                        }
                        app.close_modal();
                    }
                    KeyCode::Esc => {
                        app.close_modal();
                    }
                    KeyCode::Char(c) => {
                        app.modal_input_buffer.push(c);
                        app.modal_error = None;
                    }
                    KeyCode::Backspace => {
                        app.modal_input_buffer.pop();
                        app.modal_error = None;
                    }
                    _ => {}
                },
                InputMode::PasswordChangeModal => match key.code {
                    KeyCode::Enter => {
                        // Validate fields based on current field selection
                        if let Some(idx) = app.selected_key {
                            if idx < app.keys.len() {
                                let key = &app.keys[idx];
                                let fingerprint = key.fingerprint.clone();

                                // Validate passwords
                                let _old_password = if key.password_protected {
                                    if app.modal_input_buffer.is_empty() {
                                        app.modal_error =
                                            Some("Old password is required".to_string());
                                        continue;
                                    }
                                    Some(app.modal_input_buffer.as_str())
                                } else {
                                    None
                                };

                                if app.modal_input_buffer2.is_empty() {
                                    app.modal_error = Some("New password is required".to_string());
                                    continue;
                                }

                                if app.modal_input_buffer2.len() < 8 {
                                    app.modal_error =
                                        Some("Password must be at least 8 characters".to_string());
                                    continue;
                                }

                                if app.modal_input_buffer2 != app.modal_input_buffer3 {
                                    app.modal_error = Some("Passwords do not match".to_string());
                                    continue;
                                }

                                // Change password
                                match set_key_password(
                                    socket_path.as_ref(),
                                    &fingerprint,
                                    &app.modal_input_buffer2,
                                ) {
                                    Ok(()) => {
                                        app.set_status("Password updated".to_string());
                                        // Refresh the keys list
                                        if let Err(e) = load_keys(app, socket_path.as_ref()) {
                                            app.set_status(format!(
                                                "Failed to refresh keys: {}",
                                                e
                                            ));
                                        }
                                        app.close_modal();
                                    }
                                    Err(e) => {
                                        app.modal_error =
                                            Some(format!("Failed to change password: {}", e));
                                    }
                                }
                            }
                        }
                    }
                    KeyCode::Esc => {
                        app.close_modal();
                    }
                    KeyCode::Tab => {
                        app.modal_next_field();
                    }
                    KeyCode::BackTab => {
                        app.modal_previous_field();
                    }
                    KeyCode::Char(c) => {
                        let needs_old_password = app.selected_key
                            .and_then(|idx| app.keys.get(idx))
                            .map(|k| k.password_protected)
                            .unwrap_or(false);

                        match (app.modal_selected_field, needs_old_password) {
                            (0, true) => app.modal_input_buffer.push(c),   // Old
                            (0, false) => app.modal_input_buffer2.push(c), // New
                            (1, true) => app.modal_input_buffer2.push(c),  // New
                            (1, false) => app.modal_input_buffer3.push(c), // Confirm
                            (2, true) => app.modal_input_buffer3.push(c),  // Confirm
                            _ => {}
                        }
                        app.modal_error = None;
                    }
                    KeyCode::Backspace => {
                        let needs_old_password = app.selected_key
                            .and_then(|idx| app.keys.get(idx))
                            .map(|k| k.password_protected)
                            .unwrap_or(false);

                        match (app.modal_selected_field, needs_old_password) {
                            (0, true) => { app.modal_input_buffer.pop(); }
                            (0, false) => { app.modal_input_buffer2.pop(); }
                            (1, true) => { app.modal_input_buffer2.pop(); }
                            (1, false) => { app.modal_input_buffer3.pop(); }
                            (2, true) => { app.modal_input_buffer3.pop(); }
                            _ => {}
                        }
                        app.modal_error = None;
                    }
                    _ => {}
                },
                InputMode::ConfirmationSettingsModal => match key.code {
                    KeyCode::Enter => {
                        // Save confirmation settings
                        if let Some(fingerprint) = app.modal_key_fingerprint.clone() {
                            // Set runtime constraints if key is loaded
                            if let Some(idx) = app.selected_key {
                                if idx < app.keys.len() && app.keys[idx].loaded {
                                    let (confirm, notify) = app.modal_constraint_runtime.to_bools();

                                    // Get current lifetime to preserve it: compute
                                    // remaining seconds from the expiry timestamp.
                                    let current_lifetime = app.keys[idx]
                                        .constraints
                                        .get("lifetime_expires_at")
                                        .and_then(|v| v.as_str())
                                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                                        .and_then(|expires_at| {
                                            let secs = (expires_at.with_timezone(&chrono::Utc)
                                                - chrono::Utc::now())
                                                .num_seconds();
                                            if secs > 0 { Some(format!("{}s", secs)) } else { None }
                                        });


                                    match set_constraints(
                                        socket_path.as_ref(),
                                        &fingerprint,
                                        confirm,
                                        notify,
                                        current_lifetime.as_deref(), // Preserve existing lifetime
                                    ) {
                                        Ok(()) => {
                                            app.set_status(
                                                "Runtime constraints updated".to_string(),
                                            );
                                        }
                                        Err(e) => {
                                            app.modal_error = Some(format!(
                                                "Failed to update runtime constraints: {}",
                                                e
                                            ));
                                            continue;
                                        }
                                    }
                                }
                            }

                            // Set default constraints
                            let (confirm, notify) = app.modal_constraint_default.to_bools();

                            // Get current default lifetime to preserve it
                            let current_default_lifetime = if let Some(idx) = app.selected_key {
                                if idx < app.keys.len() {
                                    app.keys[idx]
                                        .default_constraints
                                        .as_ref()
                                        .and_then(|defaults| {
                                            defaults.get("default_lifetime_seconds")
                                        })
                                        .and_then(|v| v.as_u64())
                                        .filter(|&seconds| seconds > 0)
                                        .map(|seconds| format_lifetime_friendly(seconds as u32))
                                } else {
                                    None
                                }
                            } else {
                                None
                            };

                            match set_default_constraints(
                                socket_path.as_ref(),
                                &fingerprint,
                                confirm,
                                notify,
                                current_default_lifetime.as_deref(), // Preserve existing default lifetime
                            ) {
                                Ok(()) => {
                                    app.set_status("Confirmation settings updated".to_string());
                                    // Refresh the keys list
                                    if let Err(e) = load_keys(app, socket_path.as_ref()) {
                                        app.set_status(format!("Failed to refresh keys: {}", e));
                                    }
                                    app.close_modal();
                                }
                                Err(e) => {
                                    app.modal_error = Some(format!(
                                        "Failed to update default constraints: {}",
                                        e
                                    ));
                                }
                            }
                        }
                    }
                    KeyCode::Esc => {
                        app.close_modal();
                    }
                    KeyCode::Tab => {
                        // Navigate between sections (runtime vs default)
                        let key_loaded = app
                            .selected_key
                            .and_then(|idx| app.keys.get(idx))
                            .map(|k| k.loaded)
                            .unwrap_or(false);

                        if key_loaded {
                            // Switch between runtime (0-2) and default (3-5) sections
                            if app.modal_selected_field < 3 {
                                app.modal_selected_field = 3; // Jump to default section
                            } else {
                                app.modal_selected_field = 0; // Jump back to runtime section
                            }
                        }
                    }
                    KeyCode::BackTab => {
                        // Same as Tab but in reverse
                        let key_loaded = app
                            .selected_key
                            .and_then(|idx| app.keys.get(idx))
                            .map(|k| k.loaded)
                            .unwrap_or(false);

                        if key_loaded {
                            if app.modal_selected_field >= 3 {
                                app.modal_selected_field = 2; // Jump to end of runtime section
                            } else {
                                app.modal_selected_field = 5; // Jump to end of default section
                            }
                        }
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        // Navigate up within current section
                        let key_loaded = app
                            .selected_key
                            .and_then(|idx| app.keys.get(idx))
                            .map(|k| k.loaded)
                            .unwrap_or(false);

                        if key_loaded {
                            // Two sections: runtime (0-2) and default (3-5)
                            if app.modal_selected_field < 3 {
                                // In runtime section
                                app.modal_selected_field = if app.modal_selected_field == 0 {
                                    2
                                } else {
                                    app.modal_selected_field - 1
                                };
                            } else {
                                // In default section
                                app.modal_selected_field = if app.modal_selected_field == 3 {
                                    5
                                } else {
                                    app.modal_selected_field - 1
                                };
                            }
                        } else {
                            // Single section: default only (0-2)
                            app.modal_selected_field = if app.modal_selected_field == 0 {
                                2
                            } else {
                                app.modal_selected_field - 1
                            };
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        // Navigate down within current section
                        let key_loaded = app
                            .selected_key
                            .and_then(|idx| app.keys.get(idx))
                            .map(|k| k.loaded)
                            .unwrap_or(false);

                        if key_loaded {
                            // Two sections: runtime (0-2) and default (3-5)
                            if app.modal_selected_field < 3 {
                                // In runtime section
                                app.modal_selected_field = if app.modal_selected_field == 2 {
                                    0
                                } else {
                                    app.modal_selected_field + 1
                                };
                            } else {
                                // In default section
                                app.modal_selected_field = if app.modal_selected_field == 5 {
                                    3
                                } else {
                                    app.modal_selected_field + 1
                                };
                            }
                        } else {
                            // Single section: default only (0-2)
                            app.modal_selected_field = if app.modal_selected_field == 2 {
                                0
                            } else {
                                app.modal_selected_field + 1
                            };
                        }
                    }
                    KeyCode::Left | KeyCode::Char('h') => {
                        // In single-section mode, move between sections like Tab
                        let key_loaded = app
                            .selected_key
                            .and_then(|idx| app.keys.get(idx))
                            .map(|k| k.loaded)
                            .unwrap_or(false);

                        if key_loaded && app.modal_selected_field >= 3 {
                            app.modal_selected_field -= 3; // Move from default to runtime
                        }
                    }
                    KeyCode::Right | KeyCode::Char('l') => {
                        // In single-section mode, move between sections like Tab
                        let key_loaded = app
                            .selected_key
                            .and_then(|idx| app.keys.get(idx))
                            .map(|k| k.loaded)
                            .unwrap_or(false);

                        if key_loaded && app.modal_selected_field < 3 {
                            app.modal_selected_field += 3; // Move from runtime to default
                        }
                    }
                    KeyCode::Char(' ') => {
                        // Select the current radio button option
                        let key_loaded = app
                            .selected_key
                            .and_then(|idx| app.keys.get(idx))
                            .map(|k| k.loaded)
                            .unwrap_or(false);

                        if key_loaded {
                            // Two sections: runtime (0-2) and default (3-5)
                            match app.modal_selected_field {
                                0 => app.modal_constraint_runtime = ConstraintOption::None,
                                1 => app.modal_constraint_runtime = ConstraintOption::Notification,
                                2 => app.modal_constraint_runtime = ConstraintOption::Confirmation,
                                3 => app.modal_constraint_default = ConstraintOption::None,
                                4 => app.modal_constraint_default = ConstraintOption::Notification,
                                5 => app.modal_constraint_default = ConstraintOption::Confirmation,
                                _ => {}
                            }
                        } else {
                            // Single section: default only (0-2)
                            match app.modal_selected_field {
                                0 => app.modal_constraint_default = ConstraintOption::None,
                                1 => app.modal_constraint_default = ConstraintOption::Notification,
                                2 => app.modal_constraint_default = ConstraintOption::Confirmation,
                                _ => {}
                            }
                        }
                        app.modal_error = None;
                    }
                    _ => {}
                },
                InputMode::ExpirationSettingsModal => match key.code {
                    KeyCode::Enter => {
                        // Save expiration settings
                        if let Some(ref fingerprint) = app.modal_key_fingerprint {
                            let lifetime = if app.modal_lifetime_default.trim().is_empty() {
                                None
                            } else {
                                // Validate lifetime format
                                match parse_lifetime(&app.modal_lifetime_default) {
                                    Ok(_) => Some(app.modal_lifetime_default.clone()),
                                    Err(e) => {
                                        app.modal_error =
                                            Some(format!("Invalid lifetime format: {}", e));
                                        continue;
                                    }
                                }
                            };

                            // Get current default confirmation/notification settings to preserve them
                            let (current_confirm, current_notify) = if let Some(idx) =
                                app.selected_key
                            {
                                if idx < app.keys.len() {
                                    if let Some(ref defaults) = app.keys[idx].default_constraints {
                                        let confirm = defaults
                                            .get("default_confirm")
                                            .and_then(|v: &serde_json::Value| v.as_bool())
                                            .unwrap_or(false);
                                        let notify = defaults
                                            .get("default_notification")
                                            .and_then(|v| v.as_bool())
                                            .unwrap_or(false);
                                        (confirm, notify)
                                    } else {
                                        (false, false)
                                    }
                                } else {
                                    (false, false)
                                }
                            } else {
                                (false, false)
                            };

                            match set_default_constraints(
                                socket_path.as_ref(),
                                fingerprint,
                                current_confirm, // Preserve existing confirm setting
                                current_notify,  // Preserve existing notify setting
                                lifetime.as_deref(),
                            ) {
                                Ok(()) => {
                                    app.set_status("Expiration settings updated".to_string());
                                    // Refresh the keys list
                                    if let Err(e) = load_keys(app, socket_path.as_ref()) {
                                        app.set_status(format!("Failed to refresh keys: {}", e));
                                    }
                                    app.close_modal();
                                }
                                Err(e) => {
                                    app.modal_error = Some(format!(
                                        "Failed to update expiration settings: {}",
                                        e
                                    ));
                                }
                            }
                        }
                    }
                    KeyCode::Esc => {
                        app.close_modal();
                    }
                    KeyCode::Tab => {
                        app.modal_next_field();
                    }
                    KeyCode::BackTab => {
                        app.modal_previous_field();
                    }
                    KeyCode::Char('R') | KeyCode::Char('r') => {
                        // Reset timer functionality
                        if let Some(ref fingerprint) = app.modal_key_fingerprint {
                            if let Some(idx) = app.selected_key {
                                if idx < app.keys.len() && app.keys[idx].loaded {
                                    // Reset timer logic:
                                    // If default lifetime is set, reset timer to default
                                    // If no default, remove timer and clear default
                                    let default_lifetime = app.modal_lifetime_default.trim();

                                    if default_lifetime.is_empty() {
                                        // No default set - remove timer completely
                                        match set_constraints(
                                            socket_path.as_ref(),
                                            fingerprint,
                                            app.keys[idx]
                                                .constraints
                                                .get("confirm")
                                                .and_then(|v| v.as_bool())
                                                .unwrap_or(false),
                                            app.keys[idx]
                                                .constraints
                                                .get("notification")
                                                .and_then(|v| v.as_bool())
                                                .unwrap_or(false),
                                            None, // Remove lifetime
                                        ) {
                                            Ok(()) => {
                                                app.set_status("Timer removed".to_string());
                                            }
                                            Err(e) => {
                                                app.modal_error =
                                                    Some(format!("Failed to remove timer: {}", e));
                                                continue;
                                            }
                                        }
                                    } else {
                                        // Reset timer to default value
                                        match parse_lifetime(default_lifetime) {
                                            Ok(_) => {
                                                match set_constraints(
                                                    socket_path.as_ref(),
                                                    fingerprint,
                                                    app.keys[idx]
                                                        .constraints
                                                        .get("confirm")
                                                        .and_then(|v| v.as_bool())
                                                        .unwrap_or(false),
                                                    app.keys[idx]
                                                        .constraints
                                                        .get("notification")
                                                        .and_then(|v| v.as_bool())
                                                        .unwrap_or(false),
                                                    Some(default_lifetime),
                                                ) {
                                                    Ok(()) => {
                                                        app.set_status(format!(
                                                            "Timer reset to {}",
                                                            default_lifetime
                                                        ));
                                                    }
                                                    Err(e) => {
                                                        app.modal_error = Some(format!(
                                                            "Failed to reset timer: {}",
                                                            e
                                                        ));
                                                        continue;
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                app.modal_error = Some(format!(
                                                    "Invalid default lifetime: {}",
                                                    e
                                                ));
                                                continue;
                                            }
                                        }
                                    }

                                    // Refresh keys and close modal
                                    if let Err(e) = load_keys(app, socket_path.as_ref()) {
                                        app.set_status(format!("Failed to refresh keys: {}", e));
                                    }
                                    app.close_modal();
                                } else {
                                    app.modal_error =
                                        Some("Key must be loaded to reset timer".to_string());
                                }
                            }
                        }
                    }
                    KeyCode::Char(c) => {
                        if app.modal_selected_field == 0 {
                            app.modal_lifetime_default.push(c);
                            app.modal_error = None;
                        }
                    }
                    KeyCode::Backspace => {
                        if app.modal_selected_field == 0 {
                            app.modal_lifetime_default.pop();
                            app.modal_error = None;
                        }
                    }
                    _ => {}
                },
                InputMode::RemovePasswordModal => match key.code {
                    KeyCode::Enter => {
                        // Validate password is not empty
                        if app.modal_input_buffer.is_empty() {
                            app.modal_error = Some("Password cannot be empty".to_string());
                        } else if let Some(ref fingerprint) = app.key_being_protected.clone() {
                            // Try to remove password protection with the entered current password
                            if let Err(e) = remove_key_password(
                                socket_path.as_ref(),
                                fingerprint,
                                &app.modal_input_buffer,
                            ) {
                                app.modal_error = Some(format!("Failed to remove password: {}", e));
                            } else {
                                app.set_status("Password protection removed".to_string());
                                // Refresh keys
                                if let Err(e) = load_keys(app, socket_path.as_ref()) {
                                    app.set_status(format!("Failed to refresh keys: {}", e));
                                }
                                app.close_modal();
                            }
                        }
                    }
                    KeyCode::Esc => {
                        // Cancel password removal
                        app.close_modal();
                        app.set_status("Password removal cancelled".to_string());
                    }
                    KeyCode::Char(c) => {
                        // Add character to password buffer
                        app.modal_input_buffer.push(c);
                        app.modal_error = None; // Clear error on input
                    }
                    KeyCode::Backspace => {
                        // Remove character from password buffer
                        app.modal_input_buffer.pop();
                        app.modal_error = None; // Clear error on input
                    }
                    _ => {}
                },
                InputMode::SetKeyPasswordModal => match key.code {
                    KeyCode::Enter => {
                        // Validate passwords match and meet requirements
                        match app.modal_selected_field {
                            0 => {
                                // New password field - validate length and move to confirm
                                if app.modal_input_buffer.len() < 8 {
                                    app.modal_error =
                                        Some("Password must be at least 8 characters".to_string());
                                } else {
                                    app.modal_selected_field = 1; // Move to confirm field
                                    app.modal_error = None;
                                }
                            }
                            1 => {
                                // Confirm password field - validate match and save
                                if app.modal_input_buffer != app.modal_input_buffer2 {
                                    app.modal_error = Some("Passwords don't match".to_string());
                                } else if app.modal_input_buffer.len() < 8 {
                                    app.modal_error =
                                        Some("Password must be at least 8 characters".to_string());
                                } else if let Some(ref fingerprint) =
                                    app.modal_key_fingerprint.clone()
                                {
                                    // Set the key password
                                    if let Err(e) = set_key_password(
                                        socket_path.as_ref(),
                                        fingerprint,
                                        &app.modal_input_buffer,
                                    ) {
                                        app.modal_error =
                                            Some(format!("Failed to set password: {}", e));
                                    } else {
                                        app.set_status("Password protection enabled".to_string());
                                        // Refresh keys
                                        if let Err(e) = load_keys(app, socket_path.as_ref()) {
                                            app.set_status(format!(
                                                "Failed to refresh keys: {}",
                                                e
                                            ));
                                        }
                                        app.close_modal();
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    KeyCode::Esc => {
                        // Cancel password setting
                        app.close_modal();
                        app.set_status("Password protection cancelled".to_string());
                    }
                    KeyCode::Tab => {
                        // Navigate forward between fields
                        app.modal_next_field();
                        app.modal_error = None; // Clear error on field change
                    }
                    KeyCode::BackTab => {
                        // Navigate backward between fields (Shift+Tab)
                        app.modal_previous_field();
                        app.modal_error = None; // Clear error on field change
                    }
                    KeyCode::Char(c) => {
                        // Add character to appropriate buffer based on current field
                        match app.modal_selected_field {
                            0 => app.modal_input_buffer.push(c),  // New password
                            1 => app.modal_input_buffer2.push(c), // Confirm password
                            _ => {}
                        }
                        app.modal_error = None; // Clear error on input
                    }
                    KeyCode::Backspace => {
                        // Remove character from appropriate buffer
                        match app.modal_selected_field {
                            0 => {
                                app.modal_input_buffer.pop();
                            }
                            1 => {
                                app.modal_input_buffer2.pop();
                            }
                            _ => {}
                        }
                        app.modal_error = None; // Clear error on input
                    }
                    _ => {}
                },
                // Unified create key modal handler
                InputMode::CreateKeyModal => match key.code {
                    KeyCode::Enter => {
                        // Validate inputs and create key
                        let key_type = if app.create_key_selected_type == 0 {
                            "ed25519".to_string()
                        } else {
                            "rsa".to_string()
                        };

                        // Validate RSA bit length if RSA is selected
                        let bit_length = if app.create_key_selected_type == 1 {
                            match app.create_key_bit_length_str.parse::<u32>() {
                                Ok(bits) if bits >= 2048 && bits <= 8192 && bits % 8 == 0 => {
                                    Some(bits)
                                }
                                _ => {
                                    app.modal_error = Some(
                                        "Invalid bit length. Must be 2048-8192 and divisible by 8"
                                            .to_string(),
                                    );
                                    continue;
                                }
                            }
                        } else {
                            None
                        };

                        // Use the description from the modal
                        let description = if app.create_key_description.trim().is_empty() {
                            None
                        } else {
                            Some(app.create_key_description.trim().to_string())
                        };

                        // Close modal and initiate key creation
                        app.close_modal();

                        // Create the key
                        if let Err(e) =
                            create_key(socket_path.as_ref(), &key_type, bit_length, description)
                        {
                            app.set_status(format!("Failed to create key: {}", e));
                        } else {
                            app.set_status(format!(
                                "{} key{} created successfully",
                                if key_type == "ed25519" {
                                    "Ed25519"
                                } else {
                                    "RSA"
                                },
                                if let Some(bits) = bit_length {
                                    format!(" ({})", bits)
                                } else {
                                    String::new()
                                }
                            ));
                            // Refresh the keys list to show the new key
                            if let Err(e) = load_keys(app, socket_path.as_ref()) {
                                app.set_status(format!("Failed to refresh keys: {}", e));
                            }
                        }

                        // Set up for key creation (after using the values)
                        app.create_key_type = Some(key_type);
                        app.create_bit_length = bit_length;
                    }
                    KeyCode::Esc => {
                        // Cancel key creation
                        app.close_modal();
                        app.create_key_type = None;
                        app.create_bit_length = None;
                        app.set_status("Key creation cancelled".to_string());
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        // Navigate up through fields
                        if app.modal_selected_field > 0 {
                            app.modal_selected_field -= 1;
                        }
                        app.modal_error = None;
                    }
                    KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                        // Navigate down through fields
                        let max_field = if app.create_key_selected_type == 1 {
                            2
                        } else {
                            1
                        }; // RSA has bit length field
                        if app.modal_selected_field < max_field {
                            app.modal_selected_field += 1;
                        }
                        app.modal_error = None;
                    }
                    KeyCode::Char(' ') if app.modal_selected_field == 0 => {
                        // Toggle key type when on field 0
                        app.create_key_selected_type = if app.create_key_selected_type == 0 {
                            1
                        } else {
                            0
                        };
                        app.modal_error = None;
                    }
                    KeyCode::Char('e') | KeyCode::Char('E') if app.modal_selected_field == 0 => {
                        // Quick select Ed25519
                        app.create_key_selected_type = 0;
                        app.modal_error = None;
                    }
                    KeyCode::Char('r') | KeyCode::Char('R') if app.modal_selected_field == 0 => {
                        // Quick select RSA
                        app.create_key_selected_type = 1;
                        app.modal_error = None;
                    }
                    KeyCode::Char(c) => {
                        // Handle text input for bit length and description fields
                        let is_rsa = app.create_key_selected_type == 1;
                        if is_rsa && app.modal_selected_field == 1 {
                            // Bit length input (only allow digits)
                            if c.is_ascii_digit() {
                                app.create_key_bit_length_str.push(c);
                                app.modal_error = None;
                            }
                        } else if (is_rsa && app.modal_selected_field == 2)
                            || (!is_rsa && app.modal_selected_field == 1)
                        {
                            // Description input
                            if c.is_ascii() && !c.is_ascii_control() {
                                app.create_key_description.push(c);
                                app.modal_error = None;
                            }
                        }
                    }
                    KeyCode::Backspace => {
                        // Handle backspace for input fields
                        let is_rsa = app.create_key_selected_type == 1;
                        if is_rsa && app.modal_selected_field == 1 {
                            // Bit length input
                            app.create_key_bit_length_str.pop();
                            app.modal_error = None;
                        } else if (is_rsa && app.modal_selected_field == 2)
                            || (!is_rsa && app.modal_selected_field == 1)
                        {
                            // Description input
                            app.create_key_description.pop();
                            app.modal_error = None;
                        }
                    }
                    _ => {}
                },
                // Legacy modal input handlers (kept for backward compatibility)
                InputMode::CreateKeyTypeModal => match key.code {
                    KeyCode::Char('e') | KeyCode::Char('E') => {
                        app.create_key_type = Some("ed25519".to_string());
                        // Skip bit length for Ed25519, go straight to description
                        app.input_mode = InputMode::CreateKeyDescriptionModal;
                        app.modal_input_buffer.clear();
                        app.modal_error = None;
                    }
                    KeyCode::Char('r') | KeyCode::Char('R') => {
                        app.create_key_type = Some("rsa".to_string());
                        // Go to bit length selection for RSA
                        app.input_mode = InputMode::CreateKeyBitLengthModal;
                        app.modal_input_buffer = "2048".to_string(); // Default value
                        app.modal_error = None;
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        // Navigate up (Ed25519)
                        app.modal_selected_field = 0;
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        // Navigate down (RSA)
                        app.modal_selected_field = 1;
                    }
                    KeyCode::Enter | KeyCode::Char(' ') => {
                        // Select current option
                        if app.modal_selected_field == 0 {
                            app.create_key_type = Some("ed25519".to_string());
                            app.input_mode = InputMode::CreateKeyDescriptionModal;
                            app.modal_input_buffer.clear();
                            app.modal_error = None;
                        } else {
                            app.create_key_type = Some("rsa".to_string());
                            app.input_mode = InputMode::CreateKeyBitLengthModal;
                            app.modal_input_buffer = "2048".to_string();
                            app.modal_error = None;
                        }
                    }
                    KeyCode::Esc => {
                        // Cancel key creation
                        app.close_modal();
                        app.create_key_type = None;
                        app.create_bit_length = None;
                        app.set_status("Key creation cancelled".to_string());
                    }
                    _ => {}
                },
                InputMode::CreateKeyBitLengthModal => match key.code {
                    KeyCode::Enter => {
                        // Validate bit length input
                        match app.modal_input_buffer.parse::<u32>() {
                            Ok(bits) if bits >= 2048 && bits <= 8192 => {
                                app.create_bit_length = Some(bits);
                                app.input_mode = InputMode::CreateKeyDescriptionModal;
                                app.modal_input_buffer.clear();
                                app.modal_error = None;
                            }
                            Ok(_) => {
                                app.modal_error =
                                    Some("Bit length must be between 2048 and 8192".to_string());
                            }
                            Err(_) => {
                                app.modal_error = Some("Invalid number format".to_string());
                            }
                        }
                    }
                    KeyCode::Esc => {
                        // Cancel key creation
                        app.close_modal();
                        app.create_key_type = None;
                        app.create_bit_length = None;
                        app.set_status("Key creation cancelled".to_string());
                    }
                    KeyCode::Char(c) if c.is_ascii_digit() => {
                        // Add digit (limit to 4 digits for reasonable bit lengths)
                        if app.modal_input_buffer.len() < 4 {
                            app.modal_input_buffer.push(c);
                            app.modal_error = None; // Clear error on input
                        }
                    }
                    KeyCode::Backspace => {
                        // Remove last digit
                        app.modal_input_buffer.pop();
                        app.modal_error = None; // Clear error on input
                    }
                    _ => {}
                },
                InputMode::CreateKeyDescriptionModal => match key.code {
                    KeyCode::Enter => {
                        // Create the key with current settings
                        let description = if app.modal_input_buffer.trim().is_empty() {
                            None
                        } else {
                            Some(app.modal_input_buffer.trim().to_string())
                        };

                        if let (Some(key_type), socket_path) =
                            (app.create_key_type.as_ref(), socket_path.as_ref())
                        {
                            let result = if key_type == "ed25519" {
                                create_key(socket_path, key_type, None, description)
                            } else if key_type == "rsa" {
                                let bit_length = app.create_bit_length.unwrap_or(2048);
                                create_key(socket_path, key_type, Some(bit_length), description)
                            } else {
                                Err("Invalid key type".into())
                            };

                            match result {
                                Ok(()) => {
                                    app.set_status(format!(
                                        "Created {} key successfully",
                                        key_type
                                    ));
                                    // Refresh keys list
                                    if let Err(e) = load_keys(app, socket_path) {
                                        app.set_status(format!(
                                            "Key created but failed to refresh list: {}",
                                            e
                                        ));
                                    }
                                    app.close_modal();
                                    app.create_key_type = None;
                                    app.create_bit_length = None;
                                }
                                Err(e) => {
                                    app.modal_error = Some(format!("Failed to create key: {}", e));
                                }
                            }
                        } else {
                            app.modal_error = Some("Missing key type or socket path".to_string());
                        }
                    }
                    KeyCode::Esc => {
                        // Cancel key creation
                        app.close_modal();
                        app.create_key_type = None;
                        app.create_bit_length = None;
                        app.set_status("Key creation cancelled".to_string());
                    }
                    KeyCode::Char(c) => {
                        // Add character to description
                        app.modal_input_buffer.push(c);
                        app.modal_error = None; // Clear error on input
                    }
                    KeyCode::Backspace => {
                        // Remove last character
                        app.modal_input_buffer.pop();
                        app.modal_error = None; // Clear error on input
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
    let size = f.area();

    // Handle authentication modal first - override everything else
    if app.input_mode == InputMode::AuthenticationRequired {
        render_auth_modal(f, app, size);
        return;
    }

    // Create the main 3-frame layout
    // First split: horizontal division for main content vs status bar
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(10),   // Main content area (keys + info panel)
            Constraint::Length(3), // Status bar
        ])
        .split(size);

    // Second split: horizontal division for keys list vs info panel
    let content_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(60), // Keys list (left/center)
            Constraint::Percentage(40), // Info panel (right)
        ])
        .split(main_chunks[0]);

    // Render the three frames
    render_keys_list(f, app, content_chunks[0]); // Frame 1: Keys list
    render_info_panel(f, app, content_chunks[1]); // Frame 2: Info panel 
    render_status_bar(f, app, main_chunks[1]); // Frame 3: Status bar

    // Handle modal dialogs
    if matches!(
        app.input_mode,
        InputMode::DescriptionEditModal
            | InputMode::PasswordChangeModal
            | InputMode::ConfirmationSettingsModal
            | InputMode::ExpirationSettingsModal
            | InputMode::RemovePasswordModal
            | InputMode::KeyPasswordModal
            | InputMode::SetKeyPasswordModal
            | InputMode::CreateKeyModal
            | InputMode::CreateKeyTypeModal
            | InputMode::CreateKeyBitLengthModal
            | InputMode::CreateKeyDescriptionModal
    ) {
        render_modal(f, app);
    }

    // Handle input areas for different input modes (legacy non-modal inputs)
    if matches!(
        app.input_mode,
        InputMode::Password
            | InputMode::Description
            | InputMode::Certificate
            | InputMode::CreateKeyType  // Keep old mode for now (fallback)
            | InputMode::CreateBitLength  // Keep old mode for now (fallback)
            | InputMode::CreateDescription  // Keep old mode for now (fallback)
            | InputMode::ImportKeyPassword
            | InputMode::ImportKeyPasswordConfirm
            | InputMode::DefaultLifetimeInput
    ) {
        // Create overlay for input when needed
        render_input_overlay(f, app, size);
    }
}

/// Render input overlay for various input modes
fn render_input_overlay(f: &mut Frame, app: &App, size: ratatui::layout::Rect) {
    // Create a centered popup area
    let popup_area = centered_rect(60, 20, size);

    let input_block = match app.input_mode {
        InputMode::Password => Block::default()
            .title("Master Password")
            .borders(Borders::ALL),
        InputMode::Description => Block::default().title("Description").borders(Borders::ALL),
        InputMode::Certificate => Block::default().title("Certificate").borders(Borders::ALL),
        InputMode::CreateKeyType => Block::default().title("Key Type").borders(Borders::ALL),
        InputMode::CreateBitLength => Block::default().title("Bit Length").borders(Borders::ALL),
        InputMode::CreateDescription => Block::default()
            .title("Key Description")
            .borders(Borders::ALL),
        InputMode::ImportKeyPassword => Block::default()
            .title("Import Key Password")
            .borders(Borders::ALL),
        InputMode::ImportKeyPasswordConfirm => Block::default()
            .title("Confirm Import Key Password")
            .borders(Borders::ALL),
        InputMode::DefaultConstraints => Block::default()
            .title("Default Constraints")
            .borders(Borders::ALL),
        InputMode::DefaultLifetimeInput => Block::default()
            .title("Default Lifetime")
            .borders(Borders::ALL),
        _ => Block::default().title("Input").borders(Borders::ALL),
    };

    let input_text = match app.input_mode {
        InputMode::Password
        | InputMode::ImportKeyPassword
        | InputMode::ImportKeyPasswordConfirm => "*".repeat(app.input_buffer.len()),
        _ => app.input_buffer.clone(),
    };

    // Clear the background for the popup
    f.render_widget(ratatui::widgets::Clear, popup_area);

    let input_paragraph = Paragraph::new(input_text)
        .block(input_block)
        .style(Style::default().bg(Color::Black));

    f.render_widget(input_paragraph, popup_area);
}

fn render_modal(f: &mut Frame, app: &App) {
    let size = f.area();

    // Adjust overlay size based on modal type
    let overlay_area = match app.input_mode {
        InputMode::DescriptionEditModal => centered_rect(60, 20, size),
        InputMode::PasswordChangeModal => centered_rect(50, 40, size),
        InputMode::ConfirmationSettingsModal => centered_rect(80, 50, size),
        InputMode::ExpirationSettingsModal => centered_rect(60, 40, size),
        InputMode::RemovePasswordModal => centered_rect(50, 30, size),
        InputMode::KeyPasswordModal => centered_rect(50, 30, size),
        InputMode::SetKeyPasswordModal => centered_rect(50, 40, size),
        InputMode::CreateKeyModal => centered_rect(70, 60, size), // New unified modal
        InputMode::CreateKeyTypeModal => centered_rect(60, 30, size),
        InputMode::CreateKeyBitLengthModal => centered_rect(60, 30, size),
        InputMode::CreateKeyDescriptionModal => centered_rect(60, 30, size),
        _ => centered_rect(50, 50, size),
    };

    // Clear the overlay area
    f.render_widget(Clear, overlay_area);

    match app.input_mode {
        InputMode::DescriptionEditModal => render_description_modal(f, app, overlay_area),
        InputMode::PasswordChangeModal => render_password_modal(f, app, overlay_area),
        InputMode::ConfirmationSettingsModal => render_confirmation_modal(f, app, overlay_area),
        InputMode::ExpirationSettingsModal => render_expiration_modal(f, app, overlay_area),
        InputMode::RemovePasswordModal => render_remove_password_modal(f, app, overlay_area),
        InputMode::KeyPasswordModal => render_key_password_modal(f, app, overlay_area),
        InputMode::SetKeyPasswordModal => render_set_key_password_modal(f, app, overlay_area),
        InputMode::CreateKeyModal => render_create_key_modal(f, app, overlay_area), // New unified modal
        InputMode::CreateKeyTypeModal => render_create_key_type_modal(f, app, overlay_area),
        InputMode::CreateKeyBitLengthModal => {
            render_create_key_bit_length_modal(f, app, overlay_area)
        }
        InputMode::CreateKeyDescriptionModal => {
            render_create_key_description_modal(f, app, overlay_area)
        }
        _ => {}
    }
}

fn render_description_modal(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Edit Description ")
        .border_style(Style::default().fg(Color::Cyan))
        .bg(Color::Black);

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Split into input area, error area, and button area
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // Input field (now horizontal)
            Constraint::Length(1), // Spacer
            Constraint::Length(2), // Error message
            Constraint::Length(3), // Buttons
            Constraint::Min(1),    // Remaining space
        ])
        .split(inner);

    // Input field (horizontal)
    let cursor_pos = render_horizontal_input(
        f,
        chunks[0],
        "Description",
        &app.modal_input_buffer,
        true,  // always focused in this modal
        false, // not a password field
    );

    // Error message
    if let Some(ref error) = app.modal_error {
        let error_paragraph = Paragraph::new(error.as_str()).style(Style::default().fg(Color::Red));
        f.render_widget(error_paragraph, chunks[2]);
    }

    // Buttons
    let buttons = Paragraph::new("Press Enter to Save, Esc to Cancel")
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::Gray));
    f.render_widget(buttons, chunks[3]);

    // Set cursor position
    f.set_cursor_position(Position::new(cursor_pos.0, cursor_pos.1));
}

fn render_password_modal(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Change Password ")
        .border_style(Style::default().fg(Color::Cyan))
        .bg(Color::Black);

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Determine if we need old password field
    let needs_old_password = app
        .selected_key
        .and_then(|idx| app.keys.get(idx))
        .map(|k| k.password_protected)
        .unwrap_or(false);

    let field_count = if needs_old_password { 3 } else { 2 };
    let mut constraints = vec![Constraint::Length(1); field_count]; // Each input field is now 1 line
    constraints.push(Constraint::Length(1)); // Spacer
    constraints.push(Constraint::Length(2)); // Error area  
    constraints.push(Constraint::Length(3)); // Buttons
    constraints.push(Constraint::Min(1)); // Remaining space

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    let mut chunk_idx = 0;
    let mut cursor_pos = (0, 0);

    // Old password field (if needed)
    if needs_old_password {
        let is_focused = app.modal_selected_field == 0;
        cursor_pos = render_horizontal_input(
            f,
            chunks[chunk_idx],
            "Old password",
            &app.modal_input_buffer,
            is_focused,
            true, // is_password
        );
        chunk_idx += 1;
    }

    // New password field
    let new_password_field_idx = if needs_old_password { 1 } else { 0 };
    let is_focused = app.modal_selected_field == new_password_field_idx;
    let new_cursor_pos = render_horizontal_input(
        f,
        chunks[chunk_idx],
        "New password",
        &app.modal_input_buffer2,
        is_focused,
        true, // is_password
    );
    if is_focused {
        cursor_pos = new_cursor_pos;
    }
    chunk_idx += 1;

    // Confirm password field
    let confirm_password_field_idx = if needs_old_password { 2 } else { 1 };
    let is_focused = app.modal_selected_field == confirm_password_field_idx;
    let confirm_cursor_pos = render_horizontal_input(
        f,
        chunks[chunk_idx],
        "Confirm password",
        &app.modal_input_buffer3,
        is_focused,
        true, // is_password
    );
    if is_focused {
        cursor_pos = confirm_cursor_pos;
    }
    chunk_idx += 1;

    // Skip spacer
    chunk_idx += 1;

    // Error message
    if let Some(ref error) = app.modal_error {
        let error_paragraph = Paragraph::new(error.as_str()).style(Style::default().fg(Color::Red));
        f.render_widget(error_paragraph, chunks[chunk_idx]);
    }
    chunk_idx += 1;

    // Buttons
    let buttons = Paragraph::new("Press Enter to Change, Esc to Cancel, Tab to navigate")
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::Gray));
    f.render_widget(buttons, chunks[chunk_idx]);

    // Set cursor position for the focused field
    f.set_cursor_position(Position::new(cursor_pos.0, cursor_pos.1));
}

/// Render confirmation settings modal with radio button interface
fn render_confirmation_modal(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Confirmation Settings ")
        .border_style(Style::default().fg(Color::Cyan))
        .bg(Color::Black);

    let inner = block.inner(area);
    f.render_widget(block, inner);

    // Check if key is loaded to determine layout
    let key_loaded = app
        .selected_key
        .and_then(|idx| app.keys.get(idx))
        .map(|k| k.loaded)
        .unwrap_or(false);

    let _sections = if key_loaded { 2 } else { 1 };
    let _total_fields = if key_loaded { 6 } else { 3 }; // 3 options per section

    if key_loaded {
        // Two-section layout: Runtime (left) and Default (right)
        let main_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(50), // Runtime settings
                Constraint::Percentage(50), // Default settings
            ])
            .split(inner);

        // Determine which section is active
        let runtime_active = app.modal_selected_field < 3;
        let default_active = app.modal_selected_field >= 3;

        // Runtime settings (left)
        let runtime_block = Block::default()
            .borders(Borders::ALL)
            .title("Current Runtime (if loaded)")
            .border_style(if runtime_active {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::White)
            });

        let runtime_inner = runtime_block.inner(main_chunks[0]);
        f.render_widget(runtime_block, main_chunks[0]);

        let runtime_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // None option
                Constraint::Length(1), // Notification option
                Constraint::Length(1), // Confirmation option
                Constraint::Min(1),    // Spacer
            ])
            .split(runtime_inner);

        // Render runtime radio buttons
        render_radio_option(
            f,
            runtime_chunks[0],
            "None",
            app.modal_constraint_runtime == ConstraintOption::None,
            app.modal_selected_field == 0,
        );
        render_radio_option(
            f,
            runtime_chunks[1],
            "Notification",
            app.modal_constraint_runtime == ConstraintOption::Notification,
            app.modal_selected_field == 1,
        );
        render_radio_option(
            f,
            runtime_chunks[2],
            "Confirmation",
            app.modal_constraint_runtime == ConstraintOption::Confirmation,
            app.modal_selected_field == 2,
        );

        // Default settings (right)
        let default_block = Block::default()
            .borders(Borders::ALL)
            .title("Default for Future Loads")
            .border_style(if default_active {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::White)
            });

        let default_inner = default_block.inner(main_chunks[1]);
        f.render_widget(default_block, main_chunks[1]);

        let default_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // None option
                Constraint::Length(1), // Notification option
                Constraint::Length(1), // Confirmation option
                Constraint::Min(1),    // Spacer
            ])
            .split(default_inner);

        // Render default radio buttons
        render_radio_option(
            f,
            default_chunks[0],
            "None",
            app.modal_constraint_default == ConstraintOption::None,
            app.modal_selected_field == 3,
        );
        render_radio_option(
            f,
            default_chunks[1],
            "Notification",
            app.modal_constraint_default == ConstraintOption::Notification,
            app.modal_selected_field == 4,
        );
        render_radio_option(
            f,
            default_chunks[2],
            "Confirmation",
            app.modal_constraint_default == ConstraintOption::Confirmation,
            app.modal_selected_field == 5,
        );
    } else {
        // Single section layout for default settings only
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(2), // Title
                Constraint::Length(1), // None option
                Constraint::Length(1), // Notification option
                Constraint::Length(1), // Confirmation option
                Constraint::Min(1),    // Spacer
            ])
            .split(inner);

        let title = Paragraph::new("Default for Future Loads")
            .alignment(Alignment::Center)
            .style(
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            );
        f.render_widget(title, chunks[0]);

        // Render default radio buttons
        render_radio_option(
            f,
            chunks[1],
            "None",
            app.modal_constraint_default == ConstraintOption::None,
            app.modal_selected_field == 0,
        );
        render_radio_option(
            f,
            chunks[2],
            "Notification",
            app.modal_constraint_default == ConstraintOption::Notification,
            app.modal_selected_field == 1,
        );
        render_radio_option(
            f,
            chunks[3],
            "Confirmation",
            app.modal_constraint_default == ConstraintOption::Confirmation,
            app.modal_selected_field == 2,
        );
    }

    // Error message at bottom
    if let Some(ref error) = app.modal_error {
        let error_area = Rect::new(area.x + 2, area.y + area.height - 4, area.width - 4, 1);
        let error_paragraph = Paragraph::new(error.as_str()).style(Style::default().fg(Color::Red));
        f.render_widget(error_paragraph, error_area);
    }

    // Help text at bottom
    let help_area = Rect::new(area.x + 2, area.y + area.height - 2, area.width - 4, 1);
    let help_text = if key_loaded {
        "Arrow keys/hjkl: Navigate, Space/Enter: Select, Tab: Switch sections, Enter: Save, Esc: Cancel"
    } else {
        "Arrow keys/hjkl: Navigate, Space/Enter: Select, Enter: Save, Esc: Cancel"
    };
    let help = Paragraph::new(help_text)
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::Gray));
    f.render_widget(help, help_area);
}

/// Helper function to render a single radio button option
fn render_radio_option(f: &mut Frame, area: Rect, label: &str, selected: bool, highlighted: bool) {
    let symbol = if selected { "●" } else { "○" };
    let text = format!("{} {}", symbol, label);

    let style = if highlighted {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else if selected {
        Style::default().fg(Color::Green)
    } else {
        Style::default().fg(Color::White)
    };

    let paragraph = Paragraph::new(text).style(style).alignment(Alignment::Left);
    f.render_widget(paragraph, area);
}

fn render_expiration_modal(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Expiration Settings ")
        .border_style(Style::default().fg(Color::Cyan))
        .bg(Color::Black);

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Show current countdown timer if key is loaded and has timer
    let key_loaded = app
        .selected_key
        .and_then(|idx| app.keys.get(idx))
        .map(|k| k.loaded)
        .unwrap_or(false);

    let mut constraints = vec![];

    if key_loaded {
        constraints.push(Constraint::Length(3)); // Current timer display
    }
    constraints.push(Constraint::Length(1)); // Input field (horizontal)
    constraints.push(Constraint::Length(1)); // Spacer
    constraints.push(Constraint::Length(2)); // Error area
    constraints.push(Constraint::Length(3)); // Buttons
    constraints.push(Constraint::Min(1)); // Remaining space

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    let mut chunk_idx = 0;

    // Current timer display (if loaded)
    if key_loaded {
        if let Some(idx) = app.selected_key {
            if let Some(key) = app.keys.get(idx) {
                let timer_text = if key.constraints.is_object() {
                    if key.constraints.get("lifetime").is_some() {
                        format!("Current Timer: {} remaining", get_ttl_display(key).map_or("⏳", |v| v.0))

                    } else {
                        "Current Timer: No expiration set".to_string()
                    }
                } else {
                    "Current Timer: No constraints active".to_string()
                };

                let timer_display = Paragraph::new(timer_text)
                    .alignment(Alignment::Center)
                    .style(Style::default().fg(Color::Blue));
                f.render_widget(timer_display, chunks[chunk_idx]);
            }
        }
        chunk_idx += 1;
    }

    // Default lifetime input field (horizontal)
    let is_focused = app.modal_selected_field == 0;
    let input_value = if app.modal_lifetime_default.is_empty() {
        "" // Don't show placeholder in horizontal layout
    } else {
        &app.modal_lifetime_default
    };

    let cursor_pos = render_horizontal_input(
        f,
        chunks[chunk_idx],
        "Default expiration (e.g. 2h, 30m, 1d)",
        input_value,
        is_focused,
        false, // not a password field
    );
    chunk_idx += 1;

    // Skip spacer
    chunk_idx += 1;

    // Error message
    if let Some(ref error) = app.modal_error {
        let error_paragraph = Paragraph::new(error.as_str()).style(Style::default().fg(Color::Red));
        f.render_widget(error_paragraph, chunks[chunk_idx]);
    }
    chunk_idx += 1;

    // Buttons
    let button_text = if key_loaded {
        "R to Reset Timer, Enter to Save, Esc to Cancel"
    } else {
        "Enter to Save, Esc to Cancel"
    };

    let buttons = Paragraph::new(button_text)
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::Gray));
    f.render_widget(buttons, chunks[chunk_idx]);

    // Set cursor position for the focused input field
    if is_focused {
        f.set_cursor_position(Position::new(cursor_pos.0, cursor_pos.1));
    }
}

/// Helper function to create a centered rectangle for popups
fn render_remove_password_modal(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Remove Password Protection ")
        .border_style(Style::default().fg(Color::Red))
        .bg(Color::Black);

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Split into message area and input area
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // Message text
            Constraint::Length(1), // Spacer
            Constraint::Length(1), // Password input
            Constraint::Length(1), // Spacer
            Constraint::Length(2), // Error area
            Constraint::Length(3), // Instructions
            Constraint::Min(1),    // Remaining space
        ])
        .split(inner);

    // Message text
    let key_fingerprint = app
        .modal_key_fingerprint
        .as_ref()
        .map(|f| &f[0..16])
        .unwrap_or("unknown");

    let message = vec![
        Line::from(format!(
            "Removing password protection from key {}",
            key_fingerprint
        )),
        Line::from(""),
    ];

    let message_paragraph = Paragraph::new(message)
        .alignment(ratatui::layout::Alignment::Center)
        .style(Style::default().fg(Color::White));
    f.render_widget(message_paragraph, chunks[0]);

    // Password input field
    let cursor_pos = render_horizontal_input(
        f,
        chunks[2],
        "Enter current password",
        &app.modal_input_buffer,
        true, // always focused since it's the only field
        true, // is_password (masked)
    );

    // Error message
    if let Some(ref error) = app.modal_error {
        let error_paragraph = Paragraph::new(error.as_str())
            .style(Style::default().fg(Color::Red))
            .alignment(Alignment::Center);
        f.render_widget(error_paragraph, chunks[4]);
    }

    // Instructions
    let instructions = vec![
        Line::from("Press Enter to remove password protection"),
        Line::from("Press Esc to cancel"),
        Line::from(""),
    ];

    let instructions_paragraph = Paragraph::new(instructions)
        .alignment(ratatui::layout::Alignment::Center)
        .style(Style::default().fg(Color::Gray));
    f.render_widget(instructions_paragraph, chunks[5]);

    // Set cursor position for the password input field
    f.set_cursor_position(Position::new(cursor_pos.0, cursor_pos.1));
}

/// Render key password modal for loading password-protected keys
fn render_key_password_modal(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Enter Key Password ")
        .border_style(Style::default().fg(Color::Cyan))
        .bg(Color::Black);

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Split into compact sections
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // Compact explanation text
            Constraint::Length(1), // Password input
            Constraint::Length(1), // Spacer
            Constraint::Length(2), // Error area
            Constraint::Length(1), // Instructions
            Constraint::Min(1),    // Remaining space
        ])
        .split(inner);

    // Compact explanation text
    let explanation = vec![
        Line::from("Enter password for"),
        Line::from("protected key:"),
    ];

    let explanation_paragraph = Paragraph::new(explanation)
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::White));
    f.render_widget(explanation_paragraph, chunks[0]);

    // Password input field
    let cursor_pos = render_horizontal_input(
        f,
        chunks[1],
        "Password",
        &app.input_buffer,
        true, // always focused since it's the only field
        true, // is_password (masked)
    );

    // Error message
    if let Some(ref error) = app.modal_error {
        let error_paragraph = Paragraph::new(error.as_str())
            .style(Style::default().fg(Color::Red))
            .alignment(Alignment::Center);
        f.render_widget(error_paragraph, chunks[3]);
    }

    // Compact instructions
    let instructions_paragraph = Paragraph::new("Enter: OK   ESC: Cancel")
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::Gray));
    f.render_widget(instructions_paragraph, chunks[4]);

    // Set cursor position for the password input field
    f.set_cursor_position(Position::new(cursor_pos.0, cursor_pos.1));
}

fn render_set_key_password_modal(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Set Key Password ")
        .border_style(Style::default().fg(Color::Cyan))
        .bg(Color::Black);

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Two-field layout: new password + confirm password
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // New password input
            Constraint::Length(1), // Confirm password input
            Constraint::Length(1), // Spacer
            Constraint::Length(2), // Error area
            Constraint::Length(1), // Instructions
            Constraint::Min(1),    // Remaining space
        ])
        .split(inner);

    // Always calculate both cursor positions but only use the focused one
    let new_focused = app.modal_selected_field == 0;
    let new_cursor_pos = render_horizontal_input(
        f,
        chunks[0],
        "New password",
        &app.modal_input_buffer,
        new_focused,
        true, // is_password
    );

    let confirm_focused = app.modal_selected_field == 1;
    let confirm_cursor_pos = render_horizontal_input(
        f,
        chunks[1],
        "Confirm password",
        &app.modal_input_buffer2,
        confirm_focused,
        true, // is_password
    );

    // Select the cursor position based on the focused field
    let cursor_pos = if new_focused {
        new_cursor_pos
    } else if confirm_focused {
        confirm_cursor_pos
    } else {
        // Default to new password field if somehow neither is focused
        new_cursor_pos
    };

    // Error message
    if let Some(ref error) = app.modal_error {
        let error_paragraph = Paragraph::new(error.as_str())
            .style(Style::default().fg(Color::Red))
            .alignment(Alignment::Center);
        f.render_widget(error_paragraph, chunks[3]);
    }

    // Instructions
    let instructions_paragraph = Paragraph::new("Enter: Save   ESC: Cancel   Tab: Navigate")
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::Gray));
    f.render_widget(instructions_paragraph, chunks[4]);

    // Set cursor position for the focused field
    f.set_cursor_position(Position::new(cursor_pos.0, cursor_pos.1));
}

/// Render create key type selection modal
fn render_create_key_type_modal(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Create Key - Select Type ")
        .border_style(Style::default().fg(Color::Cyan))
        .bg(Color::Black);

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Layout: title + options + spacer + error area (flexible)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // Title text
            Constraint::Length(1), // Ed25519 option
            Constraint::Length(1), // RSA option
            Constraint::Min(1),    // Flexible spacer
        ])
        .split(inner);

    // Title text
    let title_text = vec![Line::from("Choose key type:"), Line::from("")];
    let title_paragraph = Paragraph::new(title_text)
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::White));
    f.render_widget(title_paragraph, chunks[0]);

    // Ed25519 option
    let ed25519_style = if app.modal_selected_field == 0 {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::White)
    };
    let ed25519_paragraph = Paragraph::new("E) Ed25519 (recommended)")
        .style(ed25519_style)
        .alignment(Alignment::Center);
    f.render_widget(ed25519_paragraph, chunks[1]);

    // RSA option
    let rsa_style = if app.modal_selected_field == 1 {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::White)
    };
    let rsa_paragraph = Paragraph::new("R) RSA (legacy compatibility)")
        .style(rsa_style)
        .alignment(Alignment::Center);
    f.render_widget(rsa_paragraph, chunks[2]);

    // Error message at bottom (consistent with other dialogs)
    if let Some(ref error) = app.modal_error {
        let error_area = Rect::new(area.x + 2, area.y + area.height - 4, area.width - 4, 1);
        let error_paragraph = Paragraph::new(error.as_str())
            .style(Style::default().fg(Color::Red))
            .alignment(Alignment::Center);
        f.render_widget(error_paragraph, error_area);
    }

    // Help text at bottom (consistent with other dialogs)
    let help_area = Rect::new(area.x + 2, area.y + area.height - 2, area.width - 4, 1);
    let help_text = "E: Ed25519, R: RSA, Enter: Select, Esc: Cancel";
    let help = Paragraph::new(help_text)
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::Gray));
    f.render_widget(help, help_area);
}

/// Render RSA bit length selection modal
fn render_create_key_bit_length_modal(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Create RSA Key - Select Bit Length ")
        .border_style(Style::default().fg(Color::Cyan))
        .bg(Color::Black);

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Layout: title + input field + suggestions + spacer
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // Title text
            Constraint::Length(1), // Input field (horizontal)
            Constraint::Length(2), // Suggestions
            Constraint::Min(1),    // Flexible spacer
        ])
        .split(inner);

    // Title text
    let title_text = vec![Line::from("Enter RSA key size:"), Line::from("")];
    let title_paragraph = Paragraph::new(title_text)
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::White));
    f.render_widget(title_paragraph, chunks[0]);

    // Input field (horizontal)
    let cursor_pos = render_horizontal_input(
        f,
        chunks[1],
        "Bit length",
        &app.modal_input_buffer,
        true,  // always focused since it's the only field
        false, // not a password field
    );

    // Suggestions
    let suggestions_text = vec![
        Line::from("Common sizes: 2048, 3072, 4096"),
        Line::from("Range: 2048-8192 bits"),
    ];
    let suggestions_paragraph = Paragraph::new(suggestions_text)
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::Blue));
    f.render_widget(suggestions_paragraph, chunks[2]);

    // Error message at bottom (consistent with other dialogs)
    if let Some(ref error) = app.modal_error {
        let error_area = Rect::new(area.x + 2, area.y + area.height - 4, area.width - 4, 1);
        let error_paragraph = Paragraph::new(error.as_str())
            .style(Style::default().fg(Color::Red))
            .alignment(Alignment::Center);
        f.render_widget(error_paragraph, error_area);
    }

    // Help text at bottom (consistent with other dialogs)
    let help_area = Rect::new(area.x + 2, area.y + area.height - 2, area.width - 4, 1);
    let help_text = "Enter: Continue, Esc: Cancel (Default: 2048 bits)";
    let help = Paragraph::new(help_text)
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::Gray));
    f.render_widget(help, help_area);

    // Set cursor position for the input field
    f.set_cursor_position(Position::new(cursor_pos.0, cursor_pos.1));
}

/// Render key description input modal
fn render_create_key_description_modal(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Create Key - Description ")
        .border_style(Style::default().fg(Color::Cyan))
        .bg(Color::Black);

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Layout: title + input field + spacer
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Title text
            Constraint::Length(1), // Input field (horizontal)
            Constraint::Min(1),    // Flexible spacer
        ])
        .split(inner);

    // Title text
    let key_type_text = app.create_key_type.as_deref().unwrap_or("unknown");
    let bit_length_text = if let Some(bits) = app.create_bit_length {
        format!(" ({})", bits)
    } else {
        String::new()
    };

    let title_text = vec![
        Line::from(format!("Creating {} key{}", key_type_text, bit_length_text)),
        Line::from(""),
        Line::from("Enter description (optional):"),
    ];
    let title_paragraph = Paragraph::new(title_text)
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::White));
    f.render_widget(title_paragraph, chunks[0]);

    // Input field (horizontal)
    let cursor_pos = render_horizontal_input(
        f,
        chunks[1],
        "Description",
        &app.modal_input_buffer,
        true,  // always focused since it's the only field
        false, // not a password field
    );

    // Error message at bottom (consistent with other dialogs)
    if let Some(ref error) = app.modal_error {
        let error_area = Rect::new(area.x + 2, area.y + area.height - 4, area.width - 4, 1);
        let error_paragraph = Paragraph::new(error.as_str())
            .style(Style::default().fg(Color::Red))
            .alignment(Alignment::Center);
        f.render_widget(error_paragraph, error_area);
    }

    // Help text at bottom (consistent with other dialogs)
    let help_area = Rect::new(area.x + 2, area.y + area.height - 2, area.width - 4, 1);
    let help_text = "Enter: Create Key, Esc: Cancel (Leave empty for no description)";
    let help = Paragraph::new(help_text)
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::Gray));
    f.render_widget(help, help_area);

    // Set cursor position for the input field
    f.set_cursor_position(Position::new(cursor_pos.0, cursor_pos.1));
}

/// Render unified create key modal with all options in one dialog
fn render_create_key_modal(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Create New Key ")
        .border_style(Style::default().fg(Color::Cyan))
        .bg(Color::Black);

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Layout: title + key type selection + bit length (if RSA) + description + spacer + help
    let is_rsa = app.create_key_selected_type == 1;
    let mut constraints = vec![
        Constraint::Length(2), // Title text
        Constraint::Length(3), // Key type selection (2 options + label)
    ];

    if is_rsa {
        constraints.push(Constraint::Length(2)); // RSA bit length input (label + input)
    }

    constraints.extend_from_slice(&[
        Constraint::Length(2), // Description input (label + input)
        Constraint::Length(1), // Spacer
        Constraint::Length(2), // Error area
        Constraint::Length(3), // Button area
        Constraint::Min(1),    // Remaining space
    ]);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    let mut chunk_idx = 0;
    let mut cursor_pos = (0, 0);

    // Title text
    let title_text = vec![Line::from("Create a new SSH key"), Line::from("")];
    let title_paragraph = Paragraph::new(title_text)
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::White));
    f.render_widget(title_paragraph, chunks[chunk_idx]);
    chunk_idx += 1;

    // Key type selection
    let type_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // Label
            Constraint::Length(1), // Ed25519 option
            Constraint::Length(1), // RSA option
        ])
        .split(chunks[chunk_idx]);

    // Type selection label
    let type_focused = app.modal_selected_field == 0;
    let type_label_style = if type_focused {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::White)
    };
    f.render_widget(
        Paragraph::new("Key Type:").style(type_label_style),
        type_chunks[0],
    );

    // Ed25519 option
    render_radio_option(
        f,
        type_chunks[1],
        "Ed25519 (recommended)",
        app.create_key_selected_type == 0,
        app.modal_selected_field == 0,
    );

    // RSA option
    render_radio_option(
        f,
        type_chunks[2],
        "RSA (legacy compatibility)",
        app.create_key_selected_type == 1,
        app.modal_selected_field == 0,
    );
    chunk_idx += 1;

    // RSA bit length input (only if RSA is selected)
    if is_rsa {
        let bit_length_focused = app.modal_selected_field == 1;
        let new_cursor_pos = render_horizontal_input(
            f,
            chunks[chunk_idx],
            "Bit Length",
            &app.create_key_bit_length_str,
            bit_length_focused,
            false, // not a password
        );
        if bit_length_focused {
            cursor_pos = new_cursor_pos;
        }
        chunk_idx += 1;
    }

    // Description input
    let desc_field_idx = if is_rsa { 2 } else { 1 };
    let desc_focused = app.modal_selected_field == desc_field_idx;
    let new_cursor_pos = render_horizontal_input(
        f,
        chunks[chunk_idx],
        "Description (optional)",
        &app.create_key_description,
        desc_focused,
        false, // not a password
    );
    if desc_focused {
        cursor_pos = new_cursor_pos;
    }
    chunk_idx += 1;

    // Skip spacer
    chunk_idx += 1;

    // Error message
    if let Some(ref error) = app.modal_error {
        let error_paragraph = Paragraph::new(error.as_str())
            .style(Style::default().fg(Color::Red))
            .alignment(Alignment::Center);
        f.render_widget(error_paragraph, chunks[chunk_idx]);
    }
    chunk_idx += 1;

    // Button area
    let button_text = vec![
        Line::from(""),
        Line::from("Enter: Create Key    Esc: Cancel"),
        Line::from("↑↓: Navigate    Tab: Next Field"),
    ];
    let button_paragraph = Paragraph::new(button_text)
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::Gray));
    f.render_widget(button_paragraph, chunks[chunk_idx]);

    // Set cursor position if an input field is focused
    if app.modal_selected_field > 0 {
        f.set_cursor_position(Position::new(cursor_pos.0, cursor_pos.1));
    }
}

fn centered_rect(
    percent_x: u16,
    percent_y: u16,
    r: ratatui::layout::Rect,
) -> ratatui::layout::Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

/// Renders a horizontal input field with inline label
/// Returns the cursor position (x, y) for proper cursor placement
fn render_horizontal_input(
    f: &mut Frame,
    area: Rect,
    label: &str,
    value: &str,
    is_focused: bool,
    is_password: bool,
) -> (u16, u16) {
    let label_text = format!("{}: ", label);
    let label_width = label_text.len() as u16;

    // Calculate available input width
    let input_width = area.width.saturating_sub(label_width + 1); // -1 for right border

    // Create the display text (masked if password)
    let display_text = if is_password {
        "*".repeat(value.len())
    } else {
        value.to_string()
    };

    // Create underline for input area
    let underline = "_".repeat(input_width as usize);

    // Combine label and input with underline
    let combined_text = if display_text.is_empty() {
        format!("{}{}", label_text, underline)
    } else {
        // Show text over underline, pad remaining with underlines
        let remaining_underlines = input_width.saturating_sub(display_text.len() as u16);
        format!(
            "{}{}{}",
            label_text,
            display_text,
            "_".repeat(remaining_underlines as usize)
        )
    };

    // Style based on focus
    let style = if is_focused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::White)
    };

    // Render the horizontal input line
    let paragraph = Paragraph::new(combined_text)
        .style(style)
        .alignment(Alignment::Left);
    f.render_widget(paragraph, area);

    // Calculate cursor position (at end of actual text)
    let cursor_x = area.x + label_width + value.len() as u16;
    let cursor_y = area.y;

    (cursor_x, cursor_y)
}

fn render_auth_modal(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    // Clear the screen with a dark background
    let background = Block::default().style(Style::default().bg(Color::Black));
    f.render_widget(background, area);

    // Create compact centered modal to match other password modals
    let modal_area = centered_rect(50, 40, area);

    // Modal block with professional styling
    let modal_block = Block::default()
        .title(" Authentication Required ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .bg(Color::Black);

    let inner = modal_block.inner(modal_area);
    f.render_widget(modal_block, modal_area);

    // Split into compact sections matching other modals
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // Compact explanation text
            Constraint::Length(1), // Password input
            Constraint::Length(1), // Spacer
            Constraint::Length(2), // Error area
            Constraint::Length(1), // Instructions
            Constraint::Min(1),    // Remaining space
        ])
        .split(inner);

    // Compact explanation text
    let explanation = vec![
        Line::from("Enter master password"),
        Line::from("to unlock agent:"),
    ];

    let explanation_paragraph = Paragraph::new(explanation)
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::White));
    f.render_widget(explanation_paragraph, chunks[0]);

    // Password input field (using the same horizontal style as other modals)
    let cursor_pos = render_horizontal_input(
        f,
        chunks[1],
        "Password",
        &app.auth_password,
        true, // always focused
        true, // is_password
    );

    // Error message (if any)
    if let Some(ref error) = app.auth_error {
        let error_paragraph = Paragraph::new(error.as_str())
            .style(Style::default().fg(Color::Red))
            .alignment(Alignment::Center);
        f.render_widget(error_paragraph, chunks[3]);
    }

    // Compact instructions matching other modals
    let instructions_paragraph = Paragraph::new("Enter: OK   ESC: Exit")
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::Gray));
    f.render_widget(instructions_paragraph, chunks[4]);

    // Set cursor position
    f.set_cursor_position(ratatui::layout::Position::new(cursor_pos.0, cursor_pos.1));
}

/// Get the loaded status icon and color based on source and loaded state
fn get_loaded_icon(source: &str, loaded: bool) -> (String, Color) {
    match source {
        "external" => ("↗".to_string(), Color::Blue),
        _ => {
            if loaded {
                ("●".to_string(), Color::Green)
            } else {
                ("○".to_string(), Color::Gray)
            }
        }
    }
}

/// Get the protected status icon and color
fn get_protected_icon(password_protected: bool) -> Option<(&'static str, Color)> {
    if password_protected {
        Some(("🔐", Color::Green))
    } else {
        None
    }
}

/// Get confirmation/notification icon and color, or space for alignment
fn get_confirmation_notification_icon(confirm: bool, notification: bool) -> (String, Color) {
    if confirm {
        ("⚠".to_string(), Color::Yellow)
    } else if notification {
        ("✉".to_string(), Color::Cyan)
    } else {
        // Return space to maintain consistent alignment
        (" ".to_string(), Color::White)
    }
}

/// Get constraint state (confirm, notification) from key runtime or default constraints
fn get_constraint_state(key: &KeyInfo) -> (bool, bool) {
    // Check runtime constraints first
    if !key.constraints.is_null() && key.constraints.as_object().unwrap().len() > 0 {
        let confirm = key
            .constraints
            .get("confirm")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let notification = key
            .constraints
            .get("notification")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        return (confirm, notification);
    }

    // Fall back to default constraints if key has disk storage
    if key.has_disk {
        if let Some(default_constraints) = &key.default_constraints {
            let default_confirm = default_constraints
                .get("default_confirm")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let default_notification = default_constraints
                .get("default_notification")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            return (default_confirm, default_notification);
        }
    }

    (false, false)
}

/// Get TTL (time-to-live) display and color - returns only icon for key list
fn get_ttl_display(key: &KeyInfo) -> Option<(&'static str, Color)> {
    // Check runtime constraints for active lifetime
    if !key.constraints.is_null() && key.constraints.as_object().map_or(false, |o| !o.is_empty()) {
        if let Some(lifetime_remaining) = calculate_remaining_lifetime(&key.constraints) {
            let color = if lifetime_remaining == "EXPIRED" {
                Color::Red
            } else if lifetime_remaining.contains("s")
                && !lifetime_remaining.contains("m")
                && !lifetime_remaining.contains("h")
                && !lifetime_remaining.contains("d")
            {
                Color::Yellow // Less than a minute
            } else {
                Color::Green // Active and counting down
            };
            return Some(("⏳", color));
        }
    }

    // Check default constraints for inactive lifetime
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

    // No TTL configured
    None
}

/// Format fingerprint in short format: First N chars...Last N chars
fn format_short_fingerprint(fingerprint: &str) -> String {
    // Remove any prefix like "SHA256:" if present
    let clean_fingerprint = if fingerprint.starts_with("SHA256:") {
        &fingerprint[7..]
    } else {
        fingerprint
    };

    // Use first 8 and last 8 characters for readability
    let len = clean_fingerprint.len();
    if len <= 20 {
        // If short enough, show the whole thing
        clean_fingerprint.to_string()
    } else {
        format!(
            "{}...{}",
            &clean_fingerprint[..8],
            &clean_fingerprint[len - 8..]
        )
    }
}

/// Format datetime string for display
/// Converts ISO format to more readable format
fn format_datetime(datetime_str: &str) -> String {
    // If it's already in a nice format, return as-is
    if datetime_str.len() <= 16 {
        return datetime_str.to_string();
    }

    // Try to parse ISO format and convert to YYYY-MM-DD HH:MM
    if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(datetime_str) {
        parsed.format("%Y-%m-%d %H:%M").to_string()
    } else if datetime_str.contains('T') {
        // Handle basic ISO format without timezone
        let parts: Vec<&str> = datetime_str.split('T').collect();
        if parts.len() == 2 {
            let date = parts[0];
            let time_part = parts[1].split('.').next().unwrap_or(parts[1]);
            let time = if time_part.len() >= 5 {
                &time_part[..5]
            } else {
                time_part
            };
            format!("{} {}", date, time)
        } else {
            datetime_str.to_string()
        }
    } else {
        datetime_str.to_string()
    }
}

/// Render the main keys list frame (left/center)
fn render_keys_list(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    // Get the fingerprint of the key currently being edited for constraints (if any)
    let editing_fingerprint = match &app.constraint_context {
        ConstraintContext::Load(fp) => Some(fp.as_str()),
        _ => None,
    };

    // Convert keys to list items with new icon display format
    let keys: Vec<ListItem> = app
        .keys
        .iter()
        .map(|key| {
            let mut spans = Vec::new();

            // Check if this key is currently being edited for constraints
            let is_being_edited = editing_fingerprint
                .map(|fp| fp == key.fingerprint)
                .unwrap_or(false);

            // Build the display line according to specification:
            // <icon-loaded> <icon-protected> <icon-confirmation-or-notification> <icon-ttl> <short-key-fingerprint> <key-description>

            // 1. Icon-loaded
            let (loaded_icon, loaded_color) = get_loaded_icon(&key.source, key.loaded);
            spans.push(Span::styled(loaded_icon, Style::default().fg(loaded_color)));
            spans.push(Span::raw(" "));

            // 2. Icon-protected
            if let Some((protected_icon, protected_color)) = get_protected_icon(key.password_protected) {
                spans.push(Span::styled(
                    protected_icon,
                    Style::default().fg(protected_color),
                ));
            } else {
                spans.push(Span::raw("  ")); // 2 spaces to match 🔐 width
            }


            spans.push(Span::raw(" "));

            // 3. Icon-confirmation-or-notification (get current state, considering editing)
            let (confirm, notification) = if is_being_edited {
                // Use editing state
                (app.constraint_confirm, app.constraint_notification)
            } else {
                // Use runtime or default constraints
                get_constraint_state(key)
            };

            // 3. Icon-confirmation-or-notification (always add for consistent alignment)
            let (conf_icon, conf_color) = get_confirmation_notification_icon(confirm, notification);
            spans.push(Span::styled(conf_icon, Style::default().fg(conf_color)));
            spans.push(Span::raw(" "));

            // 4. Icon-ttl (time-to-live/expiration)
            if is_being_edited {
                let (ttl_str, ttl_color) = if let Some(lifetime) = &app.constraint_lifetime {
                    (format!("⏳ {}", lifetime), Color::Magenta)
                } else {
                    ("⏳".to_string(), Color::Gray)
                };
                spans.push(Span::styled(ttl_str, Style::default().fg(ttl_color)));
                spans.push(Span::raw(" "));
            } else if let Some((ttl_display, ttl_color)) = get_ttl_display(key) {
                spans.push(Span::styled(ttl_display, Style::default().fg(ttl_color)));
                spans.push(Span::raw(" "));
            } else {
                spans.push(Span::raw("   ")); // 2 spaces for ⏳ width + 1 separator
            }




            // 5. Short-key-fingerprint (First N chars...Last N chars format)
            let short_fingerprint = format_short_fingerprint(&key.fingerprint);
            spans.push(Span::styled(
                short_fingerprint,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ));

            // 6. Key-description (if present)
            if !key.description.is_empty() {
                spans.push(Span::raw(" "));
                spans.push(Span::styled(
                    key.description.clone(),
                    Style::default()
                        .fg(Color::Gray)
                        .add_modifier(Modifier::ITALIC),
                ));
            }

            ListItem::new(Line::from(spans))
        })
        .collect();

    // Determine title based on active frame focus
    let title = if app.active_frame == ActiveFrame::KeysList {
        "SSH Keys [FOCUSED]"
    } else {
        "SSH Keys"
    };

    let keys_list = List::new(keys)
        .block(Block::default().title(title).borders(Borders::ALL))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        );

    // Only render with selection highlight if this frame is focused
    if app.active_frame == ActiveFrame::KeysList {
        f.render_stateful_widget(keys_list, area, &mut app.list_state.clone());
    } else {
        f.render_widget(keys_list, area);
    }
}

/// Render the status bar frame (bottom)
fn render_status_bar(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let status_text = app.status_message.as_deref().unwrap_or("Ready");

    // Determine status bar style based on status type
    let (status_color, border_color) = match app.status_type {
        StatusType::Success => (Color::Green, Color::Green),
        StatusType::Error => (Color::Red, Color::Red),
        StatusType::Info => (Color::White, Color::White),
    };

    let status_paragraph = Paragraph::new(status_text)
        .block(
            Block::default()
                .title("Status")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color)),
        )
        .style(Style::default().fg(status_color));

    f.render_widget(status_paragraph, area);
}

/// Render the information panel frame (right side)
fn render_info_panel(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    match app.info_panel_content {
        InfoPanelContent::KeyDetails => render_key_details_panel(f, app, area),
        InfoPanelContent::Help => render_help_panel(f, app, area),
    }
}

/// Render key details in the info panel
fn render_key_details_panel(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let title = if app.active_frame == ActiveFrame::InfoPanel {
        "Key Details [FOCUSED]"
    } else {
        "Key Details"
    };

    if let Some(selected_idx) = app.selected_key {
        if let Some(key) = app.keys.get(selected_idx) {
            let mut details = Vec::new();

            // Key Details Header
            details.push(Line::from(vec![Span::styled(
                "Key Details",
                Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            )]));
            details.push(Line::from(""));

            // Description field (editable)
            let description_style = if app.active_frame == ActiveFrame::InfoPanel
                && app.selected_info_field == InfoPanelField::Description
            {
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            let description_text = if key.description.is_empty() {
                "[No description]"
            } else {
                &key.description
            };

            details.push(Line::from(vec![
                Span::styled(
                    "Description:     ",
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::styled(description_text, description_style),
            ]));

            // Password field (read-only)
            let password_style = if app.active_frame == ActiveFrame::InfoPanel
                && app.selected_info_field == InfoPanelField::Password
            {
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            let password_status = if key.password_protected {
                "Protected"
            } else {
                "Not protected"
            };

            details.push(Line::from(vec![
                Span::styled(
                    "Password:        ",
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    password_status,
                    password_style.fg(if key.password_protected {
                        Color::Yellow
                    } else {
                        Color::Green
                    }),
                ),
            ]));

            // Created field (read-only)
            if let Some(created) = &key.created {
                details.push(Line::from(vec![
                    Span::styled(
                        "Created:         ",
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(format_datetime(created)),
                ]));
            }

            // Updated field (read-only)
            if let Some(updated) = &key.updated {
                details.push(Line::from(vec![
                    Span::styled(
                        "Updated:         ",
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(format_datetime(updated)),
                ]));
            }

            // Confirmation field (editable)
            let confirmation_style = if app.active_frame == ActiveFrame::InfoPanel
                && app.selected_info_field == InfoPanelField::Confirmation
            {
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            // Get current confirmation setting from constraints
            let current_confirm = key
                .constraints
                .get("confirm")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let current_notification = key
                .constraints
                .get("notification")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let confirmation_text = match (current_confirm, current_notification) {
                (true, _) => "Confirm",
                (false, true) => "Notify",
                _ => "None",
            };

            // Get default from key's default constraints - only show if defaults are actually stored
            let default_text = if let Some(default_constraints) = &key.default_constraints {
                // Check if any defaults are actually set
                let default_confirm = default_constraints
                    .get("default_confirm")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let default_notification = default_constraints
                    .get("default_notification")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                // Only show defaults if they differ from the system default (notification enabled)
                match (default_confirm, default_notification) {
                    (true, _) => " (default: Confirm)",
                    (false, true) => " (default: Notify)",
                    (false, false) => " (default: None)",
                }
            } else {
                "" // No stored defaults, don't show anything
            };

            details.push(Line::from(vec![
                Span::styled(
                    "Confirmation:    ",
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::styled(confirmation_text, confirmation_style),
                Span::styled(default_text, Style::default().fg(Color::DarkGray)),
            ]));

            // Expiration field (editable)
            let expiration_style = if app.active_frame == ActiveFrame::InfoPanel
                && app.selected_info_field == InfoPanelField::Expiration
            {
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            // Get current lifetime from constraints
            let lifetime_text =
                if let Some(remaining) = calculate_remaining_lifetime(&key.constraints) {
                    if remaining == "EXPIRED" {
                        remaining
                    } else {
                        format!("{} remaining", remaining)
                    }
                } else {
                    "None".to_string()
                };

            // Get default lifetime - only show if actually set in key metadata
            let mut lifetime_spans = vec![
                Span::styled(
                    "Expiration:      ",
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::styled(&lifetime_text, expiration_style),
            ];

            // Only add default text if it exists
            if let Some(default_seconds) = key
                .default_constraints
                .as_ref()
                .and_then(|dc| dc.get("default_lifetime_seconds"))
                .and_then(|v| v.as_u64())
            {
                let default_text = format!(
                    " (default: {})",
                    format_lifetime_friendly(default_seconds as u32)
                );
                lifetime_spans.push(Span::styled(
                    default_text,
                    Style::default().fg(Color::DarkGray),
                ));
            }

            details.push(Line::from(lifetime_spans));

            details.push(Line::from(""));

            // Additional key information (read-only)
            details.push(Line::from(vec![Span::styled(
                "Technical Details",
                Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            )]));
            details.push(Line::from(""));

            details.push(Line::from(vec![
                Span::styled(
                    "Fingerprint: ",
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::raw(&key.fingerprint),
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
                    Span::styled("🔓 Loaded", Style::default().fg(Color::Green))
                } else {
                    Span::styled("🔒 Not Loaded", Style::default().fg(Color::Red))
                },
            ]));

            if key.has_cert {
                details.push(Line::from(vec![
                    Span::styled(
                        "Certificate: ",
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::styled("Present", Style::default().fg(Color::Green)),
                ]));
            }

            // Navigation hint
            if app.active_frame == ActiveFrame::InfoPanel {
                details.push(Line::from(""));
                details.push(Line::from(vec![
                    Span::styled("Navigate: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled("↑/↓ arrows", Style::default().fg(Color::Cyan)),
                ]));
            }

            let details_paragraph = Paragraph::new(details)
                .block(Block::default().title(title).borders(Borders::ALL))
                .wrap(Wrap { trim: true });

            f.render_widget(details_paragraph, area);
        } else {
            let no_key_paragraph = Paragraph::new("No key selected")
                .block(Block::default().title(title).borders(Borders::ALL));

            f.render_widget(no_key_paragraph, area);
        }
    } else {
        let no_key_paragraph = Paragraph::new("No key selected")
            .block(Block::default().title(title).borders(Borders::ALL));

        f.render_widget(no_key_paragraph, area);
    }
}

/// Render help/keybindings in the info panel
fn render_help_panel(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let title = if app.active_frame == ActiveFrame::InfoPanel {
        "Help [FOCUSED]"
    } else {
        "Help"
    };

    let help_text = vec![
        Line::from(vec![Span::styled(
            "Navigation:",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from("j/↓ - Move down"),
        Line::from("k/↑ - Move up"),
        Line::from("Tab - Switch frames"),
        Line::from("h - Toggle help/details"),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Key Management:",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from("L - Load disk key"),
        Line::from("U - Unload key from memory"),
        Line::from("i - Import external key"),
        Line::from("n - Create new key"),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Key Operations:",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from("e - Edit description"),
        Line::from("C - Update certificate"),
        Line::from("P - Set password protection"),
        Line::from("R - Remove password protection"),
        Line::from("D - Set default constraints"),
        Line::from("d - Delete key (PERMANENT)"),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Agent Control:",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from("r/F5 - Refresh key list"),
        Line::from("u - Unlock agent"),
        Line::from("l - Lock agent"),
        Line::from("q - Quit"),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Indicators:",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from("🔓 - Key loaded in memory"),
        Line::from("🔒 - Key not loaded"),
        Line::from("🛡️ - Password protected"),
        Line::from("[C] - Confirm required"),
        Line::from("[N] - Desktop notification"),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Colors:",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![
            Span::styled("Green", Style::default().fg(Color::Green)),
            Span::raw(" - Stored keys"),
        ]),
        Line::from(vec![
            Span::styled("Yellow", Style::default().fg(Color::Yellow)),
            Span::raw(" - External keys"),
        ]),
        Line::from(vec![
            Span::styled("Red", Style::default().fg(Color::Red)),
            Span::raw(" - Active constraints"),
        ]),
        Line::from(vec![
            Span::styled("Blue", Style::default().fg(Color::Blue)),
            Span::raw(" - Default constraints"),
        ]),
    ];

    let help_paragraph = Paragraph::new(help_text)
        .block(Block::default().title(title).borders(Borders::ALL))
        .wrap(Wrap { trim: true });

    f.render_widget(help_paragraph, area);
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

            let mut keys: Vec<KeyInfo> = keys_data
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
                    default_constraints: k.default_constraints,
                    created: k.created,
                    updated: k.updated,
                })
                .collect();

            // Remember the currently selected key fingerprint before sorting
            let selected_fingerprint = app
                .selected_key
                .and_then(|idx| app.keys.get(idx))
                .map(|key| key.fingerprint.clone());

            // Sort keys alphabetically by description
            keys.sort_by(|a, b| a.description.cmp(&b.description));

            app.keys = keys;

            // Update selection - preserve current selection by fingerprint, otherwise select first key
            if !app.keys.is_empty() {
                let selected_idx = if let Some(fingerprint) = selected_fingerprint {
                    // Find the key with the same fingerprint after sorting
                    app.keys
                        .iter()
                        .position(|k| k.fingerprint == fingerprint)
                        .unwrap_or(0) // Fallback to first key if fingerprint not found
                } else {
                    0 // Default to first key if no selection
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

    // Build proper LOCK message with empty passphrase string
    let mut message = Vec::new();
    message.push(rssh_proto::messages::SSH_AGENTC_LOCK);

    // Add empty passphrase string (4 bytes length + 0 bytes data)
    message.extend_from_slice(&[0, 0, 0, 0]);

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

    if response[0] != rssh_proto::messages::SSH_AGENT_SUCCESS {
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
    load_disk_key_with_constraints(socket_path, fingerprint, key_password, false, false, None)
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
    notification: bool,
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
            notification: Option<bool>,
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
            notification: if notification { Some(true) } else { None },
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
            return Err(cbor_error_msg(&cbor_response.data).into());

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
    notification: bool,
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
            notification: Option<bool>,
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
            notification: if notification { Some(true) } else { None },
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
            } else {
                app.set_status("Key loaded with default constraints".to_string());
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
                    app.input_mode = InputMode::KeyPasswordModal;
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
    if response.is_empty() {
        return Err("Empty response from agent".into());
    }

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
            return Err(cbor_error_msg(&cbor_response.data).into());

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
            return Err(cbor_error_msg(&cbor_response.data).into());

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

fn set_constraints(
    socket_path: Option<&String>,
    fingerprint: &str,
    confirm: bool,
    notification: bool,
    lifetime: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = socket_path
        .cloned()
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
        .ok_or("No socket path available")?;

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(&socket)?;

    // Build CBOR request for manage.set_constraints
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

        let lifetime_seconds = if let Some(lifetime_str) = lifetime {
            Some(parse_lifetime(lifetime_str)? as u64)
        } else {
            None
        };

        let req = SetConstraintsRequest {
            fp_sha256_hex: fingerprint.to_string(),
            confirm,
            notification,
            lifetime_seconds,
        };

        let mut cbor = Vec::new();
        ciborium::into_writer(&req, &mut cbor)?;
        cbor
    };

    let request = ExtensionRequest {
        extension: "manage.set_constraints".to_string(),
        data: set_constraints_data,
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
            return Err(cbor_error_msg(&cbor_response.data).into());

        }

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
    let socket = socket_path
        .cloned()
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
        .ok_or("No socket path available")?;

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(&socket)?;

    // Build CBOR request for manage.set_default_constraints
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

        let default_lifetime_seconds = if let Some(lifetime_str) = default_lifetime {
            Some(parse_lifetime(lifetime_str)? as u64)
        } else {
            None
        };

        let req = SetDefaultConstraintsRequest {
            fp_sha256_hex: fingerprint.to_string(),
            default_confirm,
            default_notification,
            default_lifetime_seconds,
        };

        let mut cbor = Vec::new();
        ciborium::into_writer(&req, &mut cbor)?;
        cbor
    };

    let request = ExtensionRequest {
        extension: "manage.set_default_constraints".to_string(),
        data: set_defaults_data,
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
            return Err(cbor_error_msg(&cbor_response.data).into());

        }

        Ok(())
    } else {
        Err("Failed to set default constraints".into())
    }
}

/// Extract a human-readable error message from a CBOR extension response payload.
/// The payload is a CBOR-encoded JSON value of the form:
///   {"ok": false, "error": {"code": "...", "msg": "..."}}
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

