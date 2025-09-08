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
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub fingerprint: String,
    pub key_type: String,
    pub comment: String,
    pub locked: bool,
    pub last_used: Option<SystemTime>,
    pub use_count: u64,
    pub constraints: Vec<String>,
    pub is_external: bool,
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
}

#[derive(PartialEq)]
pub enum InputMode {
    Normal,
    Password,
    Confirm,
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

        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
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
                            if let Some(idx) = app.selected_key {
                                if idx < app.keys.len() {
                                    app.input_mode = InputMode::Confirm;
                                    app.set_status(format!(
                                        "Delete key {}? (y/n)",
                                        app.keys[idx].fingerprint
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
                        KeyCode::Char('i') => {
                            // Import selected external key
                            if let Some(idx) = app.selected_key {
                                if idx < app.keys.len() {
                                    let key = &app.keys[idx];
                                    // Check if key is external (can be imported)
                                    if !key.is_external {
                                        app.set_status("Only external keys (added via ssh-add) can be imported".to_string());
                                    } else if let Err(e) =
                                        import_key(socket_path.as_ref(), &key.fingerprint)
                                    {
                                        app.set_status(format!("Failed to import key: {}", e));
                                    } else {
                                        app.set_status("Key imported successfully".to_string());
                                        if let Err(e) = load_keys(app, socket_path.as_ref()) {
                                            app.set_status(format!("Failed to refresh: {}", e));
                                        }
                                    }
                                }
                            }
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
                    InputMode::Confirm => match key.code {
                        KeyCode::Char('y') | KeyCode::Char('Y') => {
                            if let Some(idx) = app.selected_key {
                                if idx < app.keys.len() {
                                    if let Err(e) =
                                        remove_key(socket_path.as_ref(), &app.keys[idx].fingerprint)
                                    {
                                        app.set_status(format!("Failed to remove key: {}", e));
                                    } else {
                                        app.set_status("Key removed".to_string());
                                        if let Err(e) = load_keys(app, socket_path.as_ref()) {
                                            app.set_status(format!("Failed to refresh: {}", e));
                                        }
                                    }
                                }
                            }
                            app.input_mode = InputMode::Normal;
                        }
                        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                            app.input_mode = InputMode::Normal;
                            app.clear_status();
                        }
                        _ => {}
                    },
                }
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
            Line::from(vec![
                Span::styled("j/↓", Style::default().fg(Color::Yellow)),
                Span::raw("    Move down"),
            ]),
            Line::from(vec![
                Span::styled("k/↑", Style::default().fg(Color::Yellow)),
                Span::raw("    Move up"),
            ]),
            Line::from(vec![
                Span::styled("d/Del", Style::default().fg(Color::Yellow)),
                Span::raw("  Remove selected key"),
            ]),
            Line::from(vec![
                Span::styled("l", Style::default().fg(Color::Yellow)),
                Span::raw("      Lock agent"),
            ]),
            Line::from(vec![
                Span::styled("u", Style::default().fg(Color::Yellow)),
                Span::raw("      Unlock agent"),
            ]),
            Line::from(vec![
                Span::styled("r/F5", Style::default().fg(Color::Yellow)),
                Span::raw("   Refresh key list"),
            ]),
            Line::from(vec![
                Span::styled("a", Style::default().fg(Color::Yellow)),
                Span::raw("      Add key (hint)"),
            ]),
            Line::from(vec![
                Span::styled("i", Style::default().fg(Color::Yellow)),
                Span::raw("      Import external key to storage"),
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
                let mut spans = vec![
                    Span::styled(
                        format!("{} ", if key.locked { "🔒" } else { "🔓" }),
                        Style::default(),
                    ),
                    Span::styled(
                        if key.is_external { "[EXT]" } else { "[INT]" },
                        Style::default().fg(if key.is_external {
                            Color::Cyan
                        } else {
                            Color::Gray
                        }),
                    ),
                    Span::raw(" "),
                    Span::styled(&key.key_type, Style::default().fg(Color::Green)),
                    Span::raw(" "),
                ];

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

                if !key.comment.is_empty() {
                    spans.push(Span::raw(format!(" ({})", key.comment)));
                }

                if let Some(last_used) = key.last_used {
                    if let Ok(elapsed) = SystemTime::now().duration_since(last_used) {
                        let mins = elapsed.as_secs() / 60;
                        spans.push(Span::styled(
                            format!(" [{}m ago]", mins),
                            Style::default().fg(Color::DarkGray),
                        ));
                    }
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
        .map(|s| s.clone())
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
                    fingerprint: k.fingerprint,
                    key_type: k.key_type,
                    comment: k.comment,
                    locked: k.locked,
                    last_used: k
                        .last_used
                        .map(|ts| SystemTime::UNIX_EPOCH + Duration::from_secs(ts)),
                    use_count: k.use_count,
                    constraints: k.constraints,
                    is_external: k.is_external,
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
        .map(|s| s.clone())
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
        .map(|s| s.clone())
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
    _socket_path: Option<&String>,
    _fingerprint: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // This would use SSH_AGENTC_REMOVE_IDENTITY
    // For now, return an error since we need the actual key blob
    Err("Key removal requires the original key blob (use ssh-add -d)".into())
}

fn import_key(
    socket_path: Option<&String>,
    fingerprint: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = socket_path
        .map(|s| s.clone())
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
