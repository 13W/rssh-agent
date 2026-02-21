use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::Line,
    widgets::Paragraph,
};

use super::ModalEvent;
use crate::tui::widgets::{ModalFrame, Selector, TextInput};

pub struct ImportKeyState {
    pub fp: String,
    pub description: TextInput,
    pub password_toggle: Selector<bool>,
    pub password: TextInput,
    pub confirm_password: TextInput,
    /// 0 = description, 1 = password_toggle, 2 = password, 3 = confirm_password
    pub selected_field: usize,
    pub error: Option<String>,
}

impl ImportKeyState {
    pub fn new(fp: String) -> Self {
        let mut description = TextInput::new("Description (optional)");
        description.focused = true;
        let mut password_toggle = Selector::new(vec![
            ("Yes — protect with password".to_string(), true),
            ("No — store without password".to_string(), false),
        ]);
        // Default: no password (index 1)
        password_toggle.set_value(&false);
        let mut password = TextInput::new("Password");
        password.masked = true;
        let mut confirm_password = TextInput::new("Confirm password");
        confirm_password.masked = true;
        Self {
            fp,
            description,
            password_toggle,
            password,
            confirm_password,
            selected_field: 0,
            error: None,
        }
    }

    fn max_field(&self) -> usize {
        if *self.password_toggle.value() { 3 } else { 1 }
    }

    fn update_focus(&mut self) {
        self.description.focused = self.selected_field == 0;
        self.password_toggle.focused = self.selected_field == 1;
        let with_password = *self.password_toggle.value();
        self.password.focused = with_password && self.selected_field == 2;
        self.confirm_password.focused = with_password && self.selected_field == 3;
    }
}

pub fn handle(state: &mut ImportKeyState, key: KeyCode) -> ModalEvent {
    match key {
        KeyCode::Enter => {
            let max = state.max_field();
            if state.selected_field < max {
                state.selected_field += 1;
                state.update_focus();
                state.error = None;
                ModalEvent::None
            } else {
                // Last field — submit
                if *state.password_toggle.value() {
                    if state.password.value.len() < 8 {
                        state.error = Some("Password must be at least 8 characters".to_string());
                        return ModalEvent::None;
                    }
                    if state.password.value != state.confirm_password.value {
                        state.error = Some("Passwords do not match".to_string());
                        return ModalEvent::None;
                    }
                }
                ModalEvent::Confirm
            }
        }
        KeyCode::Esc => ModalEvent::Cancel,
        KeyCode::Up => {
            if state.selected_field == 1 {
                state.password_toggle.next();
                if !*state.password_toggle.value() {
                    state.password.clear();
                    state.confirm_password.clear();
                }
                state.update_focus();
            } else if state.selected_field > 0 {
                state.selected_field -= 1;
                state.update_focus();
            }
            state.error = None;
            ModalEvent::None
        }
        KeyCode::Down => {
            if state.selected_field == 1 {
                state.password_toggle.next();
                if !*state.password_toggle.value() {
                    state.password.clear();
                    state.confirm_password.clear();
                }
                state.update_focus();
            } else {
                let max = state.max_field();
                if state.selected_field < max {
                    state.selected_field += 1;
                    state.update_focus();
                }
            }
            state.error = None;
            ModalEvent::None
        }
        KeyCode::Tab => {
            let max = state.max_field();
            if state.selected_field < max {
                state.selected_field += 1;
                state.update_focus();
            }
            state.error = None;
            ModalEvent::None
        }
        KeyCode::BackTab => {
            if state.selected_field > 0 {
                state.selected_field -= 1;
                state.update_focus();
            }
            state.error = None;
            ModalEvent::None
        }
        KeyCode::Char(' ') if state.selected_field == 1 => {
            state.password_toggle.next();
            if !*state.password_toggle.value() {
                state.password.clear();
                state.confirm_password.clear();
                if state.selected_field > 1 {
                    state.selected_field = 1;
                }
            }
            state.update_focus();
            state.error = None;
            ModalEvent::None
        }
        KeyCode::Char(c) => {
            match state.selected_field {
                0 => {
                    if c.is_ascii() && !c.is_ascii_control() {
                        state.description.handle_char(c);
                        state.error = None;
                    }
                }
                2 => {
                    state.password.handle_char(c);
                    state.error = None;
                }
                3 => {
                    state.confirm_password.handle_char(c);
                    state.error = None;
                }
                _ => {}
            }
            ModalEvent::None
        }
        KeyCode::Backspace => {
            match state.selected_field {
                0 => state.description.handle_backspace(),
                2 => state.password.handle_backspace(),
                3 => state.confirm_password.handle_backspace(),
                _ => {}
            }
            state.error = None;
            ModalEvent::None
        }
        _ => ModalEvent::None,
    }
}

pub fn render(state: &ImportKeyState, f: &mut Frame, screen: Rect) {
    ModalFrame::new("Import External Key")
        .width(70)
        .height(60)
        .render_with(f, screen, |f, inner| {
            let has_pw = *state.password_toggle.value();
            let mut constraints = vec![
                Constraint::Length(2), // subtitle
                Constraint::Length(2), // description input
                Constraint::Length(3), // password protection toggle
            ];
            if has_pw {
                constraints.push(Constraint::Length(2)); // password
                constraints.push(Constraint::Length(2)); // confirm password
            }
            constraints.extend_from_slice(&[
                Constraint::Length(1), // spacer
                Constraint::Length(2), // error
                Constraint::Length(3), // hint
                Constraint::Min(1),
            ]);

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints(constraints)
                .split(inner);

            let mut idx = 0;
            let mut cursor = (0u16, 0u16);

            // Subtitle
            let fp_short = if state.fp.len() > 20 {
                format!("{}…", &state.fp[..20])
            } else {
                state.fp.clone()
            };
            f.render_widget(
                Paragraph::new(format!("Save external key {} to disk", fp_short))
                    .alignment(Alignment::Center)
                    .style(Style::default().fg(Color::White)),
                chunks[idx],
            );
            idx += 1;

            // Description field (field 0)
            let c = state.description.render(f, chunks[idx]);
            if state.description.focused {
                cursor = c;
            }
            idx += 1;

            // Password protection toggle (field 1)
            let toggle_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(1), Constraint::Length(1), Constraint::Length(1)])
                .split(chunks[idx]);

            let toggle_focused = state.selected_field == 1;
            let toggle_label_style = if toggle_focused {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            f.render_widget(
                Paragraph::new("Password protection:  [Space to toggle]").style(toggle_label_style),
                toggle_chunks[0],
            );
            state.password_toggle.render_radio_focused(f, &toggle_chunks[1..]);
            idx += 1;

            // Password fields (only when protection enabled)
            if has_pw {
                let c = state.password.render(f, chunks[idx]);
                if state.password.focused {
                    cursor = c;
                }
                idx += 1;

                let c = state.confirm_password.render(f, chunks[idx]);
                if state.confirm_password.focused {
                    cursor = c;
                }
                idx += 1;
            }

            // Spacer
            idx += 1;

            // Error
            if let Some(ref err) = state.error {
                f.render_widget(
                    Paragraph::new(err.as_str())
                        .style(Style::default().fg(Color::Red))
                        .alignment(Alignment::Center),
                    chunks[idx],
                );
            }
            idx += 1;

            // Button hint
            f.render_widget(
                Paragraph::new(vec![
                    Line::from(""),
                    Line::from("Enter: Import Key    Esc: Cancel"),
                    Line::from("↑↓/Tab: Navigate    Space: Toggle password"),
                ])
                .alignment(Alignment::Center)
                .style(Style::default().fg(Color::Gray)),
                chunks[idx],
            );

            // Show cursor on focused text input
            if state.description.focused
                || (has_pw && (state.password.focused || state.confirm_password.focused))
            {
                f.set_cursor_position(ratatui::layout::Position::new(cursor.0, cursor.1));
            }
        });
}
