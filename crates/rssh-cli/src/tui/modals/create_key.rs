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

#[derive(Clone, PartialEq, Debug)]
pub enum KeyTypeOption {
    Ed25519,
    Rsa,
}

pub struct CreateKeyState {
    pub key_type_selector: Selector<KeyTypeOption>,
    pub bit_length: TextInput,
    pub description: TextInput,
    /// 0 = key type selector, 1 = bit_length (RSA only), 2 = description
    pub selected_field: usize,
    pub error: Option<String>,
}

impl CreateKeyState {
    pub fn new() -> Self {
        let mut key_type_selector = Selector::new(vec![
            ("Ed25519 (recommended)".to_string(), KeyTypeOption::Ed25519),
            ("RSA (legacy compatibility)".to_string(), KeyTypeOption::Rsa),
        ]);
        key_type_selector.focused = true;
        let mut bit_length = TextInput::new("Bit Length");
        bit_length.value = "2048".to_string();
        let mut description = TextInput::new("Description (optional)");
        description.focused = false;
        Self {
            key_type_selector,
            bit_length,
            description,
            selected_field: 0,
            error: None,
        }
    }

    fn is_rsa(&self) -> bool {
        *self.key_type_selector.value() == KeyTypeOption::Rsa
    }

    fn max_field(&self) -> usize {
        if self.is_rsa() { 2 } else { 1 }
    }

    fn update_focus(&mut self) {
        self.key_type_selector.focused = self.selected_field == 0;
        let is_rsa = self.is_rsa();
        self.bit_length.focused = is_rsa && self.selected_field == 1;
        let desc_idx = if is_rsa { 2 } else { 1 };
        self.description.focused = self.selected_field == desc_idx;
    }
}

pub fn handle(state: &mut CreateKeyState, key: KeyCode) -> ModalEvent {
    match key {
        KeyCode::Enter => {
            // Validate
            if state.is_rsa() {
                match state.bit_length.value.parse::<u32>() {
                    Ok(bits) if bits >= 2048 && bits <= 8192 && bits % 8 == 0 => {}
                    _ => {
                        state.error = Some(
                            "Invalid bit length. Must be 2048-8192 and divisible by 8".to_string(),
                        );
                        return ModalEvent::None;
                    }
                }
            }
            ModalEvent::Confirm
        }
        KeyCode::Esc => ModalEvent::Cancel,
        KeyCode::Up | KeyCode::Char('k') => {
            if state.selected_field == 0 {
                state.key_type_selector.prev();
                state.update_focus();
            } else {
                state.selected_field -= 1;
                state.update_focus();
            }
            state.error = None;
            ModalEvent::None
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if state.selected_field == 0 {
                state.key_type_selector.next();
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
        KeyCode::Char(' ') if state.selected_field == 0 => {
            state.key_type_selector.next();
            state.update_focus();
            state.error = None;
            ModalEvent::None
        }
        KeyCode::Char('e') | KeyCode::Char('E') if state.selected_field == 0 => {
            state.key_type_selector.set_value(&KeyTypeOption::Ed25519);
            state.update_focus();
            state.error = None;
            ModalEvent::None
        }
        KeyCode::Char('r') | KeyCode::Char('R') if state.selected_field == 0 => {
            state.key_type_selector.set_value(&KeyTypeOption::Rsa);
            state.update_focus();
            state.error = None;
            ModalEvent::None
        }
        KeyCode::Char(c) => {
            let is_rsa = state.is_rsa();
            if is_rsa && state.selected_field == 1 {
                if c.is_ascii_digit() {
                    state.bit_length.handle_char(c);
                    state.error = None;
                }
            } else if (is_rsa && state.selected_field == 2) || (!is_rsa && state.selected_field == 1) {
                if c.is_ascii() && !c.is_ascii_control() {
                    state.description.handle_char(c);
                    state.error = None;
                }
            }
            ModalEvent::None
        }
        KeyCode::Backspace => {
            let is_rsa = state.is_rsa();
            if is_rsa && state.selected_field == 1 {
                state.bit_length.handle_backspace();
                state.error = None;
            } else if (is_rsa && state.selected_field == 2) || (!is_rsa && state.selected_field == 1) {
                state.description.handle_backspace();
                state.error = None;
            }
            ModalEvent::None
        }
        _ => ModalEvent::None,
    }
}

pub fn render(state: &CreateKeyState, f: &mut Frame, screen: Rect) {
    ModalFrame::new("Create New Key")
        .width(70)
        .height(60)
        .render_with(f, screen, |f, inner| {
            let is_rsa = state.is_rsa();
            let mut constraints = vec![
                Constraint::Length(2), // title
                Constraint::Length(3), // type selector (label + 2 options)
            ];
            if is_rsa {
                constraints.push(Constraint::Length(2)); // bit length
            }
            constraints.extend_from_slice(&[
                Constraint::Length(2), // description
                Constraint::Length(1), // spacer
                Constraint::Length(2), // error
                Constraint::Length(3), // buttons
                Constraint::Min(1),
            ]);

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints(constraints)
                .split(inner);

            let mut idx = 0;
            let mut cursor = (0u16, 0u16);

            // Title
            f.render_widget(
                Paragraph::new(vec![Line::from("Create a new SSH key"), Line::from("")])
                    .alignment(Alignment::Center)
                    .style(Style::default().fg(Color::White)),
                chunks[idx],
            );
            idx += 1;

            // Key type selection
            let type_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(1), Constraint::Length(1), Constraint::Length(1)])
                .split(chunks[idx]);

            let type_focused = state.selected_field == 0;
            let type_label_style = if type_focused {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            f.render_widget(Paragraph::new("Key Type:").style(type_label_style), type_chunks[0]);
            state.key_type_selector.render_radio_focused(f, &type_chunks[1..]);
            idx += 1;

            // RSA bit length
            if is_rsa {
                let c = state.bit_length.render(f, chunks[idx]);
                if state.bit_length.focused {
                    cursor = c;
                }
                idx += 1;
            }

            // Description
            let c = state.description.render(f, chunks[idx]);
            if state.description.focused {
                cursor = c;
            }
            idx += 1;

            // spacer
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

            // Buttons
            f.render_widget(
                Paragraph::new(vec![
                    Line::from(""),
                    Line::from("Enter: Create Key    Esc: Cancel"),
                    Line::from("↑↓: Navigate    Tab: Next Field"),
                ])
                .alignment(Alignment::Center)
                .style(Style::default().fg(Color::Gray)),
                chunks[idx],
            );

            if state.selected_field > 0 {
                f.set_cursor_position(ratatui::layout::Position::new(cursor.0, cursor.1));
            }
        });
}
