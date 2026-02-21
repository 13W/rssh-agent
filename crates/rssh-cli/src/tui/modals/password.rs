use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    widgets::Paragraph,
};

use super::ModalEvent;
use crate::tui::widgets::{ModalFrame, TextInput};

pub struct PasswordChangeState {
    pub fp: String,
    pub was_protected: bool,
    pub old_password: TextInput,
    pub new_password: TextInput,
    pub confirm_password: TextInput,
    pub selected_field: usize,
    pub error: Option<String>,
}

impl PasswordChangeState {
    pub fn new(fp: String, was_protected: bool) -> Self {
        let mut old_password = TextInput::new("Old password");
        old_password.masked = true;
        let mut new_password = TextInput::new("New password");
        new_password.masked = true;
        let mut confirm_password = TextInput::new("Confirm password");
        confirm_password.masked = true;

        let mut state = Self {
            fp,
            was_protected,
            old_password,
            new_password,
            confirm_password,
            selected_field: 0,
            error: None,
        };
        state.update_focus();
        state
    }

    fn field_count(&self) -> usize {
        if self.was_protected { 3 } else { 2 }
    }

    fn update_focus(&mut self) {
        self.old_password.focused = self.was_protected && self.selected_field == 0;
        let new_idx = if self.was_protected { 1 } else { 0 };
        let confirm_idx = if self.was_protected { 2 } else { 1 };
        self.new_password.focused = self.selected_field == new_idx;
        self.confirm_password.focused = self.selected_field == confirm_idx;
    }
}

pub fn handle(state: &mut PasswordChangeState, key: KeyCode) -> ModalEvent {
    let new_idx = if state.was_protected { 1 } else { 0 };
    let confirm_idx = if state.was_protected { 2 } else { 1 };

    match key {
        KeyCode::Enter => {
            // Validate all fields
            if state.was_protected && state.old_password.value.is_empty() {
                state.error = Some("Old password is required".to_string());
                return ModalEvent::None;
            }
            if state.new_password.value.is_empty() {
                state.error = Some("New password is required".to_string());
                return ModalEvent::None;
            }
            if state.new_password.value.len() < 8 {
                state.error = Some("Password must be at least 8 characters".to_string());
                return ModalEvent::None;
            }
            if state.new_password.value != state.confirm_password.value {
                state.error = Some("Passwords do not match".to_string());
                return ModalEvent::None;
            }
            ModalEvent::Confirm
        }
        KeyCode::Esc => ModalEvent::Cancel,
        KeyCode::Tab => {
            let max = state.field_count() - 1;
            if state.selected_field < max {
                state.selected_field += 1;
            }
            state.update_focus();
            ModalEvent::None
        }
        KeyCode::BackTab => {
            if state.selected_field > 0 {
                state.selected_field -= 1;
            }
            state.update_focus();
            ModalEvent::None
        }
        KeyCode::Char(c) => {
            let field = state.selected_field;
            if state.was_protected && field == 0 {
                state.old_password.handle_char(c);
            } else if field == new_idx {
                state.new_password.handle_char(c);
            } else if field == confirm_idx {
                state.confirm_password.handle_char(c);
            }
            state.error = None;
            ModalEvent::None
        }
        KeyCode::Backspace => {
            let field = state.selected_field;
            if state.was_protected && field == 0 {
                state.old_password.handle_backspace();
            } else if field == new_idx {
                state.new_password.handle_backspace();
            } else if field == confirm_idx {
                state.confirm_password.handle_backspace();
            }
            state.error = None;
            ModalEvent::None
        }
        _ => ModalEvent::None,
    }
}

pub fn render(state: &PasswordChangeState, f: &mut Frame, screen: Rect) {
    ModalFrame::new("Change Password")
        .width(50)
        .height(40)
        .render_with(f, screen, |f, inner| {
            let field_count = if state.was_protected { 3 } else { 2 };
            let mut constraints: Vec<Constraint> = vec![Constraint::Length(1); field_count];
            constraints.push(Constraint::Length(1)); // spacer
            constraints.push(Constraint::Length(2)); // error
            constraints.push(Constraint::Length(3)); // buttons
            constraints.push(Constraint::Min(1));

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints(constraints)
                .split(inner);

            let mut chunk_idx = 0;
            let mut cursor = (0u16, 0u16);

            if state.was_protected {
                let c = state.old_password.render(f, chunks[chunk_idx]);
                if state.old_password.focused {
                    cursor = c;
                }
                chunk_idx += 1;
            }

            let c = state.new_password.render(f, chunks[chunk_idx]);
            if state.new_password.focused {
                cursor = c;
            }
            chunk_idx += 1;

            let c = state.confirm_password.render(f, chunks[chunk_idx]);
            if state.confirm_password.focused {
                cursor = c;
            }
            chunk_idx += 1; // skip to after spacer
            chunk_idx += 1;

            if let Some(ref err) = state.error {
                f.render_widget(
                    Paragraph::new(err.as_str()).style(Style::default().fg(Color::Red)),
                    chunks[chunk_idx],
                );
            }
            chunk_idx += 1;

            f.render_widget(
                Paragraph::new("Enter: Change   Esc: Cancel   Tab: Navigate")
                    .alignment(Alignment::Center)
                    .style(Style::default().fg(Color::Gray)),
                chunks[chunk_idx],
            );

            f.set_cursor_position(ratatui::layout::Position::new(cursor.0, cursor.1));
        });
}
