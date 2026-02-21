use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    widgets::Paragraph,
};

use super::ModalEvent;
use crate::tui::widgets::{ModalFrame, TextInput};

pub struct SetKeyPasswordState {
    pub fp: String,
    pub new_password: TextInput,
    pub confirm_password: TextInput,
    pub selected_field: usize,
    pub error: Option<String>,
}

impl SetKeyPasswordState {
    pub fn new(fp: String) -> Self {
        let mut new_password = TextInput::new("New password");
        new_password.masked = true;
        new_password.focused = true;
        let mut confirm_password = TextInput::new("Confirm password");
        confirm_password.masked = true;
        Self {
            fp,
            new_password,
            confirm_password,
            selected_field: 0,
            error: None,
        }
    }

    fn update_focus(&mut self) {
        self.new_password.focused = self.selected_field == 0;
        self.confirm_password.focused = self.selected_field == 1;
    }
}

pub fn handle(state: &mut SetKeyPasswordState, key: KeyCode) -> ModalEvent {
    match key {
        KeyCode::Enter => {
            match state.selected_field {
                0 => {
                    if state.new_password.value.len() < 8 {
                        state.error = Some("Password must be at least 8 characters".to_string());
                    } else {
                        state.selected_field = 1;
                        state.update_focus();
                        state.error = None;
                    }
                    ModalEvent::None
                }
                1 => {
                    if state.new_password.value != state.confirm_password.value {
                        state.error = Some("Passwords don't match".to_string());
                        ModalEvent::None
                    } else if state.new_password.value.len() < 8 {
                        state.error = Some("Password must be at least 8 characters".to_string());
                        ModalEvent::None
                    } else {
                        ModalEvent::Confirm
                    }
                }
                _ => ModalEvent::None,
            }
        }
        KeyCode::Esc => ModalEvent::Cancel,
        KeyCode::Tab => {
            state.selected_field = if state.selected_field == 0 { 1 } else { 0 };
            state.update_focus();
            state.error = None;
            ModalEvent::None
        }
        KeyCode::BackTab => {
            state.selected_field = if state.selected_field == 0 { 1 } else { 0 };
            state.update_focus();
            state.error = None;
            ModalEvent::None
        }
        KeyCode::Char(c) => {
            match state.selected_field {
                0 => state.new_password.handle_char(c),
                1 => state.confirm_password.handle_char(c),
                _ => {}
            }
            state.error = None;
            ModalEvent::None
        }
        KeyCode::Backspace => {
            match state.selected_field {
                0 => state.new_password.handle_backspace(),
                1 => state.confirm_password.handle_backspace(),
                _ => {}
            }
            state.error = None;
            ModalEvent::None
        }
        _ => ModalEvent::None,
    }
}

pub fn render(state: &SetKeyPasswordState, f: &mut Frame, screen: Rect) {
    ModalFrame::new("Set Key Password")
        .width(50)
        .height(40)
        .render_with(f, screen, |f, inner| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Length(2),
                    Constraint::Length(1),
                    Constraint::Min(1),
                ])
                .split(inner);

            let new_cursor = state.new_password.render(f, chunks[0]);
            let confirm_cursor = state.confirm_password.render(f, chunks[1]);

            let cursor = if state.new_password.focused {
                new_cursor
            } else {
                confirm_cursor
            };

            if let Some(ref err) = state.error {
                f.render_widget(
                    Paragraph::new(err.as_str())
                        .style(Style::default().fg(Color::Red))
                        .alignment(Alignment::Center),
                    chunks[3],
                );
            }

            f.render_widget(
                Paragraph::new("Enter: Save   ESC: Cancel   Tab: Navigate")
                    .alignment(Alignment::Center)
                    .style(Style::default().fg(Color::Gray)),
                chunks[4],
            );

            f.set_cursor_position(ratatui::layout::Position::new(cursor.0, cursor.1));
        });
}
