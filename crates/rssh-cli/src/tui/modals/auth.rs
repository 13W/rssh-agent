use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::Line,
    widgets::Paragraph,
};

use super::ModalEvent;
use crate::tui::widgets::{ModalFrame, TextInput};

pub struct AuthenticationState {
    pub password: TextInput,
    pub error: Option<String>,
}

impl AuthenticationState {
    pub fn new() -> Self {
        let mut password = TextInput::new("Password");
        password.masked = true;
        password.focused = true;
        Self {
            password,
            error: None,
        }
    }
}

pub fn handle(state: &mut AuthenticationState, key: KeyCode) -> ModalEvent {
    match key {
        KeyCode::Enter => {
            if state.password.value.is_empty() {
                state.error = Some("Password cannot be empty".to_string());
                ModalEvent::None
            } else {
                ModalEvent::Confirm
            }
        }
        KeyCode::Esc => ModalEvent::Cancel,
        KeyCode::Char(c) => {
            state.password.handle_char(c);
            state.error = None;
            ModalEvent::None
        }
        KeyCode::Backspace => {
            state.password.handle_backspace();
            state.error = None;
            ModalEvent::None
        }
        _ => ModalEvent::None,
    }
}

pub fn render(state: &AuthenticationState, f: &mut Frame, screen: Rect) {
    ModalFrame::new("Authentication Required")
        .width(50)
        .height(40)
        .render_with(f, screen, |f, inner| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(2),
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Length(2),
                    Constraint::Length(1),
                    Constraint::Min(1),
                ])
                .split(inner);

            let explanation = vec![
                Line::from("Enter master password"),
                Line::from("to unlock agent:"),
            ];
            f.render_widget(
                Paragraph::new(explanation)
                    .alignment(ratatui::layout::Alignment::Center)
                    .style(Style::default().fg(Color::White)),
                chunks[0],
            );

            let cursor = state.password.render(f, chunks[1]);

            if let Some(ref err) = state.error {
                f.render_widget(
                    Paragraph::new(err.as_str())
                        .style(Style::default().fg(Color::Red))
                        .alignment(ratatui::layout::Alignment::Center),
                    chunks[3],
                );
            }

            f.render_widget(
                Paragraph::new("Enter: OK   ESC: Exit")
                    .alignment(ratatui::layout::Alignment::Center)
                    .style(Style::default().fg(Color::Gray)),
                chunks[4],
            );

            f.set_cursor_position(ratatui::layout::Position::new(cursor.0, cursor.1));
        });
}
