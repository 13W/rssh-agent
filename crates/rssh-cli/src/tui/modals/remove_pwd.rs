use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::Line,
    widgets::Paragraph,
};

use super::ModalEvent;
use crate::tui::widgets::{ModalFrame, TextInput};

pub struct RemovePasswordState {
    pub fp: String,
    pub password: TextInput,
    pub error: Option<String>,
}

impl RemovePasswordState {
    pub fn new(fp: String) -> Self {
        let mut password = TextInput::new("Enter current password");
        password.masked = true;
        password.focused = true;
        Self {
            fp,
            password,
            error: None,
        }
    }
}

pub fn handle(state: &mut RemovePasswordState, key: KeyCode) -> ModalEvent {
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

pub fn render(state: &RemovePasswordState, f: &mut Frame, screen: Rect) {
    ModalFrame::new("Remove Password Protection")
        .width(50)
        .height(30)
        .border_color(Color::Red)
        .render_with(f, screen, |f, inner| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(2),
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Length(2),
                    Constraint::Length(3),
                    Constraint::Min(1),
                ])
                .split(inner);

            let key_fingerprint = if state.fp.len() > 16 { &state.fp[..16] } else { &state.fp };
            let message = vec![
                Line::from(format!("Removing password protection from key {}", key_fingerprint)),
                Line::from(""),
            ];
            f.render_widget(
                Paragraph::new(message)
                    .alignment(Alignment::Center)
                    .style(Style::default().fg(Color::White)),
                chunks[0],
            );

            let cursor = state.password.render(f, chunks[2]);

            if let Some(ref err) = state.error {
                f.render_widget(
                    Paragraph::new(err.as_str())
                        .style(Style::default().fg(Color::Red))
                        .alignment(Alignment::Center),
                    chunks[4],
                );
            }

            let instructions = vec![
                Line::from("Press Enter to remove password protection"),
                Line::from("Press Esc to cancel"),
                Line::from(""),
            ];
            f.render_widget(
                Paragraph::new(instructions)
                    .alignment(Alignment::Center)
                    .style(Style::default().fg(Color::Gray)),
                chunks[5],
            );

            f.set_cursor_position(ratatui::layout::Position::new(cursor.0, cursor.1));
        });
}
