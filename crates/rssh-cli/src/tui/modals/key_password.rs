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

pub struct KeyPasswordState {
    pub fp: String,
    pub password: TextInput,
    pub error: Option<String>,
}

impl KeyPasswordState {
    pub fn new(fp: String) -> Self {
        let mut password = TextInput::new("Password");
        password.masked = true;
        password.focused = true;
        Self {
            fp,
            password,
            error: None,
        }
    }
}

pub fn handle(state: &mut KeyPasswordState, key: KeyCode) -> ModalEvent {
    match key {
        KeyCode::Enter => ModalEvent::Confirm,
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

pub fn render(state: &KeyPasswordState, f: &mut Frame, screen: Rect) {
    ModalFrame::new("Enter Key Password")
        .width(50)
        .height(30)
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
                Line::from("Enter password for"),
                Line::from("protected key:"),
            ];
            f.render_widget(
                Paragraph::new(explanation)
                    .alignment(Alignment::Center)
                    .style(Style::default().fg(Color::White)),
                chunks[0],
            );

            let cursor = state.password.render(f, chunks[1]);

            if let Some(ref err) = state.error {
                f.render_widget(
                    Paragraph::new(err.as_str())
                        .style(Style::default().fg(Color::Red))
                        .alignment(Alignment::Center),
                    chunks[3],
                );
            }

            f.render_widget(
                Paragraph::new("Enter: OK   ESC: Cancel")
                    .alignment(Alignment::Center)
                    .style(Style::default().fg(Color::Gray)),
                chunks[4],
            );

            f.set_cursor_position(ratatui::layout::Position::new(cursor.0, cursor.1));
        });
}
