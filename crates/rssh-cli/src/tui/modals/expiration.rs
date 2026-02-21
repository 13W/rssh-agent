use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    widgets::Paragraph,
};

use super::ModalEvent;
use crate::tui::widgets::{ModalFrame, TextInput};

pub struct ExpirationState {
    pub fp: String,
    pub default_lifetime: TextInput,
    pub selected_field: usize,
    pub key_loaded: bool,
    pub current_timer_display: Option<String>,
    pub error: Option<String>,
}

impl ExpirationState {
    pub fn new(
        fp: String,
        key_loaded: bool,
        current_timer_display: Option<String>,
        default_lifetime_str: String,
    ) -> Self {
        let mut default_lifetime = TextInput::new("Default expiration (e.g. 2h, 30m, 1d)");
        default_lifetime.value = default_lifetime_str;
        default_lifetime.focused = true;
        Self {
            fp,
            default_lifetime,
            selected_field: 0,
            key_loaded,
            current_timer_display,
            error: None,
        }
    }
}

pub fn handle(state: &mut ExpirationState, key: KeyCode) -> ModalEvent {
    match key {
        KeyCode::Enter => ModalEvent::Confirm,
        KeyCode::Esc => ModalEvent::Cancel,
        KeyCode::Char('R') | KeyCode::Char('r') => ModalEvent::ResetTimer,
        KeyCode::Tab => {
            // Only one field, nothing to navigate
            ModalEvent::None
        }
        KeyCode::BackTab => ModalEvent::None,
        KeyCode::Char(c) => {
            if state.selected_field == 0 {
                state.default_lifetime.handle_char(c);
                state.error = None;
            }
            ModalEvent::None
        }
        KeyCode::Backspace => {
            if state.selected_field == 0 {
                state.default_lifetime.handle_backspace();
                state.error = None;
            }
            ModalEvent::None
        }
        _ => ModalEvent::None,
    }
}

pub fn render(state: &ExpirationState, f: &mut Frame, screen: Rect) {
    ModalFrame::new("Expiration Settings")
        .width(60)
        .height(40)
        .render_with(f, screen, |f, inner| {
            let mut constraints = vec![];
            if state.key_loaded {
                constraints.push(Constraint::Length(3));
            }
            constraints.push(Constraint::Length(1)); // input
            constraints.push(Constraint::Length(1)); // spacer
            constraints.push(Constraint::Length(2)); // error
            constraints.push(Constraint::Length(3)); // buttons
            constraints.push(Constraint::Min(1));

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints(constraints)
                .split(inner);

            let mut idx = 0;

            if state.key_loaded {
                let timer_text = state
                    .current_timer_display
                    .as_deref()
                    .map(|s| format!("Current Timer: {} remaining", s))
                    .unwrap_or_else(|| "Current Timer: No expiration set".to_string());
                f.render_widget(
                    Paragraph::new(timer_text)
                        .alignment(Alignment::Center)
                        .style(Style::default().fg(Color::Blue)),
                    chunks[idx],
                );
                idx += 1;
            }

            let cursor = state.default_lifetime.render(f, chunks[idx]);
            idx += 1;
            idx += 1; // spacer

            if let Some(ref err) = state.error {
                f.render_widget(
                    Paragraph::new(err.as_str()).style(Style::default().fg(Color::Red)),
                    chunks[idx],
                );
            }
            idx += 1;

            let button_text = if state.key_loaded {
                "R: Reset Timer   Enter: Save   Esc: Cancel"
            } else {
                "Enter: Save   Esc: Cancel"
            };
            f.render_widget(
                Paragraph::new(button_text)
                    .alignment(Alignment::Center)
                    .style(Style::default().fg(Color::Gray)),
                chunks[idx],
            );

            if state.selected_field == 0 {
                f.set_cursor_position(ratatui::layout::Position::new(cursor.0, cursor.1));
            }
        });
}
