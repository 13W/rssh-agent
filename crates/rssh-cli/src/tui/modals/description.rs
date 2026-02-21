use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    widgets::Paragraph,
};

use super::ModalEvent;
use crate::tui::widgets::{ModalFrame, TextInput};

pub struct DescriptionState {
    pub fp: String,
    pub input: TextInput,
    pub error: Option<String>,
}

impl DescriptionState {
    pub fn new(fp: String, current_description: String) -> Self {
        let mut input = TextInput::new("Description");
        input.value = current_description;
        input.focused = true;
        Self {
            fp,
            input,
            error: None,
        }
    }
}

pub fn handle(state: &mut DescriptionState, key: KeyCode) -> ModalEvent {
    match key {
        KeyCode::Enter => ModalEvent::Confirm,
        KeyCode::Esc => ModalEvent::Cancel,
        KeyCode::Char(c) => {
            state.input.handle_char(c);
            state.error = None;
            ModalEvent::None
        }
        KeyCode::Backspace => {
            state.input.handle_backspace();
            state.error = None;
            ModalEvent::None
        }
        _ => ModalEvent::None,
    }
}

pub fn render(state: &DescriptionState, f: &mut Frame, screen: Rect) {
    ModalFrame::new("Edit Description")
        .width(60)
        .height(20)
        .render_with(f, screen, |f, inner| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Length(2),
                    Constraint::Length(3),
                    Constraint::Min(1),
                ])
                .split(inner);

            let cursor = state.input.render(f, chunks[0]);

            if let Some(ref err) = state.error {
                f.render_widget(
                    Paragraph::new(err.as_str()).style(Style::default().fg(Color::Red)),
                    chunks[2],
                );
            }

            f.render_widget(
                Paragraph::new("Press Enter to Save, Esc to Cancel")
                    .alignment(Alignment::Center)
                    .style(Style::default().fg(Color::Gray)),
                chunks[3],
            );

            f.set_cursor_position(ratatui::layout::Position::new(cursor.0, cursor.1));
        });
}
