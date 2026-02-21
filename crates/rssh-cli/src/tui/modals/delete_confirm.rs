use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::Paragraph,
};

use super::ModalEvent;
use crate::tui::widgets::ModalFrame;

pub struct DeleteConfirmState {
    pub fp: String,
    pub description: Option<String>,
}

impl DeleteConfirmState {
    pub fn new(fp: String, description: Option<String>) -> Self {
        Self { fp, description }
    }
}

pub fn handle(_state: &mut DeleteConfirmState, key: KeyCode) -> ModalEvent {
    match key {
        KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => ModalEvent::Confirm,
        KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => ModalEvent::Cancel,
        _ => ModalEvent::None,
    }
}

pub fn render(state: &DeleteConfirmState, f: &mut Frame, screen: Rect) {
    ModalFrame::new("Delete Key")
        .width(60)
        .height(25)
        .render_with(f, screen, |f, inner| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(2),
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Min(1),
                    Constraint::Length(1),
                ])
                .split(inner);

            f.render_widget(
                Paragraph::new("This will permanently delete the key from disk.\nThis action cannot be undone.")
                    .alignment(Alignment::Center)
                    .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                chunks[0],
            );

            let fp_short = if state.fp.len() > 16 {
                format!("{}...{}", &state.fp[..8], &state.fp[state.fp.len() - 8..])
            } else {
                state.fp.clone()
            };
            f.render_widget(
                Paragraph::new(format!("Key: {}", fp_short))
                    .alignment(Alignment::Center)
                    .style(Style::default().fg(Color::Yellow)),
                chunks[1],
            );

            if let Some(ref desc) = state.description {
                if !desc.is_empty() {
                    f.render_widget(
                        Paragraph::new(format!("\"{}\"", desc))
                            .alignment(Alignment::Center)
                            .style(Style::default().fg(Color::White)),
                        chunks[2],
                    );
                }
            }

            f.render_widget(
                Paragraph::new("Enter/y: Delete  Esc/n: Cancel")
                    .alignment(Alignment::Center)
                    .style(Style::default().fg(Color::Gray)),
                chunks[5],
            );
        });
}
