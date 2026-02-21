use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::Paragraph,
};

use super::ModalEvent;
use crate::tui::widgets::{ModalFrame, Selector};
use crate::tui::ConstraintOption;

#[derive(PartialEq)]
pub enum ConfirmSection {
    Runtime,
    Default,
}

pub struct ConfirmationState {
    pub fp: String,
    pub key_loaded: bool,
    pub runtime_selector: Selector<ConstraintOption>,
    pub default_selector: Selector<ConstraintOption>,
    pub active_section: ConfirmSection,
    pub error: Option<String>,
}

impl ConfirmationState {
    pub fn new(
        fp: String,
        key_loaded: bool,
        runtime_constraint: ConstraintOption,
        default_constraint: ConstraintOption,
    ) -> Self {
        let mut runtime_selector = Selector::new(vec![
            ("None".to_string(), ConstraintOption::None),
            ("Notification".to_string(), ConstraintOption::Notification),
            ("Confirmation".to_string(), ConstraintOption::Confirmation),
        ]);
        runtime_selector.set_value(&runtime_constraint);

        let mut default_selector = Selector::new(vec![
            ("None".to_string(), ConstraintOption::None),
            ("Notification".to_string(), ConstraintOption::Notification),
            ("Confirmation".to_string(), ConstraintOption::Confirmation),
        ]);
        default_selector.set_value(&default_constraint);

        let active_section = if key_loaded {
            runtime_selector.focused = true;
            default_selector.focused = false;
            ConfirmSection::Runtime
        } else {
            runtime_selector.focused = false;
            default_selector.focused = true;
            ConfirmSection::Default
        };

        Self {
            fp,
            key_loaded,
            runtime_selector,
            default_selector,
            active_section,
            error: None,
        }
    }

    fn switch_to_section(&mut self, section: ConfirmSection) {
        self.active_section = section;
        self.runtime_selector.focused = self.active_section == ConfirmSection::Runtime;
        self.default_selector.focused = self.active_section == ConfirmSection::Default;
    }
}

pub fn handle(state: &mut ConfirmationState, key: KeyCode) -> ModalEvent {
    match key {
        KeyCode::Enter => ModalEvent::Confirm,
        KeyCode::Esc => ModalEvent::Cancel,
        KeyCode::Char(' ') | KeyCode::Down => {
            if state.active_section == ConfirmSection::Runtime {
                state.runtime_selector.next();
            } else {
                state.default_selector.next();
            }
            state.error = None;
            ModalEvent::None
        }
        KeyCode::Up => {
            if state.active_section == ConfirmSection::Runtime {
                state.runtime_selector.prev();
            } else {
                state.default_selector.prev();
            }
            state.error = None;
            ModalEvent::None
        }
        KeyCode::Tab | KeyCode::Right => {
            if state.key_loaded {
                state.switch_to_section(ConfirmSection::Default);
            }
            ModalEvent::None
        }
        KeyCode::BackTab | KeyCode::Left => {
            if state.key_loaded {
                state.switch_to_section(ConfirmSection::Runtime);
            }
            ModalEvent::None
        }
        _ => ModalEvent::None,
    }
}

pub fn render(state: &ConfirmationState, f: &mut Frame, screen: Rect) {
    ModalFrame::new("Confirmation Settings")
        .width(80)
        .height(50)
        .render_with(f, screen, |f, inner| {
            if state.key_loaded {
                // Two-column layout
                let main_chunks = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                    .split(inner);

                let runtime_active = state.active_section == ConfirmSection::Runtime;

                let runtime_block = ratatui::widgets::Block::default()
                    .borders(ratatui::widgets::Borders::ALL)
                    .title("Current Runtime (if loaded)")
                    .border_style(if runtime_active {
                        Style::default().fg(Color::Yellow)
                    } else {
                        Style::default().fg(Color::White)
                    });
                let runtime_inner = runtime_block.inner(main_chunks[0]);
                f.render_widget(runtime_block, main_chunks[0]);

                let runtime_chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(1),
                        Constraint::Length(1),
                        Constraint::Length(1),
                        Constraint::Min(1),
                    ])
                    .split(runtime_inner);

                state.runtime_selector.render_radio_focused(f, &runtime_chunks[..3]);

                let default_active = state.active_section == ConfirmSection::Default;
                let default_block = ratatui::widgets::Block::default()
                    .borders(ratatui::widgets::Borders::ALL)
                    .title("Default for Future Loads")
                    .border_style(if default_active {
                        Style::default().fg(Color::Yellow)
                    } else {
                        Style::default().fg(Color::White)
                    });
                let default_inner = default_block.inner(main_chunks[1]);
                f.render_widget(default_block, main_chunks[1]);

                let default_chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(1),
                        Constraint::Length(1),
                        Constraint::Length(1),
                        Constraint::Min(1),
                    ])
                    .split(default_inner);

                state.default_selector.render_radio_focused(f, &default_chunks[..3]);
            } else {
                // Single-section layout: default only
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(2),
                        Constraint::Length(1),
                        Constraint::Length(1),
                        Constraint::Length(1),
                        Constraint::Min(1),
                    ])
                    .split(inner);

                f.render_widget(
                    Paragraph::new("Default for Future Loads")
                        .alignment(Alignment::Center)
                        .style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                    chunks[0],
                );

                state.default_selector.render_radio_focused(f, &chunks[1..4]);
            }

            // Error at bottom
            if let Some(ref err) = state.error {
                let err_area = Rect::new(
                    inner.x,
                    inner.y + inner.height.saturating_sub(4),
                    inner.width,
                    1,
                );
                f.render_widget(
                    Paragraph::new(err.as_str())
                        .style(Style::default().fg(Color::Red))
                        .alignment(Alignment::Center),
                    err_area,
                );
            }

            // Help text at bottom
            let help_area = Rect::new(
                inner.x,
                inner.y + inner.height.saturating_sub(2),
                inner.width,
                1,
            );
            let help_text = if state.key_loaded {
                "Arrows: Navigate  Space: Cycle  Tab: Switch  Enter: Save  Esc: Cancel"
            } else {
                "Arrows: Navigate  Space: Cycle  Enter: Save  Esc: Cancel"
            };
            f.render_widget(
                Paragraph::new(help_text)
                    .alignment(Alignment::Center)
                    .style(Style::default().fg(Color::Gray)),
                help_area,
            );
        });
}
