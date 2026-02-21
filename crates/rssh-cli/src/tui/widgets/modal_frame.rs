use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    widgets::{Block, Borders, Clear},
};

pub struct ModalFrame<'a> {
    pub title: &'a str,
    pub width_pct: u16,
    pub height_pct: u16,
    pub border_color: Color,
}

impl<'a> ModalFrame<'a> {
    pub fn new(title: &'a str) -> Self {
        Self {
            title,
            width_pct: 60,
            height_pct: 40,
            border_color: Color::Cyan,
        }
    }

    pub fn width(mut self, pct: u16) -> Self {
        self.width_pct = pct;
        self
    }

    pub fn height(mut self, pct: u16) -> Self {
        self.height_pct = pct;
        self
    }

    pub fn border_color(mut self, color: Color) -> Self {
        self.border_color = color;
        self
    }

    /// Clear the centered area, draw the border block, and call `inner` with
    /// the inner (content) `Rect`.  Returns the full overlay `Rect`.
    pub fn render_with<F: FnOnce(&mut Frame, Rect)>(
        &self,
        f: &mut Frame,
        screen: Rect,
        inner_fn: F,
    ) -> Rect {
        let overlay = self.centered_rect(screen);
        f.render_widget(Clear, overlay);

        let block = Block::default()
            .title(format!(" {} ", self.title))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.border_color))
            .style(Style::default().bg(Color::Black));

        let inner = block.inner(overlay);
        f.render_widget(block, overlay);
        inner_fn(f, inner);
        overlay
    }

    fn centered_rect(&self, r: Rect) -> Rect {
        use ratatui::layout::{Constraint, Direction, Layout};

        let popup_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage((100 - self.height_pct) / 2),
                Constraint::Percentage(self.height_pct),
                Constraint::Percentage((100 - self.height_pct) / 2),
            ])
            .split(r);

        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage((100 - self.width_pct) / 2),
                Constraint::Percentage(self.width_pct),
                Constraint::Percentage((100 - self.width_pct) / 2),
            ])
            .split(popup_layout[1])[1]
    }
}
