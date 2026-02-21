use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    widgets::Paragraph,
};

pub struct TextInput {
    pub label: String,
    pub value: String,
    pub focused: bool,
    pub masked: bool,
}

impl TextInput {
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            value: String::new(),
            focused: false,
            masked: false,
        }
    }

    /// Render the text input as a horizontal inline field.
    /// Returns `(cursor_x, cursor_y)` for proper cursor placement.
    pub fn render(&self, f: &mut Frame, area: Rect) -> (u16, u16) {
        let label_text = format!("{}: ", self.label);
        let label_width = label_text.len() as u16;
        let input_width = area.width.saturating_sub(label_width + 1);

        let display_text = if self.masked {
            "*".repeat(self.value.len())
        } else {
            self.value.clone()
        };

        let underline = "_".repeat(input_width as usize);
        let combined_text = if display_text.is_empty() {
            format!("{}{}", label_text, underline)
        } else {
            let remaining = input_width.saturating_sub(display_text.len() as u16);
            format!("{}{}{}", label_text, display_text, "_".repeat(remaining as usize))
        };

        let style = if self.focused {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::White)
        };

        f.render_widget(
            Paragraph::new(combined_text).style(style),
            area,
        );

        let cursor_x = area.x + label_width + self.value.len() as u16;
        let cursor_y = area.y;
        (cursor_x, cursor_y)
    }

    pub fn handle_char(&mut self, c: char) {
        self.value.push(c);
    }

    pub fn handle_backspace(&mut self) {
        self.value.pop();
    }

    pub fn clear(&mut self) {
        self.value.clear();
    }
}
