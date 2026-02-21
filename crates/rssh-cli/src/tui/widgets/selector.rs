use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    widgets::Paragraph,
};

pub struct Selector<T: Clone + PartialEq> {
    pub options: Vec<(String, T)>,
    pub selected: usize,
    pub focused: bool,
}

impl<T: Clone + PartialEq> Selector<T> {
    pub fn new(options: Vec<(String, T)>) -> Self {
        Self {
            options,
            selected: 0,
            focused: false,
        }
    }

    pub fn next(&mut self) {
        if !self.options.is_empty() {
            self.selected = (self.selected + 1) % self.options.len();
        }
    }

    pub fn prev(&mut self) {
        if !self.options.is_empty() {
            self.selected = if self.selected == 0 {
                self.options.len() - 1
            } else {
                self.selected - 1
            };
        }
    }

    pub fn value(&self) -> &T {
        &self.options[self.selected].1
    }

    pub fn set_value(&mut self, val: &T) {
        if let Some(idx) = self.options.iter().position(|(_, v)| v == val) {
            self.selected = idx;
        }
    }

    /// Render with highlight on `self.selected` when focused, no highlight when unfocused.
    pub fn render_radio_focused(&self, f: &mut Frame, areas: &[Rect]) {
        let hi = if self.focused { Some(self.selected) } else { None };
        self.render_radio(f, areas, hi);
    }

    /// Render a radio-button style list of options.
    /// `highlight_idx` is the globally-focused field index used to determine
    /// which option row is highlighted (cursor position).
    pub fn render_radio(
        &self,
        f: &mut Frame,
        areas: &[Rect],
        highlight_idx: Option<usize>,
    ) {
        for (i, (label, _)) in self.options.iter().enumerate() {
            if i >= areas.len() {
                break;
            }
            let is_selected = i == self.selected;
            let is_highlighted = highlight_idx == Some(i);

            let symbol = if is_selected { "●" } else { "○" };
            let text = format!("{} {}", symbol, label);

            let style = if is_highlighted {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else if is_selected {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::White)
            };

            f.render_widget(
                Paragraph::new(text).style(style),
                areas[i],
            );
        }
    }
}
