//! One geometry model for rendering and hit testing.
use super::{App, Focus, LeftView};
use ratatui::layout::{Constraint, Direction, Layout, Rect};

#[derive(Debug, Clone)]
pub struct PaneSettings {
    pub functions: bool,
    pub references: bool,
    pub left_width: u16,
    pub reference_width: u16,
}

impl Default for PaneSettings {
    fn default() -> Self {
        Self {
            functions: true,
            references: true,
            left_width: 38,
            reference_width: 32,
        }
    }
}

pub struct Panes {
    pub header: Rect,
    pub footer: Rect,
    pub functions: Rect,
    pub listing: Rect,
    pub references: Rect,
    pub detail: Rect,
}

impl App {
    pub fn panes(&self, area: Rect) -> Panes {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Min(0),
                Constraint::Length(1),
            ])
            .split(area);
        let left = self.pane_settings.functions || self.focus == Focus::Functions;
        let refs = self.pane_settings.references || self.focus == Focus::Xrefs;
        let wide = area.width >= 132;
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(if left {
                    self.pane_settings.left_width.min(area.width / 2)
                } else {
                    0
                }),
                Constraint::Min(1),
                Constraint::Length(if refs && wide {
                    self.pane_settings.reference_width.min(area.width / 3)
                } else {
                    0
                }),
            ])
            .split(rows[1]);
        let detail_height = match self.left {
            LeftView::Sinks if !self.sinks.is_empty() => 6,
            LeftView::Types => 7,
            _ => 0,
        };
        let center = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(1),
                Constraint::Length(detail_height),
                Constraint::Length(if refs && !wide { 8 } else { 0 }),
            ])
            .split(cols[1]);
        Panes {
            header: rows[0],
            footer: rows[2],
            functions: cols[0],
            listing: center[0],
            detail: center[1],
            references: if wide { cols[2] } else { center[2] },
        }
    }

    pub fn close_pane(&mut self) {
        match self.focus {
            Focus::Functions => self.pane_settings.functions = false,
            Focus::Xrefs => self.pane_settings.references = false,
            Focus::Listing => {
                self.status = "listing stays open; focus a side pane to close it".into();
                return;
            }
        }
        self.focus = Focus::Listing;
    }

    pub fn resize_pane(&mut self, delta: i16) {
        let width = match self.focus {
            Focus::Functions => &mut self.pane_settings.left_width,
            Focus::Xrefs => &mut self.pane_settings.reference_width,
            Focus::Listing => {
                self.status = "focus functions or references to resize its width".into();
                return;
            }
        };
        *width = width.saturating_add_signed(delta).clamp(20, 80);
        self.status = "pane width updated; reference width applies in wide terminals".into();
    }
}
