//! Cached presentation rows from shared deterministic catalog queries.
use crate::address::{FileOffset, StaticVa};
use crate::api::{listing, symbols};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Catalog {
    Imports,
    Exports,
    Strings,
    Bookmarks,
    Sections,
    History,
}

impl Catalog {
    pub const fn title(self) -> &'static str {
        match self {
            Self::Imports => "imports",
            Self::Exports => "exports",
            Self::Strings => "strings",
            Self::Bookmarks => "bookmarks",
            Self::Sections => "sections",
            Self::History => "navigation history",
        }
    }
}

pub struct Row {
    pub address: Option<StaticVa>,
    pub file_offset: Option<FileOffset>,
    pub label: String,
    pub detail: String,
    search_text: String,
    navigation: Option<super::NavigationLocation>,
}

impl Row {
    fn new(
        address: Option<StaticVa>,
        file_offset: Option<FileOffset>,
        label: String,
        detail: String,
    ) -> Self {
        let search_text = format!("{label} {detail}").to_lowercase();
        Self {
            address,
            file_offset,
            label,
            detail,
            search_text,
            navigation: None,
        }
    }
}

pub struct Browser {
    pub catalog: Catalog,
    pub rows: Vec<Row>,
    pub visible: Vec<usize>,
    pub selection: usize,
    pub filter: String,
}

impl Browser {
    pub fn selected(&self) -> Option<&Row> {
        self.visible
            .get(self.selection)
            .and_then(|index| self.rows.get(*index))
    }

    pub fn filter(&mut self, text: String) {
        let keep = self.visible.get(self.selection).copied();
        let needle = text.to_lowercase();
        self.visible = self
            .rows
            .iter()
            .enumerate()
            .filter(|(_, row)| row.search_text.contains(&needle))
            .map(|(index, _)| index)
            .collect();
        self.selection = keep
            .and_then(|index| self.visible.iter().position(|item| *item == index))
            .unwrap_or(0);
        self.filter = text;
    }

    pub fn step(&mut self, delta: isize) {
        self.selection = self
            .selection
            .saturating_add_signed(delta)
            .min(self.visible.len().saturating_sub(1));
    }
}

impl super::App {
    pub fn refresh_catalog(&mut self) {
        let Some(browser) = &self.browser else {
            return;
        };
        let catalog = browser.catalog;
        let filter = browser.filter.clone();
        let address = browser.selected().and_then(|row| row.address);
        let focus = self.focus;
        let status = self.status.clone();
        self.show_catalog(catalog);
        if let Some(browser) = &mut self.browser {
            browser.filter(filter);
            if let Some(address) = address {
                if let Some(index) = browser
                    .visible
                    .iter()
                    .position(|index| browser.rows[*index].address == Some(address))
                {
                    browser.selection = index;
                }
            }
        }
        self.focus = focus;
        self.status = status;
    }

    pub fn show_catalog(&mut self, catalog: Catalog) {
        let rows = match catalog {
            Catalog::History => self
                .history
                .iter()
                .rev()
                .map(|location| ("PAST", location))
                .chain(
                    self.future
                        .iter()
                        .rev()
                        .map(|location| ("FORWARD", location)),
                )
                .map(|(direction, location)| {
                    let mut row = Row::new(
                        Some(StaticVa(location.address)),
                        None,
                        self.an.label(location.address),
                        format!(
                            "{direction} {} row {}",
                            if location.graph {
                                "CFG"
                            } else if location.pseudo {
                                "PSEUDOCODE"
                            } else {
                                "DISASSEMBLY"
                            },
                            location.cursor + 1
                        ),
                    );
                    row.navigation = Some(location.clone());
                    row
                })
                .collect(),
            Catalog::Sections => crate::api::binary_summary::sections(&self.bin)
                .into_iter()
                .map(|section| {
                    let native_address = match section.address {
                        crate::api::binary_summary::ImageAddress::Rva(address) => {
                            format!("RVA {:x}", address.get())
                        }
                        crate::api::binary_summary::ImageAddress::StaticVa(address) => {
                            format!("STATIC {:x}", address.get())
                        }
                    };
                    Row::new(
                        section.static_address,
                        Some(section.file_offset),
                        section.name,
                        format!(
                            "{native_address} {} vsize {:x} bytes {:x}",
                            section.flags, section.virtual_size, section.file_size
                        ),
                    )
                })
                .collect(),
            Catalog::Bookmarks => match crate::api::bookmarks::list(&self.bin, &self.db) {
                Ok(items) => items
                    .into_iter()
                    .map(|item| {
                        Row::new(
                            Some(item.address),
                            None,
                            item.user_name
                                .unwrap_or_else(|| self.an.label(item.address.get())),
                            format!("USER BOOKMARK {}", item.user_comment.unwrap_or_default()),
                        )
                    })
                    .collect(),
                Err(error) => {
                    self.status = format!("cannot list bookmarks: {error:#}");
                    return;
                }
            },
            Catalog::Imports | Catalog::Exports => {
                let query = symbols::SymbolQuery::default();
                let items = if catalog == Catalog::Imports {
                    symbols::imports_in(&self.an, &query)
                } else {
                    symbols::exports_in(&self.bin, &self.an, &query)
                };
                items
                    .into_iter()
                    .map(|item| {
                        Row::new(
                            item.address,
                            None,
                            item.name,
                            format!("{}  refs {}", item.module, item.reference_count),
                        )
                    })
                    .collect()
            }
            Catalog::Strings => listing::string_summaries(
                &self.bin,
                &self.an,
                &self.strings,
                &listing::StringQuery::default(),
            )
            .into_iter()
            .map(|item| {
                Row::new(
                    Some(StaticVa(item.address)),
                    item.file_offset,
                    item.text,
                    format!(
                        "{} len {} refs {}",
                        if item.wide { "UTF16" } else { "ASCII" },
                        item.len,
                        item.references
                    ),
                )
            })
            .collect(),
        };
        let mut browser = Browser {
            catalog,
            rows,
            visible: Vec::new(),
            selection: 0,
            filter: String::new(),
        };
        browser.filter(String::new());
        self.browser = Some(browser);
        self.left = super::LeftView::Functions;
        self.focus = super::Focus::Functions;
        self.status = "Enter opens static VA; / filters; :functions returns to functions".into();
    }

    pub fn open_browser_selection(&mut self) {
        let Some(row) = self.browser.as_ref().and_then(Browser::selected) else {
            self.status = "no catalog row selected".into();
            return;
        };
        let Some(address) = row.address else {
            self.status = "no resolved static VA for this catalog row".into();
            return;
        };
        if let Some(location) = row.navigation.clone() {
            if let Some(current) = self.navigation_location() {
                self.history.push(current);
            }
            self.future.clear();
            self.browser = None;
            self.restore_navigation(location);
            self.status = "restored history location; Backspace returns".into();
            return;
        }
        self.open(address.get(), true);
        // Capture the source mode in history before switching the destination.
        if self.graph {
            self.toggle_graph();
        }
        if self.pseudo {
            self.toggle_pseudo();
        }
        self.focus = super::Focus::Listing;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn large_catalog_filter_preserves_selection_and_clamps_empty_results() {
        let rows = (0..50_000)
            .map(|index| {
                Row::new(
                    Some(StaticVa(index)),
                    None,
                    format!("symbol_{index}"),
                    String::new(),
                )
            })
            .collect();
        let mut browser = Browser {
            catalog: Catalog::Imports,
            rows,
            visible: Vec::new(),
            selection: 0,
            filter: String::new(),
        };
        browser.filter(String::new());
        browser.selection = 42_000;
        browser.filter("symbol_42".into());
        assert_eq!(browser.selected().unwrap().address, Some(StaticVa(42_000)));
        browser.filter("absent".into());
        browser.step(isize::MAX);
        assert!(browser.selected().is_none());
        assert_eq!(browser.selection, 0);
    }
}
