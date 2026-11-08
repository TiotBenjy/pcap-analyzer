//! Window close decision and the texts of the native dialogs (startup failure, close during an
//! import). Kept free of Tauri types so the logic is tested without a window.

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

/// Language of the native dialogs. The UI reports its own (`set_ui_language`); before that,
/// the locale of the environment decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    En,
    Fr,
}

impl Language {
    /// `"en"` / `"fr"` (the UI languages), else `None`.
    pub fn parse(code: &str) -> Option<Self> {
        match code {
            "en" => Some(Self::En),
            "fr" => Some(Self::Fr),
            _ => None,
        }
    }

    /// From POSIX locale variables, in priority order (`LC_ALL`, `LC_MESSAGES`, `LANG`): the
    /// first non-empty one decides. English when none is set (Windows) or not French.
    pub fn from_locale_vars(vars: &[Option<String>]) -> Self {
        let first = vars.iter().flatten().find(|v| !v.is_empty());
        match first {
            Some(v) if v.to_ascii_lowercase().starts_with("fr") => Self::Fr,
            _ => Self::En,
        }
    }

    pub fn from_env() -> Self {
        Self::from_locale_vars(&[
            std::env::var("LC_ALL").ok(),
            std::env::var("LC_MESSAGES").ok(),
            std::env::var("LANG").ok(),
        ])
    }
}

/// Current dialog language, shared between the IPC thread and the event loop.
#[derive(Debug)]
pub struct LanguageCell(AtomicU8);

impl LanguageCell {
    pub fn new(lang: Language) -> Self {
        Self(AtomicU8::new(lang as u8))
    }

    pub fn get(&self) -> Language {
        if self.0.load(Ordering::Relaxed) == Language::Fr as u8 {
            Language::Fr
        } else {
            Language::En
        }
    }

    pub fn set(&self, lang: Language) {
        self.0.store(lang as u8, Ordering::Relaxed);
    }
}

/// Texts of the native dialogs.
#[derive(Debug)]
pub struct Texts {
    pub startup_title: &'static str,
    pub startup_intro: &'static str,
    pub close_title: &'static str,
    pub close_body: &'static str,
    pub close_quit: &'static str,
    pub close_keep: &'static str,
}

const EN: Texts = Texts {
    startup_title: "NetSift cannot start",
    startup_intro: "The local analysis service could not be started.",
    close_title: "Import in progress",
    close_body: "An import is running. If you quit now, it stops and the session is kept as incomplete.",
    close_quit: "Quit",
    close_keep: "Keep importing",
};

const FR: Texts = Texts {
    startup_title: "NetSift ne peut pas démarrer",
    startup_intro: "Le service d'analyse local n'a pas pu démarrer.",
    close_title: "Import en cours",
    close_body: "Un import est en cours. Si vous quittez maintenant, il s'arrête et la session est conservée comme incomplète.",
    close_quit: "Quitter",
    close_keep: "Continuer l'import",
};

pub fn texts(lang: Language) -> &'static Texts {
    match lang {
        Language::En => &EN,
        Language::Fr => &FR,
    }
}

/// Body of the startup failure dialog: the intro, then the error chain.
pub fn startup_message(lang: Language, error: &anyhow::Error) -> String {
    format!("{}\n\n{error:#}", texts(lang).startup_intro)
}

/// What to do with a window close request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseDecision {
    /// Let the window close (no import running, or the user already confirmed).
    Close,
    /// Keep the window and ask for confirmation.
    Ask,
    /// Keep the window: a confirmation dialog is already open.
    Wait,
}

/// Close confirmation state of the main window.
#[derive(Debug, Default)]
pub struct CloseGate {
    confirmed: AtomicBool,
    asking: AtomicBool,
}

impl CloseGate {
    pub fn request(&self, running_imports: usize) -> CloseDecision {
        if running_imports == 0 || self.confirmed.load(Ordering::Acquire) {
            return CloseDecision::Close;
        }
        if self.asking.swap(true, Ordering::AcqRel) {
            CloseDecision::Wait
        } else {
            CloseDecision::Ask
        }
    }

    /// Answer of the confirmation dialog.
    pub fn answer(&self, quit: bool) {
        if quit {
            self.confirmed.store(true, Ordering::Release);
        }
        self.asking.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::unnecessary_wraps)] // shorthand for the `Option` arguments below
    fn s(v: &str) -> Option<String> {
        Some(v.to_owned())
    }

    #[test]
    fn language_from_locale_variables() {
        assert_eq!(
            Language::from_locale_vars(&[None, None, None]),
            Language::En
        );
        assert_eq!(
            Language::from_locale_vars(&[None, None, s("fr_FR.UTF-8")]),
            Language::Fr
        );
        assert_eq!(
            Language::from_locale_vars(&[s("C"), None, s("fr_FR.UTF-8")]),
            Language::En
        );
        assert_eq!(
            Language::from_locale_vars(&[s(""), s("fr_CA"), s("en_US")]),
            Language::Fr
        );
        assert_eq!(
            Language::from_locale_vars(&[None, None, s("de_DE")]),
            Language::En
        );
        assert_eq!(Language::parse("fr"), Some(Language::Fr));
        assert_eq!(Language::parse("en"), Some(Language::En));
        assert_eq!(Language::parse("de"), None);
        assert_eq!(Language::parse("FR"), None);
    }

    #[test]
    fn language_cell_round_trips() {
        let cell = LanguageCell::new(Language::En);
        assert_eq!(cell.get(), Language::En);
        cell.set(Language::Fr);
        assert_eq!(cell.get(), Language::Fr);
    }

    #[test]
    fn texts_exist_in_both_languages() {
        for lang in [Language::En, Language::Fr] {
            let t = texts(lang);
            for text in [
                t.startup_title,
                t.startup_intro,
                t.close_title,
                t.close_body,
                t.close_quit,
                t.close_keep,
            ] {
                assert_ne!(text.trim(), "");
            }
        }
        assert_ne!(
            texts(Language::En).close_body,
            texts(Language::Fr).close_body
        );
    }

    #[test]
    fn startup_message_carries_the_error_chain() {
        let err = anyhow::anyhow!("permission denied").context("cannot create the data folder /x");
        let message = startup_message(Language::En, &err);
        assert!(message.starts_with(texts(Language::En).startup_intro));
        assert!(
            message.contains("cannot create the data folder /x: permission denied"),
            "{message}"
        );
    }

    #[test]
    fn closing_without_import_is_immediate() {
        let gate = CloseGate::default();
        assert_eq!(gate.request(0), CloseDecision::Close);
    }

    #[test]
    fn closing_during_an_import_asks_once() {
        let gate = CloseGate::default();
        assert_eq!(gate.request(1), CloseDecision::Ask);
        // Clicking the close button again while the dialog is open.
        assert_eq!(gate.request(1), CloseDecision::Wait);
        // "Keep importing": the next request asks again.
        gate.answer(false);
        assert_eq!(gate.request(2), CloseDecision::Ask);
        // "Quit": the window closes, even if the import is still running.
        gate.answer(true);
        assert_eq!(gate.request(1), CloseDecision::Close);
    }

    #[test]
    fn import_ending_while_asking_lets_the_window_close() {
        let gate = CloseGate::default();
        assert_eq!(gate.request(1), CloseDecision::Ask);
        assert_eq!(gate.request(0), CloseDecision::Close);
    }
}
