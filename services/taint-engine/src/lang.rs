//! Language detection and tree-sitter grammar selection.

use std::path::Path;

/// A supported source language. JS/TS share one semantic rule family, Python
/// has its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    JavaScript,
    TypeScript,
    Tsx,
    Python,
}

/// Rule family — the set of sources/sinks/node-kinds that applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    JavaScript,
    Python,
}

impl Language {
    /// Infer the language from a file path's extension, or `None` when the
    /// extension is not one we analyze (the engine then skips the file).
    pub fn from_path(path: &str) -> Option<Language> {
        let ext = Path::new(path).extension()?.to_str()?.to_ascii_lowercase();
        match ext.as_str() {
            "js" | "jsx" | "mjs" | "cjs" => Some(Language::JavaScript),
            "ts" | "mts" | "cts" => Some(Language::TypeScript),
            "tsx" => Some(Language::Tsx),
            "py" | "pyi" => Some(Language::Python),
            _ => None,
        }
    }

    /// The tree-sitter grammar for this language.
    pub fn ts_language(self) -> tree_sitter::Language {
        match self {
            Language::JavaScript => tree_sitter_javascript::language(),
            Language::TypeScript => tree_sitter_typescript::language_typescript(),
            Language::Tsx => tree_sitter_typescript::language_tsx(),
            Language::Python => tree_sitter_python::language(),
        }
    }

    pub fn family(self) -> Family {
        match self {
            Language::Python => Family::Python,
            _ => Family::JavaScript,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_by_extension() {
        assert_eq!(Language::from_path("a/b.js"), Some(Language::JavaScript));
        assert_eq!(Language::from_path("a/b.ts"), Some(Language::TypeScript));
        assert_eq!(Language::from_path("a/b.tsx"), Some(Language::Tsx));
        assert_eq!(Language::from_path("a/b.py"), Some(Language::Python));
        assert_eq!(Language::from_path("a/b.go"), None);
        assert_eq!(Language::from_path("README"), None);
    }
}
