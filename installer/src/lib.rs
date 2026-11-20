pub mod ipa;
pub mod operation;
pub mod preparation;
pub mod usb;

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{error::Error, fmt, path::PathBuf, sync::Arc};

pub const BUNDLE_ID: &str = "ca.mgminformatique.agent";
pub const SCHEMA: u8 = 1;

#[derive(Clone, Serialize)]
pub struct Issue {
    pub code: &'static str,
    pub message: &'static str,
    #[serde(skip)]
    source: Option<Arc<idevice::IdeviceError>>,
}

impl Issue {
    pub const fn new(code: &'static str, message: &'static str) -> Self {
        Self {
            code,
            message,
            source: None,
        }
    }
    pub(crate) fn with_source(mut self, source: idevice::IdeviceError) -> Self {
        self.source = Some(Arc::new(source));
        self
    }
    pub const fn storage() -> Self {
        Self::new("journal_io", "Le journal local est inaccessible. Vérifie l’espace et les permissions du compte local.")
    }
}

impl fmt::Debug for Issue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Issue")
            .field("code", &self.code)
            .field("message", &self.message)
            .finish()
    }
}

impl PartialEq for Issue {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code && self.message == other.message
    }
}

impl Eq for Issue {}

impl fmt::Display for Issue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} [{}]", self.message, self.code)
    }
}

impl Error for Issue {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.as_deref().map(|error| error as &dyn Error)
    }
}
pub type Result<T> = std::result::Result<T, Issue>;

pub fn state_root() -> Result<PathBuf> {
    let root = if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .filter(|path| PathBuf::from(path).is_absolute())
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|value| PathBuf::from(value).join(".local/share"))
            })
    };
    root.filter(|path| path.is_absolute())
        .map(|path| path.join(BUNDLE_ID).join("ios-installer"))
        .ok_or_else(Issue::storage)
}

pub fn device_key(udid: &str) -> Result<String> {
    if !(16..=64).contains(&udid.len()) || !udid.bytes().all(|c| c.is_ascii_hexdigit() || c == b'-')
    {
        return Err(Issue::new(
            "device_id_invalid",
            "Choisis un identifiant USB affiché par le diagnostic.",
        ));
    }
    Ok(format!("{:x}", Sha256::digest(udid.to_ascii_lowercase())))
}
