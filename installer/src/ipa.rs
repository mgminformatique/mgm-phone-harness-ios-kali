use crate::{Issue, Result};
use cms::{content_info::ContentInfo, signed_data::SignedData};
use der::{asn1::OctetString, Decode, Encode};
use plist::{Dictionary, Value};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::SystemTime,
};
use zip::{write::SimpleFileOptions, ZipArchive, ZipWriter};

const MAX_IPA: u64 = 512 * 1024 * 1024;
const MAX_EXPANDED: u64 = 2 * 1024 * 1024 * 1024;
const MAX_PLIST: u64 = 4 * 1024 * 1024;
const MAX_EXECUTABLE: u64 = 128 * 1024 * 1024;
const INVALID: Issue = Issue::new(
    "ipa_invalid",
    "L’archive IPA ou les métadonnées des apps sont incohérentes.",
);
const SIGNATURE: Issue = Issue::new(
    "signature_missing",
    "Une app ou extension n’a pas de signature de distribution exploitable dans son Mach-O arm64.",
);
const NO_PROFILE: Issue = Issue::new(
    "profile_missing",
    "Une app ou extension n’a pas de profil de provisionnement embarqué.",
);
const PROFILE: Issue = Issue::new(
    "profile_invalid",
    "Le profil embarqué ou son identifiant d’application est incompatible.",
);
const EXPIRED: Issue = Issue::new("profile_expired", "Un profil embarqué a expiré.");
const DEVICE: Issue = Issue::new(
    "profile_device_mismatch",
    "Le profil doit être valide pour cet iPhone enregistré.",
);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Identity {
    pub bundle: String,
    pub version: String,
    pub build: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataIdentity {
    pub application_identifier: String,
    pub team: String,
    pub keychain_groups: BTreeSet<String>,
    pub app_groups: BTreeSet<String>,
}

impl DataIdentity {
    pub(crate) fn read(entitlements: &Dictionary, bundle: &str) -> Option<Self> {
        let application_identifier = field(entitlements, "application-identifier", PROFILE).ok()?;
        let (prefix, name) = application_identifier.split_once('.')?;
        if prefix.is_empty() || name != bundle {
            return None;
        }
        let groups = |key| match entitlements.get(key) {
            None => Some(BTreeSet::new()),
            Some(value) => value
                .as_array()?
                .iter()
                .map(|value| {
                    let name = value.as_string()?;
                    (!name.is_empty() && !name.chars().any(char::is_control))
                        .then(|| name.to_owned())
                })
                .collect(),
        };
        Some(Self {
            application_identifier,
            team: field(entitlements, "com.apple.developer.team-identifier", PROFILE).ok()?,
            keychain_groups: groups("keychain-access-groups")?,
            app_groups: groups("com.apple.security.application-groups")?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Component {
    pub identity: Identity,
    pub team: String,
    pub expires: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_identity: Option<DataIdentity>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Inspection {
    pub identity: Identity,
    pub team: String,
    pub sha256: String,
    pub bytes: u64,
    pub components: Vec<Component>,
    pub apple_verification: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct UnsignedInput {
    pub identity: Identity,
    pub bytes: u64,
    pub sha256: String,
    pub extensions: usize,
}

pub fn inspect_input(path: &Path) -> Result<UnsignedInput> {
    let mut file = open_ipa(path)?;
    let (bytes, sha256) = digest(&mut file, std::io::sink())?;
    file.seek(SeekFrom::Start(0)).map_err(|_| INVALID)?;
    let mut zip = ZipArchive::new(file).map_err(|_| INVALID)?;
    let (root, entries, extensions) = archive_entries(&mut zip)?;
    let identity = input_identity(&mut zip, &entries, &root)?;
    Ok(UnsignedInput {
        identity,
        bytes,
        sha256,
        extensions: extensions.len(),
    })
}

pub(crate) fn stage_unsigned(
    path: &Path,
    expected: &str,
    workspace: &Path,
) -> Result<(PathBuf, Identity)> {
    let mut file = open_ipa(path)?;
    let mut scratch = tempfile::tempfile_in(workspace).map_err(|_| Issue::storage())?;
    let (_, sha256) = digest(&mut file, &mut scratch)?;
    if sha256 != expected {
        return Err(Issue::new(
            "ipa_changed",
            "Choisis de nouveau l’IPA dont l’empreinte a changé.",
        ));
    }
    scratch.seek(SeekFrom::Start(0)).map_err(|_| INVALID)?;
    let mut zip = ZipArchive::new(scratch).map_err(|_| INVALID)?;
    let (root, entries, extensions) = archive_entries(&mut zip)?;
    if !extensions.is_empty() {
        return Err(Issue::new("extension_identity_unverified", "La préparation exige les droits et profils propres aux extensions. Ce lot accepte une app MGM seule."));
    }
    let identity = input_identity(&mut zip, &entries, &root)?;
    let mut names = BTreeSet::new();
    for (name, index) in entries {
        if !name
            .strip_prefix(&root)
            .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with('/'))
        {
            continue;
        }
        if !names.insert(name.to_lowercase())
            || name.split('/').any(|part| part.ends_with(['.', ' ']))
        {
            return Err(INVALID);
        }
        let mut entry = zip.by_index(index).map_err(|_| INVALID)?;
        let output = workspace.join(&name);
        if entry.is_dir() {
            fs::create_dir_all(output).map_err(|_| INVALID)?;
        } else {
            fs::create_dir_all(output.parent().ok_or(INVALID)?).map_err(|_| INVALID)?;
            let mut out = File::options()
                .write(true)
                .create_new(true)
                .open(output)
                .map_err(|_| INVALID)?;
            std::io::copy(&mut entry, &mut out).map_err(|_| INVALID)?;
        }
    }
    Ok((workspace.join(root), identity))
}

fn input_identity(
    zip: &mut ZipArchive<File>,
    entries: &BTreeMap<String, usize>,
    root: &str,
) -> Result<Identity> {
    let info: Dictionary = plist::from_bytes(&read_entry(
        zip,
        entries,
        &format!("{root}/Info.plist"),
        MAX_PLIST,
        INVALID,
    )?)
    .map_err(|_| INVALID)?;
    Ok(Identity {
        bundle: field(&info, "CFBundleIdentifier", INVALID)?,
        version: field(&info, "CFBundleShortVersionString", INVALID)?,
        build: field(&info, "CFBundleVersion", INVALID)?,
    })
}

pub(crate) fn pack_signed(app: &Path, output: &Path) -> Result<()> {
    fn pack(archive: &mut ZipWriter<File>, directory: &Path, base: &Path) -> Result<()> {
        for item in fs::read_dir(directory).map_err(|_| INVALID)? {
            let item = item.map_err(|_| INVALID)?;
            let kind = item.file_type().map_err(|_| INVALID)?;
            if kind.is_dir() {
                pack(archive, &item.path(), base)?;
            } else if kind.is_file() {
                let path = item.path();
                let name = path
                    .strip_prefix(base)
                    .map_err(|_| INVALID)?
                    .to_str()
                    .ok_or(INVALID)?
                    .replace('\\', "/");
                archive
                    .start_file(
                        name,
                        SimpleFileOptions::default()
                            .compression_method(zip::CompressionMethod::Deflated)
                            .unix_permissions(0o755),
                    )
                    .map_err(|_| INVALID)?;
                std::io::copy(&mut File::open(path).map_err(|_| INVALID)?, archive)
                    .map_err(|_| INVALID)?;
            } else {
                return Err(INVALID);
            }
        }
        Ok(())
    }
    let payload = app.parent().ok_or(INVALID)?;
    let base = payload.parent().ok_or(INVALID)?;
    let mut archive = ZipWriter::new(
        File::options()
            .write(true)
            .create_new(true)
            .open(output)
            .map_err(|_| Issue::storage())?,
    );
    pack(&mut archive, payload, base)?;
    archive
        .finish()
        .map_err(|_| INVALID)?
        .sync_all()
        .map_err(|_| Issue::storage())
}

pub(crate) fn check_profile(
    bytes: &[u8],
    bundle: &str,
    device: &str,
    identity: &DataIdentity,
) -> Result<()> {
    let (team, _, prefix) = profile_metadata(bytes, bundle, Some(device))?;
    if identity.team != team || identity.application_identifier != format!("{prefix}.{bundle}") {
        return Err(PROFILE);
    }
    Ok(())
}

pub fn inspect(path: &Path, device: Option<&str>) -> Result<Inspection> {
    let mut file = open_ipa(path)?;
    let (bytes, sha256) = digest(&mut file, std::io::sink())?;
    file.seek(SeekFrom::Start(0)).map_err(|_| INVALID)?;
    examine(file, bytes, sha256, device)
}

/// Snapshot bytes before transfer so the user-approved digest binds the data sent over AFC.
pub fn snapshot(path: &Path, directory: &Path, device: &str) -> Result<(Inspection, File)> {
    let mut file = open_ipa(path)?;
    let mut copy = tempfile::tempfile_in(directory).map_err(|_| Issue::storage())?;
    let (bytes, sha256) = digest(&mut file, &mut copy)?;
    copy.sync_all().map_err(|_| Issue::storage())?;
    copy.seek(SeekFrom::Start(0))
        .map_err(|_| Issue::storage())?;
    let readback = copy.try_clone().map_err(|_| Issue::storage())?;
    let verified = examine(readback, bytes, sha256, Some(device))?;
    copy.seek(SeekFrom::Start(0))
        .map_err(|_| Issue::storage())?;
    Ok((verified, copy))
}

fn open_ipa(path: &Path) -> Result<File> {
    let metadata = std::fs::metadata(path).map_err(|_| INVALID)?;
    if !metadata.is_file() || !(1..=MAX_IPA).contains(&metadata.len()) {
        return Err(Issue::new(
            "ipa_size",
            "Choisis une IPA ordinaire de 512 Mio ou moins.",
        ));
    }
    File::open(path).map_err(|_| INVALID)
}

fn digest(mut source: impl Read, mut destination: impl Write) -> Result<(u64, String)> {
    let mut buffer = vec![0u8; 256 * 1024];
    let mut hash = Sha256::new();
    let mut bytes = 0;
    loop {
        let count = source.read(&mut buffer).map_err(|_| INVALID)?;
        if count == 0 {
            break;
        }
        bytes += count as u64;
        if bytes > MAX_IPA {
            return Err(INVALID);
        }
        let chunk = &buffer[..count];
        destination.write_all(chunk).map_err(|_| Issue::storage())?;
        hash.update(chunk);
    }
    Ok((bytes, format!("{:x}", hash.finalize())))
}

fn examine(file: File, bytes: u64, sha256: String, selected: Option<&str>) -> Result<Inspection> {
    let mut zip = ZipArchive::new(file).map_err(|_| INVALID)?;
    let (root, entries, components) = archive_entries(&mut zip)?;
    let main = examine_component(&mut zip, &entries, &root, selected)?;
    let mut identities = BTreeSet::from([main.identity.bundle.clone()]);
    let mut verified = vec![main.clone()];
    for nested in components {
        let item = examine_component(&mut zip, &entries, &nested, selected)?;
        if !item
            .identity
            .bundle
            .starts_with(&format!("{}.", main.identity.bundle))
            || item.team != main.team
            || !identities.insert(item.identity.bundle.clone())
        {
            return Err(PROFILE);
        }
        verified.push(item);
    }
    Ok(Inspection {
        identity: main.identity,
        team: main.team,
        sha256,
        bytes,
        components: verified,
        apple_verification: "device_acceptance_required",
    })
}

fn archive_entries(
    zip: &mut ZipArchive<File>,
) -> Result<(String, BTreeMap<String, usize>, BTreeSet<String>)> {
    if zip.len() > 30_000 {
        return Err(INVALID);
    }
    let mut sizes = 0u64;
    let mut entries = BTreeMap::new();
    let mut root = BTreeSet::new();
    let mut components = BTreeSet::new();
    for i in 0..zip.len() {
        let file = zip.by_index(i).map_err(|_| INVALID)?;
        let name = file.name().trim_end_matches('/');
        if name.is_empty()
            || name.contains(['\\', ':', '\0'])
            || name.chars().any(char::is_control)
            || name
                .split('/')
                .any(|s| s.is_empty() || matches!(s, "." | ".."))
            || file.is_symlink()
            || file.encrypted()
            || entries.insert(name.to_owned(), i).is_some()
        {
            return Err(INVALID);
        }
        sizes = sizes
            .checked_add(file.size())
            .filter(|x| *x <= MAX_EXPANDED)
            .ok_or(INVALID)?;
        let parts: Vec<_> = name.split('/').collect();
        if parts.len() < 2 || parts[0] != "Payload" {
            continue;
        }
        if !parts[1].ends_with(".app") {
            return Err(INVALID);
        }
        root.insert(format!("Payload/{}", parts[1]));
        if parts.len() >= 4 && ["Watch", "AppClips"].contains(&parts[2]) {
            return Err(Issue::new("nested_app_unsupported", "Ce parcours couvre les extensions iPhone. Les apps Watch et App Clips exigent une recette distincte."));
        }
        if parts.len() >= 4 && parts[2] == "PlugIns" && parts[3].ends_with(".appex") {
            components.insert(parts[..4].join("/"));
        }
    }
    if root.len() != 1 || components.len() > 32 {
        return Err(INVALID);
    }
    Ok((root.pop_first().ok_or(INVALID)?, entries, components))
}

fn read_entry(
    zip: &mut ZipArchive<File>,
    entries: &BTreeMap<String, usize>,
    name: &str,
    max: u64,
    missing: Issue,
) -> Result<Vec<u8>> {
    let file = zip
        .by_index(*entries.get(name).ok_or(missing)?)
        .map_err(|_| INVALID)?;
    if file.is_dir() || file.size() == 0 || file.size() > max {
        return Err(INVALID);
    }
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| INVALID)?;
    if bytes.len() as u64 > max {
        return Err(INVALID);
    }
    Ok(bytes)
}

fn examine_component(
    zip: &mut ZipArchive<File>,
    entries: &BTreeMap<String, usize>,
    root: &str,
    selected: Option<&str>,
) -> Result<Component> {
    let info: Dictionary = plist::from_bytes(&read_entry(
        zip,
        entries,
        &format!("{root}/Info.plist"),
        MAX_PLIST,
        INVALID,
    )?)
    .map_err(|_| INVALID)?;
    let bundle = field(&info, "CFBundleIdentifier", INVALID)?;
    if !bundle.contains('.')
        || !bundle
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-')
    {
        return Err(INVALID);
    }
    let identity = Identity {
        bundle,
        version: field(&info, "CFBundleShortVersionString", INVALID)?,
        build: field(&info, "CFBundleVersion", INVALID)?,
    };
    let profile = read_entry(
        zip,
        entries,
        &format!("{root}/embedded.mobileprovision"),
        MAX_PLIST,
        NO_PROFILE,
    )?;
    let (team, expires, prefix) = profile_metadata(&profile, &identity.bundle, selected)?;
    let exec = field(&info, "CFBundleExecutable", INVALID)?;
    if exec.contains(['/', '\\', ':']) || matches!(exec.as_str(), "." | "..") {
        return Err(INVALID);
    }
    let binary = read_entry(
        zip,
        entries,
        &format!("{root}/{exec}"),
        MAX_EXECUTABLE,
        SIGNATURE,
    )?;
    let signed = arm64_codesign(&binary).ok_or(SIGNATURE)?;
    let data_identity = signed.and_then(|bytes| {
        let entitlements: Dictionary = plist::from_bytes(bytes).ok()?;
        let claims = DataIdentity::read(&entitlements, &identity.bundle)?;
        (claims.team == team && claims.application_identifier.split_once('.')?.0 == prefix)
            .then_some(claims)
    });
    Ok(Component {
        identity,
        team,
        expires,
        data_identity,
    })
}

fn field(info: &Dictionary, key: &str, error: Issue) -> Result<String> {
    match info.get(key).and_then(Value::as_string) {
        Some(value) if (1..=240).contains(&value.len()) && !value.chars().any(char::is_control) => {
            Ok(value.to_owned())
        }
        _ => Err(error),
    }
}

fn profile_metadata(
    bytes: &[u8],
    bundle: &str,
    selected: Option<&str>,
) -> Result<(String, String, String)> {
    let container = ContentInfo::from_der(bytes).map_err(|_| PROFILE)?;
    if container.content_type.to_string() != "1.2.840.113549.1.7.2" {
        return Err(PROFILE);
    }
    let body = SignedData::from_der(&container.content.to_der().map_err(|_| PROFILE)?)
        .map_err(|_| PROFILE)?;
    if body.signer_infos.0.is_empty()
        || body.encap_content_info.econtent_type.to_string() != "1.2.840.113549.1.7.1"
    {
        return Err(PROFILE);
    }
    let data = body
        .encap_content_info
        .econtent
        .ok_or(PROFILE)?
        .decode_as::<OctetString>()
        .map_err(|_| PROFILE)?;
    let profile: Dictionary = plist::from_bytes(data.as_bytes()).map_err(|_| PROFILE)?;
    let expiry = profile
        .get("ExpirationDate")
        .and_then(Value::as_date)
        .ok_or(PROFILE)?;
    let now = SystemTime::now();
    if SystemTime::from(expiry) <= now {
        return Err(EXPIRED);
    }
    let created = profile
        .get("CreationDate")
        .and_then(Value::as_date)
        .ok_or(PROFILE)?;
    if SystemTime::from(created) > now || SystemTime::from(created) >= SystemTime::from(expiry) {
        return Err(PROFILE);
    }
    let devices = profile
        .get("ProvisionedDevices")
        .and_then(Value::as_array)
        .filter(|x| !x.is_empty())
        .ok_or(DEVICE)?;
    if selected.is_some_and(|id| {
        !devices.iter().any(|value| {
            value
                .as_string()
                .is_some_and(|v| v.eq_ignore_ascii_case(id))
        })
    }) {
        return Err(DEVICE);
    }
    if !profile
        .get("Platform")
        .and_then(Value::as_array)
        .is_some_and(|items| items.iter().any(|v| v.as_string() == Some("iOS")))
    {
        return Err(PROFILE);
    }
    let entitlements = profile
        .get("Entitlements")
        .and_then(Value::as_dictionary)
        .ok_or(PROFILE)?;
    let team = field(entitlements, "com.apple.developer.team-identifier", PROFILE)?;
    if !profile
        .get("TeamIdentifier")
        .and_then(Value::as_array)
        .is_some_and(|values| values.iter().any(|v| v.as_string() == Some(&team)))
    {
        return Err(PROFILE);
    }
    let application = field(entitlements, "application-identifier", PROFILE)?;
    let (prefix, name) = application.split_once('.').ok_or(PROFILE)?;
    let registered_prefix = profile
        .get("ApplicationIdentifierPrefix")
        .and_then(Value::as_array)
        .is_some_and(|values| values.iter().any(|v| v.as_string() == Some(prefix)));
    let wildcard = name
        .strip_suffix('*')
        .filter(|name| name.is_empty() || name.ends_with('.'));
    if !registered_prefix
        || !(name == bundle || wildcard.is_some_and(|prefix| bundle.starts_with(prefix)))
    {
        return Err(PROFILE);
    }
    Ok((team, expiry.to_xml_format(), prefix.to_owned()))
}

fn be(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        data.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}
fn le(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn arm64_codesign(mut data: &[u8]) -> Option<Option<&[u8]>> {
    if be(data, 0)? == 0xcafebabe {
        let count = be(data, 4)?.min(32);
        let arm = (0..count as usize)
            .map(|i| 8 + i * 20)
            .find(|&i| be(data, i) == Some(0x0100000c))?;
        let start = be(data, arm + 8)? as usize;
        let end = start.checked_add(be(data, arm + 12)? as usize)?;
        data = data.get(start..end)?;
    }
    if le(data, 0)? != 0xfeedfacf || le(data, 4)? != 0x0100000c {
        return None;
    }
    let mut cursor = 32usize;
    let end = cursor.checked_add(le(data, 20)? as usize)?;
    if end > data.len() {
        return None;
    }
    for _ in 0..le(data, 16)?.min(8_192) {
        let command = le(data, cursor)?;
        let step = le(data, cursor + 4)? as usize;
        let next = cursor.checked_add(step)?;
        if step < 8 || next > end {
            return None;
        }
        if command == 0x1d && step >= 16 {
            let start = le(data, cursor + 8)? as usize;
            let size = le(data, cursor + 12)? as usize;
            let signature = data.get(start..start.checked_add(size)?)?;
            if be(signature, 0)? != 0xfade0cc0 {
                return None;
            }
            let signature = signature.get(..be(signature, 4)? as usize)?;
            let mut has_cms = false;
            let mut has_code = false;
            let mut entitlements = None;
            for i in 0..be(signature, 8)?.min(128) as usize {
                let kind = be(signature, 12 + i * 8)?;
                let slot = be(signature, 16 + i * 8)? as usize;
                let magic = be(signature, slot)?;
                let length = be(signature, slot.checked_add(4)?)? as usize;
                if length <= 8 || slot.checked_add(length)? > signature.len() {
                    return None;
                }
                has_cms |= kind == 0x10000 && magic == 0xfade0b01;
                has_code |= kind == 0 && magic == 0xfade0c02;
                if kind == 5 && magic == 0xfade7171 {
                    if entitlements
                        .replace(signature.get(slot + 8..slot + length)?)
                        .is_some()
                    {
                        return None;
                    }
                }
            }
            return (has_cms && has_code).then_some(entitlements);
        }
        cursor = next;
    }
    None
}
