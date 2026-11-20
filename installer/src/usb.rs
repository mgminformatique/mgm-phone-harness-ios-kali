use crate::{
    ipa::{DataIdentity, Identity},
    Issue, Result, BUNDLE_ID,
};
use idevice::provider::{IdeviceProvider, UsbmuxdProvider};
use idevice::services::{
    afc::{errors::AfcError, opcode::AfcFopenMode, AfcClient},
    installation_proxy::{InstallationProxyClient, InstallationProxyError},
    lockdown::LockdownClient,
};
use idevice::usbmuxd::{Connection, UsbmuxdAddr, UsbmuxdDevice};
use idevice::{IdeviceError, IdeviceService};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs::File, time::Duration};
use tokio::{io::AsyncReadExt, time::timeout};

const TIMEOUT: Issue = Issue::new(
    "usb_timeout",
    "Le service iPhone n’a pas répondu. Vérifie le câble et l’état de l’iPhone.",
);
const SERVICE: Issue = Issue::new(
    "usb_service_unreachable",
    if cfg!(target_os = "linux") {
        "Le service usbmuxd est inaccessible. Branche l’iPhone au poste Kali et vérifie que le service démarre."
    } else {
        "Le service USB de l’iPhone est inaccessible. Vérifie le service de jumelage du poste."
    },
);
const PAIR: Issue = Issue::new(
    "trust_required",
    "Déverrouille l’iPhone et accorde la confiance à cet ordinateur.",
);
const ABSENT: Issue = Issue::new(
    "iphone_unavailable",
    "L’iPhone sélectionné est indisponible par USB.",
);
const LOCKED: Issue = Issue::new(
    "iphone_locked",
    "Déverrouille l’iPhone et refais le diagnostic.",
);
const USB_IO: Issue = Issue::new(
    "usb_io",
    "La communication USB avec l’iPhone a été interrompue.",
);
const LOOKUP: Issue = Issue::new(
    "inventory_unavailable",
    "Impossible de relire l’identité installée via le service iOS.",
);
const STAGING: Issue = Issue::new(
    "transfer_unverified",
    "Le transfert de l’IPA vers l’iPhone n’a pas pu être vérifié.",
);
const DEVICE_STORAGE_FULL: Issue = Issue::new(
    "device_storage_full",
    "Espace insuffisant signalé par l’iPhone pendant le transfert. L’installation n’a pas été demandée. Libère de l’espace sur l’appareil, puis relance l’opération.",
);
const REJECTED: Issue = Issue::new(
    "ios_rejected",
    "iOS a refusé la demande. Vérifie la signature, le profil et l’équipe de l’app installée.",
);

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Installed {
    pub identity: Identity,
    pub team: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_identity: Option<DataIdentity>,
}

#[derive(Debug, Serialize)]
pub struct Device {
    pub udid: String,
    pub label: String,
    pub product: Option<String>,
    pub os: Option<String>,
    pub session_ready: bool,
    pub issue: Option<Issue>,
}

#[async_trait::async_trait]
pub trait Access: Send + Sync {
    async fn lookup(&self, udid: &str, bundle: &str) -> Result<Option<Installed>>;
    async fn lookup_mgm(&self, udid: &str) -> Result<Option<Installed>> {
        self.lookup(udid, BUNDLE_ID).await
    }
    async fn stage(
        &self,
        udid: &str,
        destination: &str,
        input: File,
        bytes: u64,
        sha256: &str,
    ) -> Result<()>;
    async fn install(
        &self,
        udid: &str,
        destination: &str,
        bundle: &str,
        upgrade: bool,
    ) -> Result<()>;
    async fn cleanup(&self, udid: &str, destination: &str) -> Result<()>;
}

pub struct NativeUsb;

pub(crate) fn mgm_alias_team(bundle: &str) -> Option<&str> {
    bundle
        .strip_prefix(BUNDLE_ID)?
        .strip_prefix('.')
        .filter(|suffix| {
            suffix.len() == 10
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        })
}

fn installed_entry(bundle: &str, entry: &plist::Value) -> Result<Installed> {
    let info = entry.as_dictionary().ok_or(LOOKUP)?;
    let text = |key| {
        info.get(key)
            .and_then(clean_field)
            .map(str::to_owned)
            .ok_or(LOOKUP)
    };
    let identity = Identity {
        bundle: text("CFBundleIdentifier")?,
        build: text("CFBundleVersion")?,
        version: text("CFBundleShortVersionString")?,
    };
    if identity.bundle != bundle {
        return Err(LOOKUP);
    }
    let entitlements = info
        .get("Entitlements")
        .and_then(plist::Value::as_dictionary);
    let team = entitlements
        .and_then(|value| value.get("com.apple.developer.team-identifier"))
        .or_else(|| info.get("TeamIdentifier"))
        .and_then(clean_field)
        .map(str::to_owned);
    let data_identity = entitlements.and_then(|value| DataIdentity::read(value, bundle));
    Ok(Installed {
        identity,
        team,
        data_identity,
    })
}

impl NativeUsb {
    async fn lookup_entries(
        udid: &str,
        bundle: Option<&str>,
    ) -> Result<std::collections::HashMap<String, plist::Value>> {
        let provider = Self::provider(udid).await?;
        let mut service = InstallationProxyClient::connect(&provider)
            .await
            .map_err(local_error)?;
        service
            .get_apps(Some("User"), bundle.map(|id| vec![id.to_owned()]))
            .await
            .map_err(|_| LOOKUP)
    }

    async fn lookup_identity(udid: &str, bundle: &str, entry: &plist::Value) -> Result<Installed> {
        let basic = installed_entry(bundle, entry)?;
        if basic.data_identity.is_some() {
            return Ok(basic);
        }
        let inventory = Self::inventory(udid).await?;
        let observed = installed_entry(bundle, inventory.get(bundle).ok_or(LOOKUP)?)?;
        if observed.identity != basic.identity
            || basic
                .team
                .as_ref()
                .is_some_and(|team| observed.team.as_ref() != Some(team))
        {
            return Err(LOOKUP);
        }
        Ok(observed)
    }

    async fn inventory(udid: &str) -> Result<plist::Dictionary> {
        let provider = Self::provider(udid).await?;
        let mut service = InstallationProxyClient::connect(&provider)
            .await
            .map_err(local_error)?;
        // Installation Proxy's default Lookup omits signed entitlements on the device.
        let mut options = plist::Dictionary::new();
        options.insert("ApplicationType".into(), "User".into());
        let attributes = [
            "CFBundleIdentifier",
            "CFBundleVersion",
            "CFBundleShortVersionString",
            "Entitlements",
            "TeamIdentifier",
        ]
        .into_iter()
        .map(|key| plist::Value::String(key.into()))
        .collect();
        options.insert("ReturnAttributes".into(), plist::Value::Array(attributes));
        let apps = service
            .browse(Some(plist::Value::Dictionary(options)))
            .await
            .map_err(|_| LOOKUP)?;
        let mut entries = plist::Dictionary::new();
        for app in apps {
            let id = app
                .as_dictionary()
                .and_then(|item| item.get("CFBundleIdentifier"))
                .and_then(clean_field)
                .ok_or(LOOKUP)?
                .to_owned();
            if entries.insert(id, app).is_some() {
                return Err(LOOKUP);
            }
        }
        Ok(entries)
    }
    async fn devices() -> Result<Vec<UsbmuxdDevice>> {
        // The OS's local broker is the only transport used by the installer.
        let mut mux = timeout(Duration::from_secs(4), UsbmuxdAddr::default().connect(1))
            .await
            .map_err(|_| SERVICE)?
            .map_err(|_| SERVICE)?;
        let items = timeout(Duration::from_secs(5), mux.get_devices())
            .await
            .map_err(|_| TIMEOUT)?
            .map_err(|_| SERVICE)?;
        Ok(items
            .into_iter()
            .filter(|d| d.connection_type == Connection::Usb && crate::device_key(&d.udid).is_ok())
            .take(32)
            .collect())
    }

    async fn provider(udid: &str) -> Result<UsbmuxdProvider> {
        let entry = Self::devices()
            .await?
            .into_iter()
            .find(|d| d.udid.eq_ignore_ascii_case(udid))
            .ok_or(ABSENT)?;
        let provider = entry.to_provider(UsbmuxdAddr::default(), "MGM iOS Installer");
        let mut session = LockdownClient::connect(&provider)
            .await
            .map_err(local_error)?;
        let pair = provider.get_pairing_file().await.map_err(pairing_error)?;
        session.start_session(&pair).await.map_err(local_error)?;
        let verified_udid = read_string(&mut session, "UniqueDeviceID").await?;
        if !verified_udid.eq_ignore_ascii_case(udid) {
            return Err(ABSENT);
        }
        let product = read_string(&mut session, "ProductType").await?;
        let _ = session.stop_session().await;
        if product.starts_with("iPhone") {
            return Ok(provider);
        }
        Err(Issue::new(
            "unsupported_product",
            "Ce parcours est réservé à un iPhone branché par USB.",
        ))
    }

    pub async fn diagnose(&self) -> Result<Vec<Device>> {
        let mut report = Vec::new();
        for item in Self::devices().await? {
            let provider = item.to_provider(UsbmuxdAddr::default(), "MGM iOS Installer");
            let mut description = Device {
                udid: item.udid,
                label: "Appareil USB Apple".into(),
                product: None,
                os: None,
                session_ready: false,
                issue: None,
            };
            let check = timeout(Duration::from_secs(8), async {
                let mut lockdown = LockdownClient::connect(&provider)
                    .await
                    .map_err(local_error)?;
                if let Ok(model) = read_string(&mut lockdown, "ProductType").await {
                    description.label = model.clone();
                    description.product = Some(model);
                }
                description.os = read_string(&mut lockdown, "ProductVersion").await.ok();
                let pair = provider.get_pairing_file().await.map_err(pairing_error)?;
                lockdown.start_session(&pair).await.map_err(local_error)?;
                let model = read_string(&mut lockdown, "ProductType").await?;
                let verified = read_string(&mut lockdown, "UniqueDeviceID").await?;
                if !verified.eq_ignore_ascii_case(&description.udid) {
                    return Err(ABSENT);
                }
                if !model.starts_with("iPhone") {
                    return Err(Issue::new(
                        "unsupported_product",
                        "Cet appareil USB n’est pas un iPhone.",
                    ));
                }
                description.product = Some(model.clone());
                description.label = model;
                if description.os.is_none() {
                    description.os = read_string(&mut lockdown, "ProductVersion").await.ok();
                }
                let _ = lockdown.stop_session().await;
                Ok(())
            })
            .await
            .map_err(|_| TIMEOUT)
            .and_then(|outcome| outcome);
            description.session_ready = check.is_ok();
            description.issue = check.err();
            report.push(description);
        }
        Ok(report)
    }
}

#[async_trait::async_trait]
impl Access for NativeUsb {
    async fn lookup(&self, udid: &str, bundle: &str) -> Result<Option<Installed>> {
        timeout(Duration::from_secs(15), async {
            let result = Self::lookup_entries(udid, Some(bundle)).await?;
            match result.get(bundle) {
                Some(entry) => Ok(Some(Self::lookup_identity(udid, bundle, entry).await?)),
                None => Ok(None),
            }
        })
        .await
        .map_err(|_| TIMEOUT)?
    }

    async fn lookup_mgm(&self, udid: &str) -> Result<Option<Installed>> {
        timeout(Duration::from_secs(15), async {
            let inventory = Self::lookup_entries(udid, None).await?;
            let mut matching = inventory.iter().filter(|(id, _)| id.as_str() == BUNDLE_ID || mgm_alias_team(id).is_some());
            let found = matching.next();
            if matching.next().is_some() {
                return Err(Issue::new("installed_bundle_ambiguous", "Plusieurs identités Agent Admin sont installées. Vérifie le conteneur à préserver."));
            }
            match found {
                Some((id, entry)) => Ok(Some(Self::lookup_identity(udid, id, entry).await?)),
                None => Ok(None),
            }
        }).await.map_err(|_| TIMEOUT)?
    }

    async fn stage(
        &self,
        udid: &str,
        destination: &str,
        input: File,
        expected: u64,
        sha256: &str,
    ) -> Result<()> {
        let provider = Self::provider(udid).await?;
        let mut afc = AfcClient::connect(&provider).await.map_err(local_error)?;
        let dir = match afc.get_file_info("PublicStaging").await {
            Ok(dir) => dir,
            Err(IdeviceError::Afc(AfcError::ObjectNotFound)) => {
                match afc.mk_dir("PublicStaging").await {
                    Ok(()) | Err(IdeviceError::Afc(AfcError::ObjectExists)) => {}
                    Err(error) => return Err(transfer_error(error)),
                }
                afc.get_file_info("PublicStaging")
                    .await
                    .map_err(transfer_error)?
            }
            Err(error) => return Err(transfer_error(error)),
        };
        if dir.st_ifmt != "S_IFDIR" {
            return Err(STAGING);
        }
        let mut local = tokio::fs::File::from_std(input);
        let mut buffer = vec![0; 256 * 1024];
        let mut output = afc
            .open(destination, AfcFopenMode::Wr)
            .await
            .map_err(transfer_error)?;
        let mut sent = 0;
        loop {
            let n = local.read(&mut buffer).await.map_err(|_| STAGING)?;
            if n == 0 {
                break;
            }
            sent += n as u64;
            if sent > expected {
                return Err(STAGING);
            }
            output
                .write_entire(&buffer[..n])
                .await
                .map_err(transfer_error)?;
        }
        output.close().await.map_err(transfer_error)?;
        let file = afc
            .get_file_info(destination)
            .await
            .map_err(transfer_error)?;
        if sent != expected || file.size as u64 != expected || file.st_ifmt != "S_IFREG" {
            return Err(STAGING);
        }
        let mut remote = afc
            .open(destination, AfcFopenMode::RdOnly)
            .await
            .map_err(transfer_error)?;
        let mut hash = Sha256::new();
        let mut read = 0;
        while read < expected {
            let bytes = remote
                .read_n((expected - read).min(buffer.len() as u64) as usize)
                .await
                .map_err(transfer_error)?;
            if bytes.is_empty() || bytes.len() as u64 > expected - read {
                return Err(STAGING);
            }
            read += bytes.len() as u64;
            hash.update(bytes);
        }
        remote.close().await.map_err(transfer_error)?;
        if format!("{:x}", hash.finalize()) != sha256 {
            return Err(STAGING);
        }
        Ok(())
    }

    async fn install(
        &self,
        udid: &str,
        destination: &str,
        bundle: &str,
        upgrade: bool,
    ) -> Result<()> {
        let provider = Self::provider(udid).await?;
        let mut service = InstallationProxyClient::connect(&provider)
            .await
            .map_err(local_error)?;
        let mut options = plist::Dictionary::new();
        options.insert(
            "CFBundleIdentifier".into(),
            plist::Value::String(bundle.into()),
        );
        let options = Some(plist::Value::Dictionary(options));
        let result = if upgrade {
            service.upgrade(destination, options).await
        } else {
            service.install(destination, options).await
        };
        result.map_err(|error| match error {
            IdeviceError::ApplicationVerificationFailed(_) => Issue::new(
                "ios_signature_rejected",
                "iOS a refusé la vérification de l’application. Vérifie la signature et les profils embarqués.",
            ),
            IdeviceError::DeveloperModeNotEnabled => Issue::new(
                "ios_developer_mode_required",
                "iOS exige le mode développeur pour lancer ce build de développement.",
            ),
            IdeviceError::InstallationProxy(InstallationProxyError::OperationFailed(_))
            | IdeviceError::UnknownErrorType(_) => REJECTED,
            other => local_error(other),
        })
    }

    async fn cleanup(&self, udid: &str, destination: &str) -> Result<()> {
        timeout(Duration::from_secs(8), async {
            let provider = Self::provider(udid).await?;
            let mut afc = AfcClient::connect(&provider).await.map_err(local_error)?;
            match afc.remove(destination).await {
                Ok(()) | Err(IdeviceError::Afc(AfcError::ObjectNotFound)) => Ok(()),
                Err(_) => Err(STAGING),
            }
        })
        .await
        .map_err(|_| TIMEOUT)?
    }
}

fn clean_field(value: &plist::Value) -> Option<&str> {
    value
        .as_string()
        .filter(|value| (1..=240).contains(&value.len()) && !value.chars().any(char::is_control))
}

async fn read_string(lockdown: &mut LockdownClient, key: &str) -> Result<String> {
    let value = lockdown
        .get_value(Some(key), None)
        .await
        .map_err(local_error)?;
    clean_field(&value).map(str::to_owned).ok_or(USB_IO)
}

fn local_error(error: IdeviceError) -> Issue {
    match error {
        IdeviceError::DeviceNotFound => ABSENT,
        IdeviceError::DeviceLocked => LOCKED,
        IdeviceError::InvalidHostID => PAIR,
        IdeviceError::UnknownErrorType(value) if value == "PasswordProtected" => LOCKED,
        IdeviceError::UnknownErrorType(value)
            if matches!(
                value.as_str(),
                "PairingDialogResponsePending" | "UserDeniedPairing"
            ) =>
        {
            PAIR
        }
        _ => USB_IO,
    }
}

/// Classifies native AFC and connection errors raised during staging.
pub fn transfer_error(error: IdeviceError) -> Issue {
    let issue = match &error {
        IdeviceError::Afc(AfcError::NoSpaceLeft) => DEVICE_STORAGE_FULL,
        IdeviceError::Afc(AfcError::ServiceNotConnected | AfcError::MuxError)
        | IdeviceError::Socket(_)
        | IdeviceError::NoEstablishedConnection => USB_IO,
        _ => STAGING,
    };
    issue.with_source(error)
}

fn pairing_error(error: IdeviceError) -> Issue {
    if matches!(error, IdeviceError::DeviceLocked) {
        LOCKED
    } else {
        PAIR
    }
}
