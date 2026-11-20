//! Account and signing preparation. USB submission stays in `operation::Engine`.
use crate::{
    device_key,
    ipa::{self, DataIdentity, Inspection},
    operation::preflight_target,
    usb::{Access, NativeUsb},
    Issue, Result, BUNDLE_ID,
};
use apple_codesign_quick::{
    sign_bundle, BundleSigningSettings, ProvisioningProfile, RustCryptoCmsSigner,
};
use der::{Decode, Encode};
use isideload::{
    anisette::{remote_v3::RemoteV3AnisetteProvider, AnisetteProvider},
    auth::apple_account::{AppleAccount, TwoFactorCallbackResponse},
    dev::{
        app_ids::AppIdsApi,
        certificates::{CertificatesApi, DevelopmentCertificate},
        developer_session::DeveloperSession,
        devices::DevicesApi,
        teams::{DeveloperTeam, TeamsApi},
    },
    sideload::cert_identity::CertificateIdentity,
    util::{
        keyring_storage::KeyringStorage,
        storage::{InMemoryStorage, SideloadingStorage},
    },
    SideloadError,
};
use plist::{Dictionary, Value};
use rcgen::{CertificateParams, DnType, KeyPair, PKCS_RSA_SHA256};
use reqwest::Url;
use rootcause::Report;
use rsa::{
    pkcs1::EncodeRsaPublicKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding},
    RsaPrivateKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    future::Future,
    io::Write,
    path::Path,
    sync::{
        atomic::{AtomicU8, Ordering},
        Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::time::timeout;
use x509_cert::Certificate;
use zeroize::Zeroizing;

const PROVIDER: Issue = Issue::new("anisette_unavailable", "Le fournisseur Anisette configuré est indisponible. Vérifie sa connexion et son certificat TLS.");
const AUTH: Issue = Issue::new("apple_authentication_failed", "Apple a refusé ou interrompu la connexion. Vérifie le compte et l’état indiqué avant de recommencer.");
const TWO_FACTOR: Issue = Issue::new(
    "apple_2fa_not_completed",
    "La validation Apple à deux facteurs a été refusée, annulée ou a expiré.",
);
const SESSION: Issue = Issue::new(
    "apple_session_expired",
    "La session développeur Apple a expiré. Reconnecte le même compte.",
);
const DEVELOPER: Issue = Issue::new(
    "apple_developer_unavailable",
    "Le service développeur Apple ne répond pas pour ce compte.",
);
const TEAM: Issue = Issue::new(
    "apple_team_mismatch",
    "Le compte Apple ne donne pas accès à l’équipe signataire de l’app installée.",
);
const PROFILE: Issue = Issue::new(
    "apple_profile_failed",
    "Apple n’a pas fourni de profil compatible avec l’app et l’iPhone sélectionnés.",
);
const CERTIFICATE: Issue = Issue::new("apple_certificate_failed", "Le certificat de l’équipe ou son coffre est indisponible. Vérifie les certificats existants avant de réessayer.");
const SIGN: Issue = Issue::new(
    "ipa_signing_failed",
    "La signature locale de l’IPA a échoué.",
);
const UPDATE: Issue = Issue::new(
    "installed_data_identity_unverified",
    "Sélectionne l’iPhone où l’identité signée d’Agent Admin est déjà lisible.",
);
const EXPIRED_OR_UNCERTAIN: Issue = Issue::new("apple_preparation_uncertain", "La préparation Apple n’a pas confirmé son résultat. Vérifie le compte et les certificats avant une nouvelle tentative.");

#[derive(Clone, Debug, Serialize)]
pub struct Challenge {
    pub sms: bool,
    pub choose: bool,
    pub rejected: bool,
    pub numbers: Vec<MaskedNumber>,
}

#[derive(Clone, Debug, Serialize)]
pub struct MaskedNumber {
    pub id: u32,
    pub suffix: String,
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Answer {
    Code { code: String },
    Sms { id: u32 },
    Device,
    Cancel,
}

impl Answer {
    fn response(self, challenge: &Challenge) -> TwoFactorCallbackResponse {
        match self {
            Self::Code { code }
                if !challenge.choose
                    && code.len() == 6
                    && code.bytes().all(|b| b.is_ascii_digit()) =>
            {
                TwoFactorCallbackResponse::SubmitCode(code)
            }
            Self::Device if challenge.choose => TwoFactorCallbackResponse::SendToDevices,
            Self::Sms { id } if challenge.numbers.iter().any(|n| n.id == id) => {
                TwoFactorCallbackResponse::SendSms(id)
            }
            _ => TwoFactorCallbackResponse::Abort,
        }
    }
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Provider,
    Authentication,
    DeveloperSession,
    Device,
    AppIdentifier,
    Certificate,
    Profile,
    Signing,
    FinalVerification,
}

pub struct Account {
    developer: DeveloperSession,
    email: String,
    teams: Vec<DeveloperTeam>,
    expires: Instant,
}

pub struct PreparedIpa {
    _directory: tempfile::TempDir,
    pub path: std::path::PathBuf,
    pub inspection: Inspection,
}

struct Audit(Mutex<File>);

impl Audit {
    fn open() -> Result<Self> {
        let root = crate::state_root()?.join("preparation");
        fs::create_dir_all(&root).map_err(|_| Issue::storage())?;
        let mut options = File::options();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(root.join(format!("{}.jsonl", uuid::Uuid::new_v4())))
            .map_err(|_| Issue::storage())?;
        Ok(Self(Mutex::new(file)))
    }

    fn record(&self, stage: Option<Stage>, outcome: Option<&'static str>) -> Result<()> {
        let mut file = self.0.lock().map_err(|_| Issue::storage())?;
        let at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        serde_json::to_writer(
            &mut *file,
            &serde_json::json!({"at":at,"stage":stage,"outcome":outcome}),
        )
        .map_err(|_| Issue::storage())?;
        file.write_all(b"\n")
            .and_then(|_| file.sync_data())
            .map_err(|_| Issue::storage())
    }
}

fn provider_url(origin: &str) -> Result<String> {
    let invalid = Issue::new(
        "anisette_configuration_required",
        "Configure l’origine HTTPS d’un fournisseur Anisette maîtrisé pour MGM.",
    );
    let url = Url::parse(origin.trim()).map_err(|_| invalid.clone())?;
    let host = url.host_str().ok_or_else(|| invalid.clone())?;
    let loopback = matches!(host, "127.0.0.1" | "localhost" | "[::1]");
    if !(url.scheme() == "https" || (loopback && url.scheme() == "http"))
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(invalid);
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

fn categorized(error: &Report, fallback: Issue) -> Issue {
    for layer in error.iter_reports() {
        if let Some(network) = layer.downcast_current_context::<reqwest::Error>() {
            match network.status().map(|s| s.as_u16()) {
                Some(429) => {
                    return Issue::new(
                        "apple_rate_limited",
                        "Le service demande d’attendre avant toute nouvelle tentative.",
                    )
                }
                Some(401) if fallback.code != PROVIDER.code => return SESSION,
                Some(500..=599) if fallback.code != PROVIDER.code => return Issue::new(
                    "apple_service_unavailable", "Le service Apple a renvoyé une erreur serveur. Attends avant de reprendre cette étape."),
                _ => {}
            }
        }
        if let Some(SideloadError::AuthWithMessage(-22411, _)) =
            layer.downcast_current_context::<SideloadError>()
        {
            return SESSION;
        }
    }
    fallback
}

fn configure_tls() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub async fn diagnose_provider(origin: &str) -> Result<()> {
    configure_tls();
    let url = provider_url(origin)?;
    let provider =
        RemoteV3AnisetteProvider::new(&url, Box::new(InMemoryStorage::new()), "0".into())
            .map_err(|_| PROVIDER)?;
    timeout(Duration::from_secs(10), provider.get_client_info())
        .await
        .map_err(|_| PROVIDER)?
        .map_err(|e| categorized(&e, PROVIDER))?;
    Ok(())
}

pub async fn connect<F, Fut>(
    origin: &str,
    email: String,
    password: Zeroizing<String>,
    report: impl Fn(Stage) + Send + Sync,
    challenge: F,
) -> Result<Account>
where
    F: Fn(Challenge) -> Fut + Send + Sync,
    Fut: Future<Output = Answer> + Send,
{
    let audit = Audit::open()?;
    audit.record(None, Some("login_started"))?;
    let result = connect_inner(
        origin,
        email,
        password,
        |stage| {
            let _ = audit.record(Some(stage), None);
            report(stage);
        },
        challenge,
    )
    .await;
    audit.record(
        None,
        Some(
            result
                .as_ref()
                .err()
                .map_or("session_ready", |issue| issue.code),
        ),
    )?;
    result
}

async fn connect_inner<F, Fut>(
    origin: &str,
    email: String,
    password: Zeroizing<String>,
    report: impl Fn(Stage) + Send + Sync,
    challenge: F,
) -> Result<Account>
where
    F: Fn(Challenge) -> Fut + Send + Sync,
    Fut: Future<Output = Answer> + Send,
{
    let email = email.trim().to_owned();
    if !email.contains('@')
        || email.len() > 254
        || email.chars().any(char::is_control)
        || password.is_empty()
        || password.len() > 1024
    {
        return Err(Issue::new(
            "apple_credentials_required",
            "Saisis le compte Apple et son mot de passe dans MGM.",
        ));
    }
    report(Stage::Provider);
    diagnose_provider(origin).await?;
    let url = provider_url(origin)?;
    let provider =
        RemoteV3AnisetteProvider::new(&url, Box::new(InMemoryStorage::new()), "0".into())
            .map_err(|_| PROVIDER)?;
    report(Stage::Authentication);
    let callbacks = AtomicU8::new(0);
    let build = AppleAccount::builder(&email)
        .anisette_provider(provider)
        .err_429_retries(None);
    let auth = build.login(
        &password,
        |params: isideload::auth::apple_account::TwoFactorCallbackParams| {
            let attempt = callbacks.fetch_add(1, Ordering::Relaxed);
            let callback = &challenge;
            async move {
                if attempt >= 4 {
                    return Ok(TwoFactorCallbackResponse::Abort);
                }
                let prompt = Challenge {
                    sms: params.sms,
                    choose: params.unknown,
                    rejected: params.last_error.is_some(),
                    numbers: params
                        .numbers
                        .into_iter()
                        .map(|n| MaskedNumber {
                            id: n.id,
                            suffix: n
                                .last_two_digits
                                .chars()
                                .filter(char::is_ascii_digit)
                                .take(2)
                                .collect(),
                        })
                        .collect(),
                };
                let reply = timeout(Duration::from_secs(120), callback(prompt.clone()))
                    .await
                    .unwrap_or(Answer::Cancel);
                Ok(reply.response(&prompt))
            }
        },
    );
    let mut account = timeout(Duration::from_secs(285), auth)
        .await
        .map_err(|_| {
            if callbacks.load(Ordering::Relaxed) != 0 {
                TWO_FACTOR
            } else {
                AUTH
            }
        })?
        .map_err(|e| {
            categorized(
                &e,
                if callbacks.load(Ordering::Relaxed) != 0 {
                    TWO_FACTOR
                } else {
                    AUTH
                },
            )
        })?;
    drop(password);
    report(Stage::DeveloperSession);
    let mut developer = timeout(
        Duration::from_secs(30),
        DeveloperSession::from_account(&mut account),
    )
    .await
    .map_err(|_| DEVELOPER)?
    .map_err(|e| categorized(&e, DEVELOPER))?;
    let teams = timeout(Duration::from_secs(30), developer.list_teams())
        .await
        .map_err(|_| DEVELOPER)?
        .map_err(|e| categorized(&e, DEVELOPER))?;
    Ok(Account {
        developer,
        email,
        teams,
        expires: Instant::now() + Duration::from_secs(20 * 60),
    })
}

async fn apple_call<T>(
    work: impl Future<Output = std::result::Result<T, Report>>,
    issue: Issue,
) -> Result<T> {
    timeout(Duration::from_secs(45), work)
        .await
        .map_err(|_| EXPIRED_OR_UNCERTAIN)?
        .map_err(|error| categorized(&error, issue))
}

const CERTIFICATE_LABEL: &str = "MGM iOS Installer";

async fn signing_identity(
    session: &mut DeveloperSession,
    team: &DeveloperTeam,
    email: &str,
) -> Result<CertificateIdentity> {
    let key_name = format!("{:x}/key", Sha256::digest(email.as_bytes()));
    let scope = format!("{:x}", Sha256::digest(key_name.as_bytes()));
    let root = crate::state_root()?.join("preparation");
    let lock = File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(root.join(format!("certificate-{scope}.lock")))
        .map_err(|_| Issue::storage())?;
    lock.try_lock().map_err(|_| {
        Issue::new(
            "apple_certificate_busy",
            "Une préparation utilise déjà le coffre de signature de ce compte.",
        )
    })?;
    let store = KeyringStorage::new(CERTIFICATE_LABEL.into());
    let prior = store.retrieve_data(&key_name).map_err(|_| CERTIFICATE)?;
    let private = if let Some(bytes) = prior {
        RsaPrivateKey::from_pkcs8_der(&Zeroizing::new(bytes)).map_err(|_| CERTIFICATE)?
    } else {
        let private = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).map_err(|_| CERTIFICATE)?;
        let pkcs8 = private.to_pkcs8_der().map_err(|_| CERTIFICATE)?;
        store
            .store_data(&key_name, pkcs8.as_bytes())
            .map_err(|_| CERTIFICATE)?;
        private
    };
    let public = private
        .to_public_key()
        .to_pkcs1_der()
        .map_err(|_| CERTIFICATE)?;
    let existing = apple_call(session.list_ios_certs(team), CERTIFICATE).await?;
    let matched = matching_certificate(&existing, public.as_bytes(), None)?;
    let (machine_id, certificate) = match matched {
        Some(pair) => pair,
        None => {
            let request = match timeout(
                Duration::from_secs(45),
                session.submit_development_csr(
                    team,
                    certificate_request(&private)?,
                    CERTIFICATE_LABEL.into(),
                    None,
                ),
            )
            .await
            {
                Ok(Ok(request)) => request,
                Ok(Err(error))
                    if error.iter_reports().any(|layer| {
                        matches!(
                            layer.downcast_current_context::<SideloadError>(),
                            Some(SideloadError::DeveloperError(7460, _))
                        )
                    }) =>
                {
                    return Err(Issue::new(
                        "apple_certificate_limit",
                        "Apple a atteint la limite de certificats. MGM a conservé les certificats existants.",
                    ));
                }
                _ => return Err(EXPIRED_OR_UNCERTAIN),
            };
            let updated = apple_call(session.list_ios_certs(team), EXPIRED_OR_UNCERTAIN)
                .await
                .map_err(|_| EXPIRED_OR_UNCERTAIN)?;
            matching_certificate(&updated, public.as_bytes(), Some(&request.cert_request_id))
                .map_err(|_| EXPIRED_OR_UNCERTAIN)?
                .ok_or(EXPIRED_OR_UNCERTAIN)?
        }
    };
    Ok(CertificateIdentity {
        machine_id,
        machine_name: CERTIFICATE_LABEL.into(),
        certificate,
        private_key: private,
    })
}

fn matching_certificate(
    candidates: &[DevelopmentCertificate],
    public_key: &[u8],
    requested_id: Option<&str>,
) -> Result<Option<(String, Certificate)>> {
    for candidate in candidates.iter().filter(|cert| {
        cert.machine_name.as_deref() == Some(CERTIFICATE_LABEL)
            && requested_id.is_none_or(|id| cert.certificate_id.as_deref() == Some(id))
    }) {
        let data = candidate.cert_content.as_ref().ok_or(CERTIFICATE)?;
        let certificate = Certificate::from_der(data.as_ref()).map_err(|_| CERTIFICATE)?;
        if certificate
            .tbs_certificate
            .validity
            .not_after
            .to_system_time()
            > SystemTime::now()
            && certificate
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .as_bytes()
                == Some(public_key)
        {
            return Ok(Some((
                candidate.machine_id.clone().unwrap_or_default(),
                certificate,
            )));
        }
    }
    Ok(None)
}

fn certificate_request(private: &RsaPrivateKey) -> Result<String> {
    let pem = private
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|_| CERTIFICATE)?;
    let key =
        KeyPair::from_pkcs8_pem_and_sign_algo(&pem, &PKCS_RSA_SHA256).map_err(|_| CERTIFICATE)?;
    let mut params = CertificateParams::new(Vec::<String>::new()).map_err(|_| CERTIFICATE)?;
    params
        .distinguished_name
        .push(DnType::CommonName, CERTIFICATE_LABEL);
    params
        .serialize_request(&key)
        .and_then(|request| request.pem())
        .map_err(|_| CERTIFICATE)
}

impl Account {
    pub async fn prepare(
        &mut self,
        input: &Path,
        expected: &str,
        target: &str,
        report: impl Fn(Stage) + Send + Sync,
    ) -> Result<PreparedIpa> {
        let root = crate::state_root()?;
        std::fs::create_dir_all(&root).map_err(|_| Issue::storage())?;
        let directory = tempfile::Builder::new()
            .prefix("prepare-")
            .tempdir_in(root)
            .map_err(|_| Issue::storage())?;
        let path = directory.path().join("MGMAgent-signed.ipa");
        let inspection = self
            .sign_update(input, expected, target, directory.path(), &path, report)
            .await?;
        Ok(PreparedIpa {
            _directory: directory,
            path,
            inspection,
        })
    }
    pub async fn sign_update(
        &mut self,
        input: &Path,
        expected: &str,
        target: &str,
        workspace: &Path,
        output: &Path,
        report: impl Fn(Stage) + Send + Sync,
    ) -> Result<Inspection> {
        let audit = Audit::open()?;
        audit.record(None, Some("prepare_started"))?;
        let result = self
            .sign_update_inner(input, expected, target, workspace, output, |stage| {
                let _ = audit.record(Some(stage), None);
                report(stage);
            })
            .await;
        if result
            .as_ref()
            .is_err_and(|issue| issue.code == EXPIRED_OR_UNCERTAIN.code)
        {
            self.expires = Instant::now();
        }
        audit.record(
            None,
            Some(
                result
                    .as_ref()
                    .err()
                    .map_or("ipa_ready", |issue| issue.code),
            ),
        )?;
        result
    }

    async fn sign_update_inner(
        &mut self,
        input: &Path,
        expected: &str,
        target: &str,
        workspace: &Path,
        output: &Path,
        report: impl Fn(Stage) + Send + Sync,
    ) -> Result<Inspection> {
        if Instant::now() >= self.expires {
            return Err(SESSION);
        }
        device_key(target)?;
        let installed = NativeUsb.lookup_mgm(target).await?.ok_or(UPDATE)?;
        let identity = installed.data_identity.as_ref().ok_or(UPDATE)?;
        let team = self
            .teams
            .iter()
            .find(|team| team.team_id == identity.team)
            .cloned()
            .ok_or(TEAM)?;
        let bundle = &installed.identity.bundle;
        let (app, original) = ipa::stage_unsigned(input, expected, workspace)?;
        if original.bundle != BUNDLE_ID && &original.bundle != bundle {
            return Err(Issue::new(
                "bundle_unsupported",
                "Choisis une IPA Agent Admin liée à l’application déjà installée.",
            ));
        }

        report(Stage::Device);
        apple_call(
            self.developer
                .ensure_device_registered(&team, "iPhone MGM", target, None),
            DEVELOPER,
        )
        .await?;
        report(Stage::AppIdentifier);
        let ids = apple_call(self.developer.list_app_ids(&team, None), PROFILE).await?;
        let app_id = ids.app_ids.into_iter().find(|id| &id.identifier == bundle).ok_or_else(|| Issue::new(
            "apple_app_id_missing", "L’équipe Apple doit déjà posséder l’identifiant exact qui est installé sur l’iPhone."))?;

        report(Stage::Certificate);
        let cert = signing_identity(&mut self.developer, &team, &self.email).await?;

        report(Stage::Profile);
        let profile = apple_call(
            self.developer
                .download_team_provisioning_profile(&team, &app_id, None),
            PROFILE,
        )
        .await?;
        let raw: &[u8] = profile.encoded_profile.as_ref();
        ipa::check_profile(raw, bundle, target, identity)?;
        let profile = ProvisioningProfile::parse(raw).map_err(|_| PROFILE)?;
        let claims = compatible_claims(profile.entitlements(), identity)?;
        let chain = cert
            .profile_to_certificate_chain(&profile)
            .map_err(|_| CERTIFICATE)?;
        let certificate = cert.certificate.to_der().map_err(|_| CERTIFICATE)?;
        let certified = profile
            .plist()
            .get("DeveloperCertificates")
            .and_then(Value::as_array)
            .is_some_and(|allowed| {
                allowed
                    .iter()
                    .any(|item| item.as_data() == Some(certificate.as_slice()))
            });
        if !certified {
            return Err(CERTIFICATE);
        }
        report(Stage::Signing);
        let info = app.join("Info.plist");
        let mut info_data: Dictionary = plist::from_file(&info).map_err(|_| SIGN)?;
        info_data.insert(
            "CFBundleIdentifier".into(),
            Value::String(bundle.to_owned()),
        );
        plist::to_file_xml(&info, &info_data).map_err(|_| SIGN)?;
        let signer = RustCryptoCmsSigner::new(cert.private_key, cert.certificate, chain);
        let mut settings = BundleSigningSettings::new(&team.team_id, claims, Some(&signer));
        settings.embedded_mobileprovision = Some(raw);
        sign_bundle(&app, &settings).map_err(|_| SIGN)?;
        ipa::pack_signed(&app, output)?;

        report(Stage::FinalVerification);
        let result = ipa::inspect(output, Some(target))?;
        if result.identity.build != original.build
            || result.identity.version != original.version
            || preflight_target(&NativeUsb, target, &result)
                .await?
                .as_ref()
                != Some(&installed)
        {
            return Err(UPDATE);
        }
        Ok(result)
    }
}

fn compatible_claims(profile: &Dictionary, identity: &DataIdentity) -> Result<Dictionary> {
    let incompatible = Issue::new(
        "signed_data_identity_incompatible",
        "Le profil Apple ne couvre pas les groupes Keychain et App Groups installés.",
    );
    let mut claims = profile.clone();
    for (field, needed) in [
        ("keychain-access-groups", &identity.keychain_groups),
        (
            "com.apple.security.application-groups",
            &identity.app_groups,
        ),
    ] {
        let allowed = profile
            .get(field)
            .and_then(Value::as_array)
            .map(|groups| {
                groups
                    .iter()
                    .filter_map(Value::as_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for group in needed {
            let matches = allowed.iter().any(|value| {
                *value == group
                    || (field == "keychain-access-groups"
                        && !group.contains('*')
                        && value
                            .strip_suffix('*')
                            .is_some_and(|prefix| group.starts_with(prefix)))
            });
            if !matches {
                return Err(incompatible);
            }
        }
        if needed.is_empty() {
            claims.remove(field);
        } else {
            claims.insert(
                field.into(),
                Value::Array(needed.iter().cloned().map(Value::String).collect()),
            );
        }
    }
    claims.insert(
        "application-identifier".into(),
        Value::String(identity.application_identifier.clone()),
    );
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "nécessite le coffre de la session graphique Linux"]
    fn linux_desktop_keyring_stores_and_reads_binary() {
        let storage = KeyringStorage::new(CERTIFICATE_LABEL.into());
        let key = format!("diagnostic-{}", uuid::Uuid::new_v4());
        let fixture = [0x80, 0x00, 0xff, 0x01];
        storage
            .store_data(&key, &fixture)
            .expect("écriture de la fixture");
        let fetched = storage.retrieve_data(&key);
        storage.delete(&key).expect("effacement de la fixture");
        assert_eq!(
            fetched.expect("relecture de la fixture").as_deref(),
            Some(fixture.as_slice())
        );
        assert!(storage
            .retrieve_data(&key)
            .expect("absence après effacement")
            .is_none());
    }

    async fn probe(status: &str, body: &'static str) -> Result<()> {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let status = status.to_owned();
        let server = std::thread::spawn(move || {
            let (mut peer, _) = listener.accept().unwrap();
            let mut request = [0u8; 1200];
            let count = peer.read(&mut request).unwrap();
            assert!(request[..count].starts_with(b"GET /v3/client_info HTTP/"));
            write!(peer, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        });
        let result = diagnose_provider(&url).await;
        server.join().unwrap();
        result
    }

    #[tokio::test]
    async fn provider_http_failure_is_distinct_from_throttling() {
        assert_eq!(
            probe("503 Service Unavailable", "{}")
                .await
                .unwrap_err()
                .code,
            "anisette_unavailable"
        );
        assert_eq!(
            probe("429 Too Many Requests", "{}").await.unwrap_err().code,
            "apple_rate_limited"
        );
    }

    #[test]
    fn provider_requires_operator_origin_and_tls_outside_loopback() {
        assert!(provider_url("https://sign.example.org").is_ok());
        assert!(provider_url("http://127.0.0.1:6940").is_ok());
        for invalid in [
            "",
            "http://sign.example.org",
            "https://user@sign.example.org",
            "https://sign.example.org/a",
            "https://sign.example.org?token=x",
        ] {
            assert_eq!(
                provider_url(invalid).unwrap_err().code,
                "anisette_configuration_required"
            );
        }
    }

    #[test]
    fn two_factor_uses_the_pending_method_and_a_single_valid_reply() {
        let prompt = Challenge {
            sms: false,
            choose: false,
            rejected: false,
            numbers: vec![MaskedNumber {
                id: 15,
                suffix: "88".into(),
            }],
        };
        assert!(matches!(
            Answer::Code {
                code: "123456".into()
            }
            .response(&prompt),
            TwoFactorCallbackResponse::SubmitCode(_)
        ));
        assert!(matches!(
            Answer::Code {
                code: "abcd01".into()
            }
            .response(&prompt),
            TwoFactorCallbackResponse::Abort
        ));
        assert!(matches!(
            Answer::Sms { id: 99 }.response(&prompt),
            TwoFactorCallbackResponse::Abort
        ));
        assert!(matches!(
            Answer::Cancel.response(&prompt),
            TwoFactorCallbackResponse::Abort
        ));
        let prompt = Challenge {
            choose: true,
            ..prompt
        };
        assert!(matches!(
            Answer::Device.response(&prompt),
            TwoFactorCallbackResponse::SendToDevices
        ));
        assert!(matches!(
            Answer::Sms { id: 15 }.response(&prompt),
            TwoFactorCallbackResponse::SendSms(15)
        ));
    }

    #[test]
    fn profile_may_authorize_more_rights_but_the_signature_preserves_the_installed_groups() {
        let identity = DataIdentity {
            application_identifier: "TESTTEAM00.ca.mgminformatique.agent".into(),
            team: "TESTTEAM00".into(),
            keychain_groups: ["TESTTEAM00.*".into()].into_iter().collect(),
            app_groups: ["group.existing".into()].into_iter().collect(),
        };
        let mut profile = Dictionary::new();
        profile.insert(
            "keychain-access-groups".into(),
            Value::Array(vec!["TESTTEAM00.*".into(), "TESTTEAM00.extra".into()]),
        );
        assert_eq!(
            compatible_claims(&profile, &identity).unwrap_err().code,
            "signed_data_identity_incompatible"
        );
        profile.insert(
            "com.apple.security.application-groups".into(),
            Value::Array(vec!["group.existing".into(), "group.extra".into()]),
        );
        let result = compatible_claims(&profile, &identity).unwrap();
        assert_eq!(
            result["keychain-access-groups"].as_array().unwrap().len(),
            1
        );
        assert_eq!(
            result["com.apple.security.application-groups"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            result["application-identifier"].as_string(),
            Some(identity.application_identifier.as_str())
        );
    }

    #[test]
    #[ignore = "requires OpenSSL and a local unsigned ARM64 IPA in MGM_SIGN_FIXTURE_IPA"]
    fn signs_arm64_ipa_in_a_fixture_and_inspects_the_final_identity() {
        use der::Decode;
        use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey};
        use std::{
            fs,
            process::{Command, Stdio},
            time::SystemTime,
        };

        let source = std::path::PathBuf::from(
            std::env::var_os("MGM_SIGN_FIXTURE_IPA").expect("IPA de recette locale"),
        );
        let work = tempfile::tempdir().unwrap();
        let root = work.path();
        let run = |args: &[&str]| {
            let output = Command::new("openssl")
                .current_dir(root)
                .args(args)
                .stderr(Stdio::null())
                .output()
                .unwrap();
            assert!(output.status.success(), "génération de la fixture OpenSSL");
            output.stdout
        };
        run(&[
            "req",
            "-new",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "key.pem",
            "-out",
            "cert.pem",
            "-subj",
            "/CN=MGM Fixture",
            "-days",
            "1",
        ]);
        let cert = run(&["x509", "-in", "cert.pem", "-outform", "DER"]);
        let private =
            RsaPrivateKey::from_pkcs8_pem(&fs::read_to_string(root.join("key.pem")).unwrap())
                .unwrap();
        let certificate = x509_cert::Certificate::from_der(&cert).unwrap();
        assert!(certificate_request(&private)
            .unwrap()
            .starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
        let candidates = [
            serde_json::from_value::<DevelopmentCertificate>(serde_json::json!({
                "machineName": CERTIFICATE_LABEL,
                "certificateId": "fixture-csr"
            }))
            .unwrap(),
        ];
        let mut candidates = candidates;
        candidates[0].cert_content = Some(cert.clone().into());
        let public = private.to_public_key().to_pkcs1_der().unwrap();
        assert!(
            matching_certificate(&candidates, public.as_bytes(), Some("fixture-csr"))
                .unwrap()
                .is_some()
        );
        assert!(
            matching_certificate(&candidates, public.as_bytes(), Some("other-csr"))
                .unwrap()
                .is_none()
        );
        let udid = "00008140-001234567890ABCD";
        let source_info = ipa::inspect_input(&source).unwrap();
        let (app, _) = ipa::stage_unsigned(&source, &source_info.sha256, root).unwrap();
        let team = "MGMTEST001";
        let bundle = format!("{BUNDLE_ID}.{team}");
        let claim = DataIdentity {
            application_identifier: format!("{team}.{bundle}"),
            team: team.into(),
            keychain_groups: [format!("{team}.*")].into_iter().collect(),
            app_groups: [format!("group.{bundle}")].into_iter().collect(),
        };
        let mut rights = Dictionary::new();
        for (key, values) in [
            ("keychain-access-groups", &claim.keychain_groups),
            ("com.apple.security.application-groups", &claim.app_groups),
        ] {
            rights.insert(
                key.into(),
                Value::Array(values.iter().cloned().map(Value::String).collect()),
            );
        }
        rights.insert("com.apple.developer.team-identifier".into(), team.into());
        rights.insert(
            "application-identifier".into(),
            claim.application_identifier.clone().into(),
        );
        let mut profile = Dictionary::new();
        for (key, value) in [
            ("TeamIdentifier", team),
            ("ApplicationIdentifierPrefix", team),
            ("Platform", "iOS"),
            ("ProvisionedDevices", udid),
        ] {
            profile.insert(key.into(), Value::Array(vec![value.into()]));
        }
        profile.insert(
            "DeveloperCertificates".into(),
            Value::Array(vec![Value::Data(cert)]),
        );
        profile.insert(
            "ExpirationDate".into(),
            Value::Date((SystemTime::now() + Duration::from_secs(86_400)).into()),
        );
        profile.insert(
            "CreationDate".into(),
            Value::Date((SystemTime::now() - Duration::from_secs(60)).into()),
        );
        profile.insert("Entitlements".into(), Value::Dictionary(rights.clone()));
        plist::to_file_xml(root.join("profile.plist"), &profile).unwrap();
        run(&[
            "cms",
            "-sign",
            "-binary",
            "-in",
            "profile.plist",
            "-signer",
            "cert.pem",
            "-inkey",
            "key.pem",
            "-outform",
            "DER",
            "-nodetach",
            "-out",
            "profile.bin",
        ]);
        let raw = fs::read(root.join("profile.bin")).unwrap();
        ipa::check_profile(&raw, &bundle, udid, &claim).unwrap();
        let output = root.join("fake-signed.ipa");
        let mut info: Dictionary = plist::from_file(app.join("Info.plist")).unwrap();
        info.insert("CFBundleIdentifier".into(), bundle.clone().into());
        plist::to_file_xml(app.join("Info.plist"), &info).unwrap();
        let signer = RustCryptoCmsSigner::new(private, certificate, vec![]);
        let mut settings = BundleSigningSettings::new(
            team,
            compatible_claims(&rights, &claim).unwrap(),
            Some(&signer),
        );
        settings.embedded_mobileprovision = Some(&raw);
        assert!(
            sign_bundle(&app, &settings).is_ok(),
            "signature Mach-O ARM64"
        );
        ipa::pack_signed(&app, &output).unwrap();
        let observed = ipa::inspect(&output, Some(udid)).unwrap();
        assert_eq!(observed.identity.bundle, bundle);
        assert_eq!(observed.identity.build, source_info.identity.build);
        assert_eq!(observed.components[0].data_identity.as_ref(), Some(&claim));
        assert_eq!(
            ipa::inspect_input(&source).unwrap().sha256,
            source_info.sha256
        );
    }
}
