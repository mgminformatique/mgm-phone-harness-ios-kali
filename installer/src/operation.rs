use crate::{
    device_key,
    ipa::{self, Identity, Inspection},
    usb::{mgm_alias_team, Access, Installed},
    Issue, Result, BUNDLE_ID, SCHEMA,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::watch,
    time::{sleep, timeout},
};
use uuid::Uuid;

const ACTIVE: Issue = Issue::new(
    "operation_active",
    "Une opération USB est déjà active pour cet iPhone.",
);
const PENDING: Issue = Issue::new(
    "operation_pending",
    "Relis le reçu de cet iPhone avant de lancer une nouvelle installation.",
);
const CANCEL: Issue = Issue::new(
    "stop_requested",
    "L’arrêt a été demandé. La relecture indique le résultat connu.",
);
const TIMEOUT: Issue = Issue::new(
    "operation_timeout",
    "Le délai USB est écoulé. Relis le reçu avant de reprendre.",
);
const RECONCILE: Issue = Issue::new(
    "installed_build_unconfirmed",
    "Le build attendu reste à confirmer sur l’iPhone.",
);
const OPERATOR_REVIEW: Issue =
    Issue::new("operator_review", "Suivi clos après vérification manuelle.");

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Prepared,
    Transferring,
    TransferVerified,
    SubmissionIntent,
    AcceptanceUnknown,
    Accepted,
    InstalledBuildObserved,
    InstalledBuildObservedAfterInterruption,
    VerificationPending,
    InterruptedBeforeSubmit,
    FailedBeforeSubmit,
    Rejected,
    OutcomeLeftUnconfirmed,
}

impl Phase {
    fn blocks(self) -> bool {
        matches!(
            self,
            Self::Prepared
                | Self::Transferring
                | Self::TransferVerified
                | Self::SubmissionIntent
                | Self::AcceptanceUnknown
                | Self::Accepted
                | Self::VerificationPending
        )
    }
    fn pre_submit(self) -> bool {
        matches!(
            self,
            Self::Prepared | Self::Transferring | Self::TransferVerified
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Event {
    pub phase: Phase,
    pub time_unix: u64,
    pub issue: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Receipt {
    pub schema: u8,
    pub id: Uuid,
    pub device_key: String,
    pub identity: Identity,
    pub signing_team: String,
    pub sha256: String,
    pub bytes: u64,
    pub before: Option<Installed>,
    pub observed: Option<Installed>,
    pub same_app_version_before: bool,
    pub phase: Phase,
    pub ios_accepted: Option<bool>,
    pub transfer_verified: bool,
    pub stop_requested: bool,
    pub cleanup_pending: bool,
    pub installed_file_sha256_verified: bool,
    pub launch_verified: bool,
    pub events: Vec<Event>,
}

impl Receipt {
    fn remote_path(&self) -> String {
        format!("PublicStaging/mgm-{}.ipa", self.id)
    }
}

struct DeviceLock(File);

impl Drop for DeviceLock {
    fn drop(&mut self) {
        // Release the logical operation even if a concurrent process is between fork and exec.
        let _ = self.0.unlock();
    }
}

pub struct Engine<T> {
    directory: PathBuf,
    device: T,
}

pub async fn preflight_target(
    device: &impl Access,
    udid: &str,
    ipa: &Inspection,
) -> Result<Option<Installed>> {
    let alias = mgm_alias_team(&ipa.identity.bundle);
    if ipa.identity.bundle != BUNDLE_ID && alias != Some(ipa.team.as_str()) {
        return Err(Issue::new(
            "bundle_unsupported",
            "Choisis une IPA Agent Admin avec l’identité de signature attendue.",
        ));
    }
    let before = device.lookup_mgm(udid).await?;
    let alternate_identity = Issue::new("installed_bundle_mismatch",
        "L’identifiant de l’IPA doit correspondre à celui d’Agent Admin déjà installé pour conserver ses données.");
    let Some(current) = before.as_ref() else {
        return if alias.is_some() {
            Err(alternate_identity)
        } else {
            Ok(None)
        };
    };
    if current.identity.bundle != ipa.identity.bundle {
        return Err(alternate_identity);
    }
    if current.team.as_ref().is_some_and(|team| *team != ipa.team) {
        return Err(Issue::new("installed_team_mismatch", "L’app installée appartient à une autre équipe. Utilise l’identité de signature existante."));
    }
    match (current.data_identity.as_ref(), ipa.components.first().and_then(|app| app.data_identity.as_ref())) {
        (Some(old), Some(new)) if old != new => return Err(Issue::new("installed_data_identity_mismatch",
            "L’identifiant signé ou les groupes de données diffèrent de l’app installée.")),
        (Some(_), Some(_)) => {},
        _ if alias.is_some() => return Err(Issue::new("installed_data_identity_unverified",
            "Les droits signés de l’IPA et de l’app installée doivent être lisibles pour confirmer la continuité des données.")),
        _ => {},
    }
    Ok(before)
}

impl<T: Access> Engine<T> {
    pub fn new(directory: PathBuf, device: T) -> Result<Self> {
        fs::create_dir_all(&directory).map_err(|_| Issue::storage())?;
        Ok(Self { directory, device })
    }

    pub fn list(&self) -> Result<Vec<Receipt>> {
        let mut results = Vec::new();
        for item in fs::read_dir(&self.directory).map_err(|_| Issue::storage())? {
            let item = item.map_err(|_| Issue::storage())?;
            let name = item.file_name();
            let Some(id) = name
                .to_str()
                .and_then(|name| name.strip_suffix(".json"))
                .and_then(|name| Uuid::parse_str(name).ok())
            else {
                continue;
            };
            results.push(self.receipt(id)?);
        }
        results.sort_by_key(|r| r.events.first().map(|event| event.time_unix));
        results.reverse();
        Ok(results)
    }

    pub fn receipt(&self, id: Uuid) -> Result<Receipt> {
        let file = File::open(self.record_path(id))
            .map_err(|_| Issue::new("receipt_unavailable", "Reçu local indisponible."))?;
        let receipt: Receipt =
            serde_json::from_reader(file.take(1024 * 1024)).map_err(|_| Issue::storage())?;
        if receipt.schema != SCHEMA || receipt.id != id || receipt.events.is_empty() {
            return Err(Issue::storage());
        }
        Ok(receipt)
    }

    pub async fn install(
        &self,
        source: &Path,
        udid: &str,
        expected: &str,
        approved_state: Option<&Option<Installed>>,
        mut stop: watch::Receiver<bool>,
    ) -> Result<Receipt> {
        let key = device_key(udid)?;
        if expected.len() != 64 || !expected.bytes().all(|value| value.is_ascii_hexdigit()) {
            return Err(Issue::new(
                "digest_required",
                "Confirme le SHA-256 obtenu par l’inspection de l’IPA.",
            ));
        }
        let _lock = self.lock(&key)?;
        if self
            .list()?
            .into_iter()
            .any(|r| r.device_key == key && r.phase.blocks())
        {
            return Err(PENDING);
        }
        let path = source.to_path_buf();
        let directory = self.directory.clone();
        let target = udid.to_owned();
        let (ipa, snapshot) =
            tokio::task::spawn_blocking(move || ipa::snapshot(&path, &directory, &target))
                .await
                .map_err(|_| Issue::storage())??;
        if !ipa.sha256.eq_ignore_ascii_case(expected) {
            return Err(Issue::new(
                "ipa_changed",
                "L’IPA a changé depuis l’inspection. Vérifie de nouveau son empreinte.",
            ));
        }
        let before = preflight_target(&self.device, udid, &ipa).await?;
        if approved_state.is_some_and(|approved| *approved != before) {
            return Err(Issue::new(
                "installed_state_changed",
                "L’app installée a changé depuis la confirmation. Refais le diagnostic.",
            ));
        }
        if *stop.borrow() {
            return Err(CANCEL);
        }
        let same_app_version_before = before
            .as_ref()
            .is_some_and(|app| app.identity == ipa.identity);
        let mut receipt = Receipt {
            schema: SCHEMA,
            id: Uuid::new_v4(),
            device_key: key,
            identity: ipa.identity,
            signing_team: ipa.team,
            sha256: ipa.sha256,
            bytes: ipa.bytes,
            before,
            observed: None,
            same_app_version_before,
            phase: Phase::Prepared,
            ios_accepted: None,
            transfer_verified: false,
            stop_requested: false,
            cleanup_pending: false,
            installed_file_sha256_verified: false,
            launch_verified: false,
            events: Vec::new(),
        };
        self.record(&mut receipt, Phase::Prepared, None)?;
        let remote = receipt.remote_path();
        receipt.cleanup_pending = true;
        self.record(&mut receipt, Phase::Transferring, None)?;
        let upload = self
            .device
            .stage(udid, &remote, snapshot, receipt.bytes, &receipt.sha256);
        if let Err(issue) = work(upload, Duration::from_secs(900), &mut stop).await {
            return self.finish_before_submit(receipt, udid, issue).await;
        }
        receipt.transfer_verified = true;
        self.record(&mut receipt, Phase::TransferVerified, None)?;
        let lookup = self.device.lookup_mgm(udid);
        match work(lookup, Duration::from_secs(20), &mut stop).await {
            Ok(before) if before == receipt.before => {}
            Ok(_) => {
                let issue = Issue::new(
                    "installed_state_changed",
                    "L’app installée a changé pendant le transfert. Refais le diagnostic.",
                );
                return self.finish_before_submit(receipt, udid, issue).await;
            }
            Err(issue) => return self.finish_before_submit(receipt, udid, issue).await,
        }

        self.record(&mut receipt, Phase::SubmissionIntent, None)?;
        let request = self.device.install(
            udid,
            &remote,
            &receipt.identity.bundle,
            receipt.before.is_some(),
        );
        match work(request, Duration::from_secs(420), &mut stop).await {
            Ok(()) => {
                receipt.ios_accepted = Some(true);
                self.record(&mut receipt, Phase::Accepted, None)?;
                self.reconcile(&mut receipt, udid, true).await?;
                self.cleanup(&mut receipt, udid).await?;
            }
            Err(issue)
                if matches!(
                    issue.code,
                    "ios_rejected" | "ios_signature_rejected" | "ios_developer_mode_required"
                ) =>
            {
                receipt.ios_accepted = Some(false);
                self.record(&mut receipt, Phase::Rejected, Some(&issue))?;
                self.cleanup(&mut receipt, udid).await?;
            }
            Err(issue) => {
                receipt.stop_requested = issue == CANCEL;
                self.record(&mut receipt, Phase::AcceptanceUnknown, Some(&issue))?;
            }
        }
        Ok(receipt)
    }

    pub async fn recover(&self, id: Uuid, udid: &str) -> Result<Receipt> {
        let (mut receipt, _lock) = self.lock_receipt(id, udid)?;
        if receipt.phase.pre_submit() {
            self.record(&mut receipt, Phase::InterruptedBeforeSubmit, None)?;
            self.cleanup(&mut receipt, udid).await?;
        } else if receipt.phase.blocks() {
            self.reconcile(&mut receipt, udid, false).await?;
            if !receipt.phase.blocks() || receipt.ios_accepted == Some(true) {
                self.cleanup(&mut receipt, udid).await?;
            }
        } else {
            self.cleanup(&mut receipt, udid).await?;
        }
        Ok(receipt)
    }

    pub fn close_unconfirmed(&self, id: Uuid, udid: &str) -> Result<Receipt> {
        let (mut receipt, _lock) = self.lock_receipt(id, udid)?;
        if receipt.phase != Phase::AcceptanceUnknown
            || receipt
                .events
                .last()
                .and_then(|event| event.issue.as_deref())
                != Some(RECONCILE.code)
        {
            return Err(Issue::new(
                "review_required",
                "Relis l’issue sur l’iPhone avant de clore un résultat toujours incertain.",
            ));
        }
        // An operator can stop tracking a receipt without deleting a package iOS could still need.
        self.record(
            &mut receipt,
            Phase::OutcomeLeftUnconfirmed,
            Some(&OPERATOR_REVIEW),
        )?;
        Ok(receipt)
    }

    async fn finish_before_submit(
        &self,
        mut receipt: Receipt,
        udid: &str,
        issue: Issue,
    ) -> Result<Receipt> {
        receipt.stop_requested = issue == CANCEL;
        self.record(&mut receipt, Phase::FailedBeforeSubmit, Some(&issue))?;
        self.cleanup(&mut receipt, udid).await?;
        Ok(receipt)
    }

    async fn reconcile(&self, receipt: &mut Receipt, udid: &str, poll: bool) -> Result<()> {
        // Only inventory reads can be repeated. A repeated version is ambiguous after lost acceptance.
        for attempt in 0..if poll { 3 } else { 1 } {
            match self.device.lookup(udid, &receipt.identity.bundle).await {
                Ok(observed) => {
                    let matches = observed.as_ref().is_some_and(|app| {
                        app.identity == receipt.identity
                            && app
                                .team
                                .as_ref()
                                .is_none_or(|team| *team == receipt.signing_team)
                    });
                    receipt.observed = observed;
                    if matches && receipt.ios_accepted == Some(true) {
                        return self.record(receipt, Phase::InstalledBuildObserved, None);
                    }
                    if matches && !receipt.same_app_version_before {
                        return self.record(
                            receipt,
                            Phase::InstalledBuildObservedAfterInterruption,
                            None,
                        );
                    }
                }
                Err(issue) => {
                    return self.record(receipt, phase_after_lookup(receipt), Some(&issue))
                }
            }
            if poll && attempt < 2 {
                sleep(Duration::from_millis(700)).await;
            }
        }
        self.record(receipt, phase_after_lookup(receipt), Some(&RECONCILE))
    }

    async fn cleanup(&self, receipt: &mut Receipt, udid: &str) -> Result<()> {
        if receipt.cleanup_pending
            && receipt.phase != Phase::OutcomeLeftUnconfirmed
            && self
                .device
                .cleanup(udid, &receipt.remote_path())
                .await
                .is_ok()
        {
            receipt.cleanup_pending = false;
            self.save(receipt)?;
        }
        Ok(())
    }

    fn lock_receipt(&self, id: Uuid, udid: &str) -> Result<(Receipt, DeviceLock)> {
        let key = device_key(udid)?;
        let lock = self.lock(&key)?;
        let receipt = self.receipt(id)?;
        if receipt.device_key != key {
            return Err(Issue::new(
                "device_mismatch",
                "Rebranche l’iPhone qui correspond à ce reçu.",
            ));
        }
        Ok((receipt, lock))
    }

    fn lock(&self, key: &str) -> Result<DeviceLock> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.directory.join(format!("{key}.lock")))
            .map_err(|_| Issue::storage())?;
        file.try_lock().map_err(|_| ACTIVE)?;
        Ok(DeviceLock(file))
    }

    fn record_path(&self, id: Uuid) -> PathBuf {
        self.directory.join(format!("{id}.json"))
    }

    fn record(&self, receipt: &mut Receipt, phase: Phase, issue: Option<&Issue>) -> Result<()> {
        let time_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Issue::storage())?
            .as_secs();
        receipt.phase = phase;
        let code = issue.map(|issue| issue.code);
        if !receipt
            .events
            .last()
            .is_some_and(|old| old.phase == phase && old.issue.as_deref() == code)
        {
            receipt.events.push(Event {
                phase,
                time_unix,
                issue: code.map(str::to_owned),
                message: issue.map(|issue| issue.message.to_owned()),
            });
        }
        self.save(receipt)
    }

    fn save(&self, receipt: &Receipt) -> Result<()> {
        let mut file =
            tempfile::NamedTempFile::new_in(&self.directory).map_err(|_| Issue::storage())?;
        serde_json::to_writer(&mut file, receipt).map_err(|_| Issue::storage())?;
        file.flush().map_err(|_| Issue::storage())?;
        file.as_file().sync_all().map_err(|_| Issue::storage())?;
        file.persist(self.record_path(receipt.id))
            .map_err(|_| Issue::storage())?;
        #[cfg(unix)]
        File::open(&self.directory)
            .and_then(|file| file.sync_all())
            .map_err(|_| Issue::storage())?;
        Ok(())
    }
}

fn phase_after_lookup(receipt: &Receipt) -> Phase {
    if receipt.ios_accepted == Some(true) {
        Phase::VerificationPending
    } else {
        Phase::AcceptanceUnknown
    }
}

async fn work<T>(
    action: impl std::future::Future<Output = Result<T>>,
    limit: Duration,
    stop: &mut watch::Receiver<bool>,
) -> Result<T> {
    let stop_requested = async {
        let _ = stop.wait_for(|flag| *flag).await;
        if !*stop.borrow() {
            std::future::pending::<()>().await;
        }
    };
    tokio::select! {
        biased;
        _ = stop_requested => Err(CANCEL),
        outcome = timeout(limit, action) => outcome.map_err(|_| TIMEOUT)?,
    }
}
