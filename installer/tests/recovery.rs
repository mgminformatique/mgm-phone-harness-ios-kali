use cms::{
    content_info::{CmsVersion, ContentInfo},
    signed_data::{EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo},
};
use der::{
    asn1::{Any, OctetString},
    Decode, Encode,
};
use idevice::{services::afc::errors::AfcError, IdeviceError};
use mgm_ios_installer::{
    ipa::{self, Identity},
    operation::{Engine, Phase},
    usb::{transfer_error, Access, Installed},
    Issue, Result, BUNDLE_ID,
};
use plist::{Dictionary, Value};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};
use tempfile::TempDir;
use tokio::sync::{watch, Notify};
use zip::{write::SimpleFileOptions, ZipWriter};

const PHONE: &str = "00008140-001234567890ABCD";
const OTHER: &str = "00008140-001234567890ABCE";
const TEAM: &str = "MGMTEST001";

#[derive(Default, Clone, Copy)]
enum Effect {
    #[default]
    Accepted,
    LostWithoutEffect,
    LostAfterCommit,
    WaitBeforeSubmit,
    WaitAfterSubmit,
    StageFailure(u64),
}

#[derive(Default)]
struct Phone {
    app: Option<Installed>,
    submissions: u32,
    stage_calls: u32,
    cleanup_calls: u32,
    staged_chunks: Vec<[u8; 64]>,
    cleanup_target: Option<String>,
    cleanup_fails: bool,
    effect: Effect,
    upgraded: bool,
}

#[derive(Clone)]
struct Probe {
    phone: Arc<Mutex<Phone>>,
    arrived: Arc<Notify>,
    journal: PathBuf,
}

#[async_trait::async_trait]
impl Access for Probe {
    async fn lookup(&self, _: &str, _: &str) -> Result<Option<Installed>> {
        Ok(self.phone.lock().unwrap().app.clone())
    }
    async fn stage(
        &self,
        _: &str,
        remote: &str,
        mut input: File,
        bytes: u64,
        _: &str,
    ) -> Result<()> {
        assert!(remote.starts_with("PublicStaging/mgm-"));
        assert_phase(&self.journal, "transferring");
        let effect = {
            let mut phone = self.phone.lock().unwrap();
            phone.stage_calls += 1;
            phone.effect
        };
        match effect {
            Effect::WaitBeforeSubmit => {
                self.arrived.notify_one();
                std::future::pending().await
            }
            Effect::StageFailure(status) => {
                let mut chunk = [0; 64];
                assert!(bytes > (2 * chunk.len()) as u64);
                for _ in 0..2 {
                    input.read_exact(&mut chunk).unwrap();
                    self.phone.lock().unwrap().staged_chunks.push(chunk);
                }
                Err(transfer_error(IdeviceError::Afc(AfcError::from(status))))
            }
            _ => Ok(()),
        }
    }
    async fn install(&self, _: &str, _: &str, _: &str, upgrade: bool) -> Result<()> {
        assert_phase(&self.journal, "submission_intent");
        let effect = {
            let mut phone = self.phone.lock().unwrap();
            phone.submissions += 1;
            phone.upgraded = upgrade;
            if matches!(phone.effect, Effect::Accepted | Effect::LostAfterCommit) {
                let mut app = phone.app.take().unwrap_or_else(|| installed("31"));
                app.identity.build = "31".to_owned();
                phone.app = Some(app);
            }
            phone.effect
        };
        match effect {
            Effect::Accepted => Ok(()),
            Effect::WaitAfterSubmit => {
                self.arrived.notify_one();
                std::future::pending().await
            }
            _ => Err(Issue::new("usb_io", "Fixture : déconnexion USB.")),
        }
    }
    async fn cleanup(&self, _: &str, remote: &str) -> Result<()> {
        assert!(remote.starts_with("PublicStaging/mgm-"));
        let mut phone = self.phone.lock().unwrap();
        phone.cleanup_calls += 1;
        phone.cleanup_target = Some(remote.to_owned());
        if phone.cleanup_fails {
            return Err(Issue::new("usb_io", "Fixture : échec du nettoyage USB."));
        }
        phone.staged_chunks.clear();
        Ok(())
    }
}

fn assert_phase(directory: &Path, expected: &str) {
    let paths = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path());
    assert!(paths
        .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("json"))
        .any(
            |path| serde_json::from_slice::<serde_json::Value>(&fs::read(path).unwrap()).unwrap()
                ["phase"]
                == expected
        ));
}

fn installed(build: &str) -> Installed {
    Installed {
        identity: Identity {
            bundle: BUNDLE_ID.to_owned(),
            version: "1.4.6".into(),
            build: build.into(),
        },
        team: Some(TEAM.into()),
        data_identity: None,
    }
}

fn setup(
    effect: Effect,
    app: Option<Installed>,
) -> (TempDir, PathBuf, String, Probe, Engine<Probe>) {
    let area = tempfile::tempdir().unwrap();
    let path = area.path().join("Mon iPhone.ipa");
    fixture(&path, PHONE, false, true);
    let sha = ipa::inspect(&path, None).unwrap().sha256;
    let probe = Probe {
        phone: Arc::new(Mutex::new(Phone {
            app,
            effect,
            ..Default::default()
        })),
        arrived: Arc::new(Notify::new()),
        journal: area.path().join("receipts"),
    };
    let engine = Engine::new(probe.journal.clone(), probe.clone()).unwrap();
    (area, path, sha, probe, engine)
}

fn fixture(path: &Path, phone: &str, expired: bool, signature: bool) {
    package_fixture(path, phone, expired, signature, BUNDLE_ID, false);
}

fn package_fixture(
    path: &Path,
    phone: &str,
    expired: bool,
    signature: bool,
    bundle: &str,
    signed_identity: bool,
) {
    let now = SystemTime::now();
    let hour = Duration::from_secs(3600);
    let mut profile = Dictionary::new();
    profile.insert("CreationDate".into(), Value::Date((now - 2 * hour).into()));
    profile.insert(
        "ExpirationDate".into(),
        Value::Date((if expired { now - hour } else { now + hour }).into()),
    );
    profile.insert(
        "Platform".into(),
        Value::Array(vec![Value::String("iOS".into())]),
    );
    profile.insert(
        "ProvisionedDevices".into(),
        Value::Array(vec![Value::String(phone.into())]),
    );
    for key in ["TeamIdentifier", "ApplicationIdentifierPrefix"] {
        profile.insert(key.into(), Value::Array(vec![Value::String(TEAM.into())]));
    }
    let mut rights = Dictionary::new();
    rights.insert(
        "com.apple.developer.team-identifier".into(),
        Value::String(TEAM.into()),
    );
    rights.insert(
        "application-identifier".into(),
        Value::String(format!("{TEAM}.{bundle}")),
    );
    let mut signed_xml = Vec::new();
    if signed_identity {
        rights.insert(
            "keychain-access-groups".into(),
            Value::Array(vec![Value::String(format!("{TEAM}.*"))]),
        );
        rights.insert(
            "com.apple.security.application-groups".into(),
            Value::Array(vec![Value::String("group.ca.mgminformatique.agent".into())]),
        );
        plist::to_writer_xml(&mut signed_xml, &rights).unwrap();
    }
    profile.insert("Entitlements".into(), Value::Dictionary(rights));
    let mut xml = Vec::new();
    plist::to_writer_xml(&mut xml, &profile).unwrap();

    // A synthetic ASN.1 fixture tests parsing. No Apple certificate or device request is involved.
    let algorithm = [
        0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1,
    ];
    let signer = SignerInfo {
        version: CmsVersion::V3,
        sid: SignerIdentifier::from_der(&[0x80, 0x01, 0x02]).unwrap(),
        digest_alg: Decode::from_der(&algorithm).unwrap(),
        signed_attrs: None,
        signature_algorithm: Decode::from_der(&algorithm).unwrap(),
        signature: OctetString::new(vec![1]).unwrap(),
        unsigned_attrs: None,
    };
    let signed = SignedData {
        version: CmsVersion::V3,
        digest_algorithms: vec![signer.digest_alg.clone()].try_into().unwrap(),
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: "1.2.840.113549.1.7.1".parse().unwrap(),
            econtent: Some(Any::encode_from(&OctetString::new(xml).unwrap()).unwrap()),
        },
        certificates: None,
        crls: None,
        signer_infos: cms::signed_data::SignerInfos(
            der::asn1::SetOfVec::try_from(vec![signer]).unwrap(),
        ),
    };
    let profile = ContentInfo {
        content_type: "1.2.840.113549.1.7.2".parse().unwrap(),
        content: Any::encode_from(&signed).unwrap(),
    }
    .to_der()
    .unwrap();
    let mut info = Dictionary::new();
    for (key, value) in [
        ("CFBundleIdentifier", bundle),
        ("CFBundleExecutable", "MGMAgent"),
        ("CFBundleVersion", "31"),
        ("CFBundleShortVersionString", "1.4.6"),
    ] {
        info.insert(key.into(), Value::String(value.into()));
    }
    let mut info_xml = Vec::new();
    plist::to_writer_xml(&mut info_xml, &info).unwrap();

    let mut binary = vec![0u8; 96];
    for (start, word) in [
        (0, 0xfeedfacfu32),
        (4, 0x0100000c),
        (16, 1),
        (20, 16),
        (32, 0x1d),
        (36, 16),
        (40, 48),
        (44, 48),
    ] {
        binary[start..start + 4].copy_from_slice(&word.to_le_bytes());
    }
    if signature {
        for (start, word) in [
            (48, 0xfade0cc0u32),
            (52, 48),
            (56, 2),
            (60, 0),
            (64, 28),
            (68, 0x10000),
            (72, 38),
            (76, 0xfade0c02),
            (80, 10),
            (86, 0xfade0b01),
            (90, 10),
        ] {
            binary[start..start + 4].copy_from_slice(&word.to_be_bytes());
        }
        if signed_identity {
            binary.splice(76..76, [0; 8]);
            let length = signed_xml.len() as u32 + 8;
            let signature_size = 56 + length;
            binary[44..48].copy_from_slice(&signature_size.to_le_bytes());
            for (start, word) in [
                (52, signature_size),
                (56, 3),
                (64, 36),
                (72, 46),
                (76, 5),
                (80, 56),
            ] {
                binary[start..start + 4].copy_from_slice(&word.to_be_bytes());
            }
            binary.extend_from_slice(&0xfade7171u32.to_be_bytes());
            binary.extend_from_slice(&length.to_be_bytes());
            binary.extend_from_slice(&signed_xml);
        }
    }

    let mut app = ZipWriter::new(File::create(path).unwrap());
    for (name, bytes) in [
        ("Info.plist", info_xml),
        ("embedded.mobileprovision", profile),
        ("MGMAgent", binary),
    ] {
        app.start_file(
            format!("Payload/Agent Admin.app/{name}"),
            SimpleFileOptions::default(),
        )
        .unwrap();
        app.write_all(&bytes).unwrap();
    }
    app.finish().unwrap();
}

#[tokio::test]
async fn existing_sideload_identity_must_preserve_its_data_before_any_transfer() {
    let (_area, path, canonical_sha, probe, engine) = setup(Effect::Accepted, None);
    let bundle = format!("{BUNDLE_ID}.{TEAM}");
    let signed_file = path.with_file_name("MGM signé.ipa");
    package_fixture(&signed_file, PHONE, false, true, &bundle, true);
    let inspected = ipa::inspect(&signed_file, Some(PHONE)).unwrap();
    let signed_identity = inspected.components[0].data_identity.clone().unwrap();
    let mut actual = installed("30");
    actual.identity.bundle = bundle;
    actual.data_identity = Some(signed_identity);
    let (_stop, receive) = watch::channel(false);

    let try_alias = || {
        engine.install(
            &signed_file,
            PHONE,
            &inspected.sha256,
            None,
            receive.clone(),
        )
    };
    assert_eq!(
        try_alias().await.unwrap_err().code,
        "installed_bundle_mismatch"
    );
    probe.phone.lock().unwrap().app = Some(actual.clone());
    assert_eq!(
        engine
            .install(&path, PHONE, &canonical_sha, None, receive.clone())
            .await
            .unwrap_err()
            .code,
        "installed_bundle_mismatch"
    );
    probe
        .phone
        .lock()
        .unwrap()
        .app
        .as_mut()
        .unwrap()
        .data_identity
        .as_mut()
        .unwrap()
        .app_groups
        .clear();
    assert_eq!(
        try_alias().await.unwrap_err().code,
        "installed_data_identity_mismatch"
    );
    probe
        .phone
        .lock()
        .unwrap()
        .app
        .as_mut()
        .unwrap()
        .data_identity = None;
    assert_eq!(
        try_alias().await.unwrap_err().code,
        "installed_data_identity_unverified"
    );
    assert_eq!(probe.phone.lock().unwrap().stage_calls, 0);
    assert_eq!(probe.phone.lock().unwrap().submissions, 0);

    probe.phone.lock().unwrap().app = Some(actual);
    let receipt = try_alias().await.unwrap();
    assert_eq!(receipt.phase, Phase::InstalledBuildObserved);
    assert_eq!(receipt.identity, inspected.identity);
    let stats = probe.phone.lock().unwrap();
    assert!(stats.upgraded);
    assert_eq!(stats.submissions, 1);
}

#[test]
fn malformed_expired_and_wrong_device_never_pass_inspection() {
    let area = tempfile::tempdir().unwrap();
    let path = area.path().join("MGM.ipa");
    fixture(&path, PHONE, false, true);
    assert_eq!(
        ipa::inspect(&path, Some(PHONE)).unwrap().identity.build,
        "31"
    );
    assert_eq!(
        ipa::inspect(&path, Some(OTHER)).unwrap_err().code,
        "profile_device_mismatch"
    );
    fixture(&path, PHONE, true, true);
    assert_eq!(
        ipa::inspect(&path, Some(PHONE)).unwrap_err().code,
        "profile_expired"
    );
    fixture(&path, PHONE, false, false);
    assert_eq!(
        ipa::inspect(&path, Some(PHONE)).unwrap_err().code,
        "signature_missing"
    );
    fs::write(&path, b"invalid zip").unwrap();
    assert_eq!(
        ipa::inspect(&path, Some(PHONE)).unwrap_err().code,
        "ipa_invalid"
    );
}

#[tokio::test]
async fn accepted_upgrade_is_read_back_and_does_not_claim_launch() {
    let (_area, path, digest, probe, engine) = setup(Effect::Accepted, Some(installed("30")));
    let (_, stop) = watch::channel(false);
    let receipt = engine
        .install(&path, PHONE, &digest, None, stop)
        .await
        .unwrap();
    assert_eq!(receipt.phase, Phase::InstalledBuildObserved);
    assert_eq!(receipt.ios_accepted, Some(true));
    assert!(
        receipt.transfer_verified
            && !receipt.launch_verified
            && !receipt.installed_file_sha256_verified
    );
    assert_eq!(receipt.observed.unwrap().identity.build, "31");
    let phone = probe.phone.lock().unwrap();
    assert_eq!(phone.submissions, 1);
    assert!(phone.upgraded);
}

#[tokio::test]
async fn afc_no_space_after_partial_transfer_never_submits_installation() {
    let previous = Some(installed("30"));
    // Status 18 is the value sent by AFC for NoSpaceLeft.
    let (area, path, digest, probe, engine) = setup(Effect::StageFailure(18), previous.clone());
    let original = fs::read(&path).unwrap();
    probe.phone.lock().unwrap().cleanup_fails = true;
    let (_, stop) = watch::channel(false);
    let receipt = engine
        .install(&path, PHONE, &digest, None, stop)
        .await
        .unwrap();

    {
        let phone = probe.phone.lock().unwrap();
        assert_eq!(phone.stage_calls, 1);
        assert_eq!(phone.staged_chunks.len(), 2);
        assert_eq!(phone.staged_chunks.concat(), original[..128]);
        assert_eq!(phone.submissions, 0);
        assert_eq!(phone.app, previous);
        assert_eq!(phone.cleanup_calls, 1);
        assert_eq!(
            phone.cleanup_target.as_deref(),
            Some(format!("PublicStaging/mgm-{}.ipa", receipt.id).as_str())
        );
    }
    assert_eq!(fs::read(&path).unwrap(), original);
    assert_eq!(receipt.phase, Phase::FailedBeforeSubmit);
    assert_eq!(receipt.ios_accepted, None);
    assert!(!receipt.transfer_verified && !receipt.launch_verified);
    assert!(receipt.cleanup_pending);
    assert_eq!(
        receipt
            .events
            .iter()
            .map(|event| event.phase)
            .collect::<Vec<_>>(),
        [
            Phase::Prepared,
            Phase::Transferring,
            Phase::FailedBeforeSubmit
        ]
    );
    assert_eq!(
        receipt.events.last().unwrap().issue.as_deref(),
        Some("device_storage_full")
    );

    probe.phone.lock().unwrap().cleanup_fails = false;
    let recovered = engine.recover(receipt.id, PHONE).await.unwrap();
    assert_eq!(recovered.phase, Phase::FailedBeforeSubmit);
    assert_eq!(
        recovered.events.last().unwrap().issue,
        receipt.events.last().unwrap().issue
    );
    assert!(!recovered.cleanup_pending);
    assert_eq!(probe.phone.lock().unwrap().submissions, 0);

    // CLI reads back the actual journal produced by the engine, under an isolated data root.
    let root = area.path().join("cli");
    let cli_journal = root.join(BUNDLE_ID).join("ios-installer");
    fs::create_dir_all(&cli_journal).unwrap();
    let record = format!("{}.json", receipt.id);
    fs::copy(probe.journal.join(&record), cli_journal.join(&record)).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_mgm-ios-installer"))
        .args(["receipt", &receipt.id.to_string()])
        .env("XDG_DATA_HOME", &root)
        .env("LOCALAPPDATA", &root)
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output.status);
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["receipt"], serde_json::to_value(&recovered).unwrap());
    assert_eq!(
        json["receipt"]["events"][2]["message"],
        "Espace insuffisant signalé par l’iPhone pendant le transfert. L’installation n’a pas été demandée. Libère de l’espace sur l’appareil, puis relance l’opération."
    );
    assert!(!String::from_utf8(output.stdout)
        .unwrap()
        .contains("afc error:"));
    println!("Écritures AFC simulées : 2. Demandes d’installation : 0.");
    println!("Reçu de la CLI : {json}");
}

#[test]
fn transfer_errors_use_native_status_and_preserve_the_cause() {
    let issue = transfer_error(IdeviceError::Afc(AfcError::from(18)));
    assert_eq!(issue.code, "device_storage_full");
    let source = std::error::Error::source(&issue).unwrap();
    assert!(matches!(
        source.downcast_ref::<IdeviceError>(),
        Some(IdeviceError::Afc(AfcError::NoSpaceLeft))
    ));
    assert_eq!(source.to_string(), "afc error: No space left");
    assert_eq!(
        transfer_error(IdeviceError::Afc(AfcError::ServiceNotConnected)).code,
        "usb_io"
    );
    assert_eq!(
        transfer_error(IdeviceError::Afc(AfcError::WriteError)).code,
        "transfer_unverified"
    );
    assert_eq!(
        transfer_error(IdeviceError::Socket(std::io::Error::new(
            std::io::ErrorKind::StorageFull,
            "No space left",
        )))
        .code,
        "usb_io"
    );
    assert_eq!(Issue::storage().code, "journal_io");
}

#[tokio::test]
async fn readback_after_lost_response_does_not_submit_again() {
    let (_area, path, digest, probe, engine) =
        setup(Effect::LostAfterCommit, Some(installed("30")));
    let (_, stop) = watch::channel(false);
    let receipt = engine
        .install(&path, PHONE, &digest, None, stop.clone())
        .await
        .unwrap();
    assert_eq!(receipt.phase, Phase::AcceptanceUnknown);
    assert_eq!(
        engine
            .install(&path, PHONE, &digest, None, stop)
            .await
            .unwrap_err()
            .code,
        "operation_pending"
    );
    assert_eq!(
        engine.recover(receipt.id, OTHER).await.unwrap_err().code,
        "device_mismatch"
    );
    let reopened = Engine::new(probe.journal.clone(), probe.clone()).unwrap();
    let found = reopened.recover(receipt.id, PHONE).await.unwrap();
    assert_eq!(found.phase, Phase::InstalledBuildObservedAfterInterruption);
    assert_eq!(found.ios_accepted, None);
    assert!(!found.cleanup_pending);
    assert_eq!(probe.phone.lock().unwrap().submissions, 1);
}

#[tokio::test]
async fn same_version_and_absent_app_remain_uncertain() {
    for previous in [None, Some(installed("31"))] {
        let (_area, path, digest, probe, engine) = setup(Effect::LostWithoutEffect, previous);
        let (_, stop) = watch::channel(false);
        let receipt = engine
            .install(&path, PHONE, &digest, None, stop)
            .await
            .unwrap();
        assert_eq!(
            engine
                .close_unconfirmed(receipt.id, PHONE)
                .unwrap_err()
                .code,
            "review_required"
        );
        let observed = engine.recover(receipt.id, PHONE).await.unwrap();
        assert_eq!(observed.phase, Phase::AcceptanceUnknown);
        assert!(observed.cleanup_pending && observed.ios_accepted.is_none());
        assert_eq!(
            engine.close_unconfirmed(receipt.id, PHONE).unwrap().phase,
            Phase::OutcomeLeftUnconfirmed
        );
        assert_eq!(probe.phone.lock().unwrap().submissions, 1);
    }
}

#[tokio::test]
async fn simultaneous_requests_and_cancellation_preserve_checkpoint_semantics() {
    for phase in [Effect::WaitBeforeSubmit, Effect::WaitAfterSubmit] {
        let (_area, path, digest, probe, engine) = setup(phase, None);
        let (send, stop) = watch::channel(false);
        let install = engine.install(&path, PHONE, &digest, None, stop.clone());
        let check = async {
            probe.arrived.notified().await;
            assert_eq!(
                engine
                    .install(&path, PHONE, &digest, None, stop)
                    .await
                    .unwrap_err()
                    .code,
                "operation_active"
            );
            send.send(true).unwrap();
        };
        let (result, ()) = tokio::join!(install, check);
        let receipt = result.unwrap();
        assert!(receipt.stop_requested);
        if matches!(phase, Effect::WaitBeforeSubmit) {
            assert_eq!(receipt.phase, Phase::FailedBeforeSubmit);
            assert_eq!(probe.phone.lock().unwrap().submissions, 0);
        } else {
            assert_eq!(receipt.phase, Phase::AcceptanceUnknown);
            assert!(receipt.cleanup_pending);
        }
    }
}

#[tokio::test]
async fn digest_change_and_conflicting_team_stop_before_usb_write() {
    let mut foreign = installed("31");
    foreign.team = Some("FOREIGN123".into());
    let (_area, path, digest, probe, engine) = setup(Effect::Accepted, Some(foreign));
    let (_, stop) = watch::channel(false);
    assert_eq!(
        engine
            .install(&path, PHONE, &"0".repeat(64), None, stop.clone())
            .await
            .unwrap_err()
            .code,
        "ipa_changed"
    );
    assert_eq!(
        engine
            .install(&path, PHONE, &digest, None, stop)
            .await
            .unwrap_err()
            .code,
        "installed_team_mismatch"
    );
    assert_eq!(probe.phone.lock().unwrap().stage_calls, 0);
}

#[tokio::test]
async fn changed_inventory_requires_new_local_confirmation() {
    let (_area, path, digest, probe, engine) = setup(Effect::Accepted, Some(installed("30")));
    let (_, stop) = watch::channel(false);
    let result = engine
        .install(&path, PHONE, &digest, Some(&None), stop)
        .await
        .unwrap_err();
    assert_eq!(result.code, "installed_state_changed");
    assert_eq!(probe.phone.lock().unwrap().stage_calls, 0);
}

#[test]
fn abrupt_exit_leaves_a_recoverable_submission_intent() {
    const CHILD_ROOT: &str = "MGM_TEST_INTERRUPTED_OPERATION_ROOT";
    if let Some(directory) = std::env::var_os(CHILD_ROOT) {
        let root = PathBuf::from(directory);
        let source = root.join("Mon iPhone.ipa");
        let journal = root.join("receipts");
        let sha = ipa::inspect(&source, None).unwrap().sha256;
        let probe = Probe {
            phone: Arc::new(Mutex::new(Phone {
                effect: Effect::WaitAfterSubmit,
                ..Default::default()
            })),
            arrived: Arc::new(Notify::new()),
            journal: journal.clone(),
        };
        let engine = Engine::new(journal, probe).unwrap();
        let (_sender, stop) = watch::channel(false);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _ = runtime.block_on(engine.install(&source, PHONE, &sha, None, stop));
        panic!("Le processus de test aurait dû être arrêté au point de contrôle");
    }

    let (area, _source, _digest, probe, engine) = setup(Effect::Accepted, None);
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "abrupt_exit_leaves_a_recoverable_submission_intent",
        ])
        .env(CHILD_ROOT, area.path())
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let limit = std::time::Instant::now() + Duration::from_secs(10);
    let receipt = loop {
        if let Some(receipt) = engine
            .list()
            .unwrap()
            .into_iter()
            .find(|entry| entry.phase == Phase::SubmissionIntent)
        {
            break Some(receipt);
        }
        if std::time::Instant::now() > limit || child.try_wait().unwrap().is_some() {
            break None;
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    if child.try_wait().unwrap().is_none() {
        child.kill().unwrap();
        child.wait().unwrap();
    }
    let receipt = receipt.expect("intention d’installation durable avant l’arrêt du processus");
    probe.phone.lock().unwrap().app = Some(installed("31"));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let recovered = runtime.block_on(engine.recover(receipt.id, PHONE)).unwrap();
    assert_eq!(
        recovered.phase,
        Phase::InstalledBuildObservedAfterInterruption
    );
    assert_eq!(probe.phone.lock().unwrap().submissions, 0);
}
