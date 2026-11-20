use mgm_ios_installer::{
    device_key, ipa,
    operation::{preflight_target, Engine, Phase},
    preparation::{self, Answer, Challenge},
    state_root,
    usb::{Access, NativeUsb},
    Issue, Result, SCHEMA,
};
use serde_json::{json, Value};
use std::{
    ffi::OsString,
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
};
use tokio::sync::watch;
use uuid::Uuid;
use zeroize::Zeroizing;

const USAGE: &str = "MGM iOS Installer\n  diagnose\n  apple-diagnose --provider ORIGINE\n  prepare FICHIER.ipa --device UDID --provider ORIGINE --output SIGNED.ipa\n  inspect FICHIER.ipa [--device UDID]\n  installed --device UDID\n  preflight FICHIER.ipa --device UDID\n  install FICHIER.ipa --device UDID --sha256 EMPREINTE\n  receipts\n  receipt ID\n  recover ID --device UDID\n  close-unconfirmed ID --device UDID --reviewed";

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    match run(&args).await {
        Ok((value, exit)) => {
            println!("{value}");
            ExitCode::from(exit)
        }
        Err(issue) => {
            println!("{}", json!({"schema":SCHEMA,"ok":false,"error":issue}));
            ExitCode::FAILURE
        }
    }
}

async fn run(args: &[OsString]) -> Result<(Value, u8)> {
    let action = args.first().and_then(|x| x.to_str()).unwrap_or("help");
    let value = match (action, &args[1.min(args.len())..]) {
        ("help" | "--help", []) => json!({"schema":SCHEMA,"usage":USAGE}),
        ("--version", []) => {
            json!({"name":"mgm-ios-installer","version":env!("CARGO_PKG_VERSION")})
        }
        ("diagnose", []) => {
            let devices = NativeUsb.diagnose().await?;
            json!({"schema":SCHEMA,"usb_service":"available","os":std::env::consts::OS,"devices":devices})
        }
        ("apple-diagnose", [flag, endpoint]) if flag == "--provider" => {
            preparation::diagnose_provider(text(endpoint)?).await?;
            json!({"schema":SCHEMA,"provider":"client_info_available"})
        }
        ("prepare", [source, device, target, provider, endpoint, output, file])
            if device == "--device" && provider == "--provider" && output == "--output" =>
        {
            let source = PathBuf::from(source);
            let destination = PathBuf::from(file);
            let target = text(target)?;
            device_key(target)?;
            let local = ipa::inspect_input(&source)?;
            if local.extensions != 0 {
                return Err(Issue::new(
                    "extension_identity_unverified",
                    "Choisis la version standard MGM sans extensions.",
                ));
            }
            if destination.exists() {
                return Err(Issue::new(
                    "signed_output_exists",
                    "Choisis un nouveau fichier de sortie pour préserver l’IPA existante.",
                ));
            }
            let installed = NativeUsb.lookup_mgm(target).await?.ok_or_else(|| {
                Issue::new(
                    "installed_data_identity_unverified",
                    "Agent Admin doit être présent sur l’iPhone sélectionné pour préparer cette mise à jour.",
                )
            })?;
            if installed.data_identity.is_none() {
                return Err(Issue::new(
                    "installed_data_identity_unverified",
                    "Relis l’identité signée d’Agent Admin sur l’iPhone avant de connecter le compte.",
                ));
            }
            eprintln!(
                "MGM · mise à jour du build {} vers {} sur la cible USB sélectionnée",
                installed.identity.build, local.identity.build
            );
            let endpoint = text(endpoint)?;
            preparation::diagnose_provider(endpoint).await?;
            let email = prompt("Compte Apple : ")?;
            let password = Zeroizing::new(
                rpassword::prompt_password("Mot de passe Apple : ")
                    .map_err(|_| Issue::storage())?,
            );
            let mut account =
                preparation::connect(endpoint, email, password, print_stage, |challenge| async {
                    tokio::task::spawn_blocking(move || answer(challenge))
                        .await
                        .unwrap_or(Answer::Cancel)
                })
                .await?;
            if NativeUsb.lookup_mgm(target).await?.as_ref() != Some(&installed) {
                return Err(Issue::new(
                    "preflight_changed",
                    "L’app installée a changé pendant la connexion. Relis l’identité avant de préparer l’IPA.",
                ));
            }
            let parent = destination
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| std::path::Path::new("."));
            let work = tempfile::tempdir_in(parent).map_err(|_| Issue::storage())?;
            let output = work.path().join("prepared.ipa");
            let result = account
                .sign_update(
                    &source,
                    &local.sha256,
                    target,
                    work.path(),
                    &output,
                    print_stage,
                )
                .await?;
            let file = tempfile::TempPath::try_from_path(output).map_err(|_| Issue::storage())?;
            file.persist_noclobber(&destination)
                .map_err(|_| Issue::storage())?;
            json!({"schema":SCHEMA,"prepared":destination,"ipa":result,"submitted":false})
        }
        ("inspect", [path]) => {
            json!({"schema":SCHEMA,"ipa":ipa::inspect(&PathBuf::from(path),None)?})
        }
        ("inspect", [path, flag, target]) if flag == "--device" => {
            let udid = text(target)?;
            device_key(udid)?;
            json!({"schema":SCHEMA,"ipa":ipa::inspect(&PathBuf::from(path),Some(udid))?})
        }
        ("installed", [flag, target]) if flag == "--device" => {
            let udid = text(target)?;
            device_key(udid)?;
            json!({"schema":SCHEMA,"installed":NativeUsb.lookup_mgm(udid).await?})
        }
        ("preflight", [path, flag, target]) if flag == "--device" => {
            let udid = text(target)?;
            device_key(udid)?;
            let ipa = ipa::inspect(&PathBuf::from(path), Some(udid))?;
            let installed = preflight_target(&NativeUsb, udid, &ipa).await?;
            json!({"schema":SCHEMA,"ipa":ipa,"installed":installed})
        }
        ("receipts", []) => json!({"schema":SCHEMA,"receipts":engine()?.list()?}),
        ("receipt", [id]) => json!({"schema":SCHEMA,"receipt":engine()?.receipt(identifier(id)?)?}),
        ("recover", [id, flag, target]) if flag == "--device" => {
            json!({"schema":SCHEMA,"receipt":engine()?.recover(identifier(id)?,text(target)?).await?})
        }
        ("close-unconfirmed", [id, flag, target, reviewed])
            if flag == "--device" && reviewed == "--reviewed" =>
        {
            json!({"schema":SCHEMA,"receipt":engine()?.close_unconfirmed(identifier(id)?,text(target)?)?})
        }
        ("install", [path, device, target, digest, expected])
            if device == "--device" && digest == "--sha256" =>
        {
            let (stop, receiver) = watch::channel(false);
            tokio::spawn(async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    let _ = stop.send(true);
                }
            });
            let receipt = engine()?
                .install(
                    &PathBuf::from(path),
                    text(target)?,
                    text(expected)?,
                    None,
                    receiver,
                )
                .await?;
            let exit = if receipt.phase == Phase::InstalledBuildObserved {
                0
            } else {
                2
            };
            return Ok((json!({"schema":SCHEMA,"receipt":receipt}), exit));
        }
        _ => return Err(Issue::new("usage", USAGE)),
    };
    Ok((value, 0))
}

fn engine() -> Result<Engine<NativeUsb>> {
    Engine::new(state_root()?, NativeUsb)
}

fn text(value: &OsString) -> Result<&str> {
    value
        .to_str()
        .ok_or_else(|| Issue::new("invalid_argument", "Argument de commande illisible."))
}

fn identifier(value: &OsString) -> Result<Uuid> {
    Uuid::parse_str(text(value)?)
        .map_err(|_| Issue::new("receipt_invalid", "Identifiant de reçu invalide."))
}

fn prompt(label: &str) -> Result<String> {
    let mut stderr = io::stderr();
    write!(stderr, "{label}")
        .and_then(|_| stderr.flush())
        .map_err(|_| Issue::storage())?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|_| Issue::storage())?;
    Ok(answer.trim().to_owned())
}

fn print_stage(stage: preparation::Stage) {
    if let Ok(name) = serde_json::to_string(&stage) {
        eprintln!("MGM · {}", name.trim_matches('"'));
    }
}

fn answer(challenge: Challenge) -> Answer {
    if challenge.choose {
        for (index, number) in challenge.numbers.iter().enumerate() {
            eprintln!(
                "{} · SMS au numéro qui finit par {}",
                index + 1,
                number.suffix
            );
        }
        match prompt("Appareil de confiance (d), numéro de SMS ou annuler (a) : ")
            .ok()
            .as_deref()
        {
            Some("d") => Answer::Device,
            Some(choice) => choice
                .parse::<usize>()
                .ok()
                .and_then(|index| index.checked_sub(1))
                .and_then(|index| challenge.numbers.get(index))
                .map(|number| Answer::Sms { id: number.id })
                .unwrap_or(Answer::Cancel),
            None => Answer::Cancel,
        }
    } else {
        if challenge.rejected {
            eprintln!("Apple demande une nouvelle validation.");
        }
        rpassword::prompt_password("Code Apple à six chiffres (Entrée pour annuler) : ")
            .ok()
            .filter(|code| !code.is_empty())
            .map(|code| Answer::Code { code })
            .unwrap_or(Answer::Cancel)
    }
}
