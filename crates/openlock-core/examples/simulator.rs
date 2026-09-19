//! Deterministic test device, not production firmware. Control lines simulate local hardware.
#[path = "../tests/support/mod.rs"]
mod support;
use openlock_core::device::{BootOutcome, SessionContext};
use openlock_protocol::{Session, SessionEvent};
use openlock_types::*;
use std::io::{self, BufRead, Write};
use support::*;
fn hex(data: &[u8]) -> String {
    data.iter().map(|x| format!("{x:02x}")).collect()
}
fn unhex(text: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if text.len() % 2 != 0 || !text.is_ascii() {
        return Err("invalid hex".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&text[i..i + 2], 16)?))
        .collect()
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut device = fresh();
    device.open_pairing_window()?;
    let mut session = Session::responder(&[4; 32], KNOWN_CAPABILITIES)?;
    let mut context: Option<SessionContext> = None;
    let mut confirm = false;
    for line in io::stdin().lock().lines() {
        let line = line?;
        let response: Result<String, Box<dyn std::error::Error>> = (|| match line.as_str() {
            "connect" => {
                let private = if device.snapshot().device_key.x25519_public_key
                    == openlock_crypto::static_public(&[12; 32])
                {
                    [12; 32]
                } else {
                    [4; 32]
                };
                session = Session::responder(&private, KNOWN_CAPABILITIES)?;
                context = None;
                Ok("ok".into())
            }
            "pair" => {
                device.open_pairing_window()?;
                Ok("ok".into())
            }
            "confirm-next" => {
                confirm = true;
                Ok("ok".into())
            }
            "complete-unlock" => {
                complete(&mut device, BoltState::Unlocked);
                Ok("ok".into())
            }
            "complete-lock" => {
                complete(&mut device, BoltState::Locked);
                Ok("ok".into())
            }
            "confirm-boot" => {
                device.platform_mut().boot = BootOutcome::Confirmed;
                device.poll()?;
                Ok("ok".into())
            }
            "quit" => std::process::exit(0),
            _ => {
                let input = unhex(&line)?;
                let (events, reply) = session.receive(&input)?;
                if let Some(reply) = reply {
                    for event in events {
                        if let SessionEvent::HandshakeComplete { peer } = event {
                            context = Some(device.context(peer));
                        }
                    }
                    return Ok(hex(&reply));
                }
                let mut output = None;
                for event in events {
                    if let SessionEvent::Request {
                        request_id,
                        command,
                        ..
                    } = event
                    {
                        let context = context.ok_or("no handshake")?;
                        if confirm {
                            device.confirm_physical(context, &command)?;
                            confirm = false;
                        }
                        let response = device.handle(context, &command);
                        output = Some(hex(&session.respond(request_id, response)?));
                        if context.generation != device.snapshot().generation {
                            session.close();
                        }
                    }
                }
                Ok(output.ok_or("no response")?)
            }
        })();
        match response {
            Ok(line) => println!("{line}"),
            Err(e) => println!("error:{e}"),
        };
        io::stdout().flush()?;
    }
    Ok(())
}

fn fixtures() {
    use openlock_crypto::{sign_policy, wire::encode_wire, SigningKey};
    let admin = grant(2, KNOWN_RIGHTS, None, 0);
    let policy = sign_policy(
        &SigningKey::from_bytes(&[9; 32]),
        &PolicyUpdate {
            lock_id: LockId([1; 16]),
            epoch: 0,
            version: 1,
            revoked: [CredentialId([5; 16])].into_iter().collect(),
        },
    )
    .unwrap();
    let mut config = DeviceConfig::factory(&factory().info);
    config.version = 1;
    let actions = vec![
        ("pairing", 0, Action::PairingStatus),
        (
            "claim",
            1,
            Action::Claim {
                setup_key: [7; 32],
                issuer: SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
                admin_credential: admin.clone(),
            },
        ),
        ("unlock", 1, Action::Unlock),
        ("status", 0, Action::Status),
        ("lock", 2, Action::Lock),
        ("config", 3, Action::SetConfig(config)),
        ("getconfig", 0, Action::GetConfig),
        (
            "log",
            0,
            Action::ReadLog {
                after: 0,
                limit: 16,
            },
        ),
        ("begin", 4, Action::FirmwareBegin(signed_image(b"abc", 1))),
        (
            "chunk",
            5,
            Action::FirmwareChunk {
                offset: 0,
                data: b"abc".to_vec(),
            },
        ),
        ("finish", 6, Action::FirmwareFinish),
        ("activate", 7, Action::FirmwareActivate),
        ("firmware", 0, Action::FirmwareStatus),
        ("policy", 8, Action::ApplyPolicy(policy)),
        ("clock", 9, Action::SetClock(2000)),
        ("reboot", 10, Action::Reboot),
        ("reset", 11, Action::FactoryReset),
    ];
    for (name, seq, action) in actions {
        let credential = if matches!(action, Action::PairingStatus | Action::Claim { .. }) {
            vec![]
        } else {
            admin.clone()
        };
        println!(
            "{} {}",
            name,
            hex(&encode_wire(&request(credential, seq, action)).unwrap())
        );
    }
}
fn main() {
    if std::env::args().nth(1).as_deref() == Some("fixtures") {
        fixtures();
        return;
    }
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1)
    }
}
