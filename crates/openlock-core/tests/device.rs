mod support;
use openlock_core::device::*;
use openlock_crypto::{sign_grant, SigningKey};
use openlock_types::*;
use support::*;

#[test]
fn physical_cycle_counts_only_unlock_and_returns_sensor_evidence() {
    let mut d = ready();
    let cred = grant(3, RIGHTS_UNLOCK | RIGHTS_LOCK | RIGHTS_STATUS, Some(1), 0);
    let c = request(cred.clone(), 1, Action::Unlock);
    let context = d.context(peer());
    let first = success(d.handle(context, &c));
    assert_eq!(first.phase, OperationPhase::Running);
    assert_eq!(d.snapshot().uses[&CredentialId([3; 16])], 1);
    assert_eq!(d.handle(context, &c).result, Ok(Reply::Operation(first)));
    assert_eq!(d.platform().actions.len(), 1);
    complete(&mut d, BoltState::Unlocked);
    let r = success(d.handle(context, &c));
    assert_eq!(r.evidence, CompletionEvidence::Sensor);
    for action in [Action::Status, Action::CredentialStatus] {
        assert!(d
            .handle(context, &request(cred.clone(), 0, action))
            .result
            .is_ok());
    }
    success(d.handle(context, &request(cred.clone(), 2, Action::Lock)));
    complete(&mut d, BoltState::Locked);
    assert_eq!(
        d.handle(context, &request(cred, 3, Action::Unlock)).result,
        Err(Error::UsageExhausted.code())
    );
}
#[test]
fn no_change_busy_privacy_door_and_unsupported_do_not_consume() {
    let mut d = ready();
    // A confirmed target requires no movement, even when extending would be unsafe.
    d.platform_mut().sample.door = Reading::Known(DoorState::Open);
    assert_eq!(
        success(send(&mut d, 1, Action::Lock)).evidence,
        CompletionEvidence::NoChange
    );
    assert!(d.platform().actions.is_empty());
    d.platform_mut().sample.door = Reading::Known(DoorState::Closed);
    d.platform_mut().sample.privacy = Reading::Known(true);
    assert_eq!(
        send(&mut d, 2, Action::Unlock).result,
        Err(Error::PrivacyActive.code())
    );
    assert!(d.snapshot().uses.is_empty());
    d.platform_mut().sample.privacy = Reading::Known(false);
    success(send(&mut d, 2, Action::Unlock));
    assert_eq!(
        send(&mut d, 3, Action::Lock).result,
        Err(Error::Busy.code())
    );
    complete(&mut d, BoltState::Unlocked);
    d.platform_mut().sample.door = Reading::Known(DoorState::Open);
    assert_eq!(
        send(&mut d, 3, Action::Lock).result,
        Err(Error::DoorOpen.code())
    );
    assert_eq!(d.snapshot().uses[&CredentialId([2; 16])], 1);
}

#[test]
fn opening_or_losing_the_door_sensor_stops_manual_and_automatic_locking() {
    for automatic in [false, true] {
        for door in [Reading::Known(DoorState::Open), Reading::Unknown] {
            let mut d = ready();
            d.platform_mut().sample.bolt = Reading::Known(BoltState::Unlocked);
            d.hardware_changed().unwrap();
            if automatic {
                let mut config = d.snapshot().config.clone();
                config.version = 1;
                config.auto_relock = AutoRelock::Delay(500);
                success(send(&mut d, 1, Action::SetConfig(config)));
                d.platform_mut().ms += 500;
                d.poll().unwrap();
            } else {
                success(send(&mut d, 1, Action::Lock));
            }
            assert_eq!(d.platform().actions, [ActionTarget::Lock]);
            d.platform_mut().sample.door = door;
            d.poll().unwrap();
            assert_eq!(d.platform().stop_count, 1);
            assert!(d.status().active.is_none());
            assert!(!d.snapshot().pending_relock);
            assert!(!d.snapshot().automatic_inflight);
            if automatic {
                let logged = d
                    .snapshot()
                    .events
                    .iter()
                    .rev()
                    .find(|event| event.operation.is_some())
                    .unwrap()
                    .operation
                    .as_ref()
                    .unwrap();
                assert_eq!(logged.opcode, 3);
                assert_eq!(logged.sequence, 0);
                assert_eq!(logged.phase, OperationPhase::Failed);
            }
            if !automatic {
                let Ok(Reply::Operation(status)) = send(&mut d, 1, Action::Lock).result else {
                    panic!("expected the retained failed operation");
                };
                assert_eq!(status.phase, OperationPhase::Failed);
                assert_eq!(
                    status.error,
                    if door == Reading::Unknown {
                        Error::SensorConflict.code()
                    } else {
                        Error::DoorOpen.code()
                    }
                );
            }
            d.platform_mut().sample.door = Reading::Known(DoorState::Closed);
            d.platform_mut().ms += 10_000;
            d.poll().unwrap();
            assert_eq!(d.platform().actions.len(), 1);
        }
    }
}

#[test]
fn trial_boot_defers_an_already_due_automatic_lock() {
    let mut d = ready();
    d.platform_mut().sample.bolt = Reading::Known(BoltState::Unlocked);
    d.hardware_changed().unwrap();
    let mut config = d.snapshot().config.clone();
    config.version = 1;
    config.auto_relock = AutoRelock::Delay(500);
    success(send(&mut d, 1, Action::SetConfig(config)));
    success(send(
        &mut d,
        2,
        Action::FirmwareBegin(signed_image(b"abc", 1)),
    ));
    success(send(
        &mut d,
        3,
        Action::FirmwareChunk {
            offset: 0,
            data: b"abc".to_vec(),
        },
    ));
    success(send(&mut d, 4, Action::FirmwareFinish));
    success(send(&mut d, 5, Action::FirmwareActivate));
    d.platform_mut().ms += 1000;
    d.poll().unwrap();
    assert!(d.platform().actions.is_empty());
    assert!(d.snapshot().pending_relock);
    d.platform_mut().boot = BootOutcome::Confirmed;
    d.poll().unwrap();
    assert_eq!(d.platform().actions, [ActionTarget::Lock]);
}

#[test]
fn a_door_already_open_at_boot_still_triggers_the_reminder() {
    let mut d = ready();
    let mut config = d.snapshot().config.clone();
    config.version = 1;
    config.door_ajar_ms = 500;
    success(send(&mut d, 1, Action::SetConfig(config)));
    d.platform_mut().sample.door = Reading::Known(DoorState::Open);
    let (s, h) = d.into_parts();
    let mut d = DeviceController::open(factory(), s, h).unwrap();
    d.platform_mut().ms += 500;
    d.poll().unwrap();
    assert_eq!(d.status().fault, Fault::DoorAjar);
}
#[test]
fn pulse_without_sensor_never_claims_physical_opening() {
    let mut f = factory();
    f.info.actuator = ActuatorKind::Pulse;
    f.info.capabilities &= !(1 << 3);
    f.info.bolt_sensor = false;
    let mut h = Hardware::default();
    h.sample.bolt = Reading::Unsupported;
    let mut d = DeviceController::provision(f, MemoryStore::default(), h).unwrap();
    claim(&mut d);
    success(send(&mut d, 1, Action::Unlock));
    d.actuator_finished(d.platform().action_id.unwrap(), ActuatorResult::Completed)
        .unwrap();
    let r = success(send(&mut d, 1, Action::Unlock));
    assert_eq!(r.evidence, CompletionEvidence::Driver);
    assert_eq!(d.status().bolt, Reading::Unsupported);
    assert_eq!(
        send(&mut d, 2, Action::Lock).result,
        Err(Error::UnsupportedCapability.code())
    );
}
#[test]
fn stale_sequences_survive_eviction_and_reboot() {
    let mut d = ready();
    let c = request(grant(2, KNOWN_RIGHTS, None, 0), 1, Action::Unlock);
    success(d.handle(d.context(peer()), &c));
    complete(&mut d, BoltState::Unlocked);
    assert_eq!(
        send(&mut d, 1, Action::Reboot).result,
        Err(Error::Conflict.code())
    );
    for seq in 2..22 {
        success(send(&mut d, seq, Action::SetClock(1000 + seq)));
    }
    assert_eq!(
        d.handle(d.context(peer()), &c).result,
        Err(Error::ResultUnavailable.code())
    );
    let (s, h) = d.into_parts();
    let mut d = DeviceController::open(factory(), s, h).unwrap();
    assert_eq!(
        d.handle(d.context(peer()), &c).result,
        Err(Error::ResultUnavailable.code())
    );
    assert_eq!(d.platform().actions.len(), 1);
}
#[test]
fn every_acceptance_commit_boundary_is_fail_closed() {
    for after in [false, true] {
        for delta in [1, 2] {
            let mut d = ready();
            let (store, h) = d.into_parts();
            let access = store.clone();
            d = DeviceController::open(factory(), store, h).unwrap();
            access.fail_at.set(Some(access.commits.get() + delta));
            access.after_write.set(after);
            let c = request(
                grant(3, RIGHTS_UNLOCK | RIGHTS_STATUS, Some(1), 0),
                1,
                Action::Unlock,
            );
            assert_eq!(
                d.handle(d.context(peer()), &c).result,
                Err(Error::StorageUnavailable.code())
            );
            let count = d.platform().actions.len();
            assert_eq!(count, if delta == 1 { 0 } else { 1 });
            assert_eq!(
                d.handle(d.context(peer()), &c).result,
                Err(Error::StorageUnavailable.code())
            );
            access.fail_at.set(None);
            let (store, h) = d.into_parts();
            let mut recovered = DeviceController::open(factory(), store, h).unwrap();
            let replay = recovered.handle(recovered.context(peer()), &c);
            if delta == 1 && !after {
                assert!(replay.result.is_ok());
                assert_eq!(recovered.platform().actions.len(), 1);
            } else {
                assert!(matches!(
                    replay.result,
                    Ok(Reply::Operation(OperationStatus {
                        phase: OperationPhase::Unknown,
                        ..
                    }))
                ));
                assert_eq!(recovered.platform().actions.len(), count);
            }
        }
    }
}
#[test]
fn reboot_never_replays_an_interrupted_motor() {
    let mut d = ready();
    success(send(&mut d, 1, Action::Unlock));
    let (s, h) = d.into_parts();
    let mut d = DeviceController::open(factory(), s, h).unwrap();
    let r = send(&mut d, 1, Action::Unlock);
    assert!(matches!(
        r.result,
        Ok(Reply::Operation(OperationStatus {
            phase: OperationPhase::Unknown,
            ..
        }))
    ));
    assert_eq!(d.platform().actions.len(), 1);
}
#[test]
fn faults_and_timeout_retain_consumption() {
    for fault in [
        ActuatorResult::Jammed,
        ActuatorResult::SensorConflict,
        ActuatorResult::Failed,
    ] {
        let mut d = ready();
        success(send(&mut d, 1, Action::Unlock));
        d.actuator_finished(d.platform().action_id.unwrap(), fault)
            .unwrap();
        assert!(matches!(
            send(&mut d, 1, Action::Unlock).result,
            Ok(Reply::Operation(OperationStatus {
                phase: OperationPhase::Failed,
                ..
            }))
        ));
        assert_eq!(d.snapshot().uses[&CredentialId([2; 16])], 1);
    }
    let mut d = ready();
    success(send(&mut d, 1, Action::Unlock));
    d.platform_mut().ms += 40_000;
    d.poll().unwrap();
    assert_eq!(d.status().fault, Fault::Timeout);
    assert_eq!(d.platform().stop_count, 1);
    assert!(matches!(
        send(&mut d, 1, Action::Unlock).result,
        Ok(Reply::Operation(OperationStatus { error: 36, .. }))
    ));
}
#[test]
fn relock_waits_for_closed_door_and_survives_restart() {
    let mut d = ready();
    let mut config = d.snapshot().config.clone();
    config.version = 1;
    config.auto_relock = AutoRelock::AfterClose(500);
    success(send(&mut d, 1, Action::SetConfig(config)));
    success(send(&mut d, 2, Action::Unlock));
    d.platform_mut().sample.door = Reading::Known(DoorState::Open);
    complete(&mut d, BoltState::Unlocked);
    assert!(d.snapshot().pending_relock);
    d.platform_mut().ms += 1000;
    d.poll().unwrap();
    assert_eq!(d.platform().actions.len(), 1);
    let (s, h) = d.into_parts();
    let mut d = DeviceController::open(factory(), s, h).unwrap();
    d.poll().unwrap();
    assert_eq!(d.platform().actions.len(), 1);
    d.platform_mut().sample.door = Reading::Known(DoorState::Closed);
    d.poll().unwrap();
    d.platform_mut().ms += 500;
    d.poll().unwrap();
    assert_eq!(d.platform().actions.len(), 2);
    complete(&mut d, BoltState::Locked);
    assert!(!d.snapshot().pending_relock);
    let logged = d
        .snapshot()
        .events
        .last()
        .unwrap()
        .operation
        .as_ref()
        .unwrap();
    assert_eq!(logged.opcode, 3);
    assert_eq!(logged.sequence, 0);
    assert_eq!(logged.phase, OperationPhase::Completed);
    assert_eq!(logged.evidence, CompletionEvidence::Sensor);
}
#[test]
fn pairing_window_failures_and_competing_claims() {
    let mut d = fresh();
    let make = |key| {
        request(
            vec![],
            1,
            Action::Claim {
                setup_key: key,
                issuer: SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
                admin_credential: grant(2, KNOWN_RIGHTS, None, 0),
            },
        )
    };
    assert_eq!(
        d.handle(d.context(peer()), &make([7; 32])).result,
        Err(Error::PairingClosed.code())
    );
    d.open_pairing_window().unwrap();
    for _ in 0..5 {
        assert_eq!(
            d.handle(d.context(peer()), &make([6; 32])).result,
            Err(Error::InvalidSetupKey.code())
        );
    }
    assert_eq!(
        d.handle(d.context(peer()), &make([7; 32])).result,
        Err(Error::PairingClosed.code())
    );
    d.open_pairing_window().unwrap();
    let stale = d.context(peer());
    assert!(d.handle(stale, &make([7; 32])).result.is_ok());
    assert_eq!(
        d.handle(stale, &make([7; 32])).result,
        Err(Error::InvalidState.code())
    );
    assert_eq!(
        d.handle(d.context(peer()), &make([7; 32])).result,
        Err(Error::AlreadyProvisioned.code())
    );
}
#[test]
fn reset_requires_exact_unexpired_local_confirmation_and_invalidates_credentials() {
    let mut d = ready();
    let old = grant(2, KNOWN_RIGHTS, None, 0);
    let c = request(old.clone(), 1, Action::FactoryReset);
    let context = d.context(peer());
    assert_eq!(
        d.handle(context, &c).result,
        Err(Error::PhysicalConfirmationRequired.code())
    );
    d.confirm_physical(context, &c).unwrap();
    d.platform_mut().ms += 60_000;
    assert_eq!(
        d.handle(context, &c).result,
        Err(Error::PhysicalConfirmationRequired.code())
    );
    d.confirm_physical(context, &c).unwrap();
    success(d.handle(context, &c));
    assert!(d.snapshot().owner.is_none());
    assert!(d.snapshot().events.is_empty());
    assert_eq!(d.snapshot().epoch, 1);
    assert_eq!(
        d.handle(context, &request(old.clone(), 0, Action::Status))
            .result,
        Err(Error::InvalidState.code())
    );
    claim(&mut d);
    assert_eq!(
        d.handle(d.context(peer()), &request(old, 0, Action::Status))
            .result,
        Err(Error::StaleEpoch.code())
    );
}
#[test]
fn authorization_tampering_time_limits_revocation_and_log_gaps() {
    let mut d = ready();
    let c = request(grant(3, RIGHTS_STATUS, None, 0), 1, Action::Unlock);
    assert_eq!(
        d.handle(d.context(peer()), &c).result,
        Err(Error::MissingRight.code())
    );
    let mut c = request(grant(3, RIGHTS_UNLOCK, None, 0), 1, Action::Unlock);
    c.credential[40] ^= 1;
    assert!(d.handle(d.context(peer()), &c).result.is_err());
    assert!(d.platform().actions.is_empty());
    let signed = sign_grant(
        &SigningKey::from_bytes(&[9; 32]),
        &Grant {
            credential_id: CredentialId([5; 16]),
            lock_id: LockId([1; 16]),
            subject_key: peer(),
            rights: RIGHTS_STATUS,
            epoch: 0,
            validity: Some(Validity {
                not_before: 100,
                not_after: 200,
            }),
            max_uses: None,
        },
    )
    .unwrap();
    assert_eq!(
        d.handle(d.context(peer()), &request(signed, 0, Action::Status))
            .result,
        Err(Error::Expired.code())
    );
    for i in 1..50 {
        success(send(&mut d, i, Action::SetClock(1000 + i)));
    }
    match send(
        &mut d,
        0,
        Action::ReadLog {
            after: 0,
            limit: 16,
        },
    )
    .result
    {
        Ok(Reply::Audit(page)) => {
            assert!(page.gap);
            assert_eq!(page.events.len(), 16)
        }
        _ => panic!(),
    }
    assert_eq!(
        send(&mut d, 50, Action::SetClock(100)).result,
        Err(Error::ClockRollback.code())
    );
}
#[test]
fn firmware_transfer_resume_verify_trial_and_confirm() {
    let mut d = ready();
    let bytes = b"signed-image";
    let signed = signed_image(bytes, 1);
    success(send(&mut d, 1, Action::FirmwareBegin(signed.clone())));
    success(send(
        &mut d,
        2,
        Action::FirmwareChunk {
            offset: 0,
            data: bytes[..5].to_vec(),
        },
    ));
    let (s, h) = d.into_parts();
    let mut d = DeviceController::open(factory(), s, h).unwrap();
    assert_eq!(d.snapshot().firmware.received, 5);
    success(send(
        &mut d,
        3,
        Action::FirmwareChunk {
            offset: 0,
            data: bytes[..5].to_vec(),
        },
    ));
    assert_eq!(
        send(
            &mut d,
            4,
            Action::FirmwareChunk {
                offset: 0,
                data: b"wrong".to_vec()
            }
        )
        .result,
        Err(Error::FirmwareConflict.code())
    );
    success(send(
        &mut d,
        4,
        Action::FirmwareChunk {
            offset: 5,
            data: bytes[5..].to_vec(),
        },
    ));
    success(send(&mut d, 5, Action::FirmwareFinish));
    success(send(&mut d, 6, Action::FirmwareActivate));
    assert_eq!(d.snapshot().firmware.security_version, 0);
    d.platform_mut().boot = BootOutcome::Confirmed;
    d.poll().unwrap();
    assert_eq!(d.snapshot().firmware.security_version, 1);
    assert_eq!(d.info().firmware, "2.0");
    assert_eq!(
        send(&mut d, 7, Action::FirmwareBegin(signed)).result,
        Err(Error::FirmwareRollback.code())
    );
}
#[test]
fn firmware_rejects_bad_signature_hash_power_and_recovers_bad_boot() {
    let mut d = ready();
    let bytes = b"image";
    let mut signed = signed_image(bytes, 1);
    *signed.last_mut().unwrap() ^= 1;
    assert_eq!(
        send(&mut d, 1, Action::FirmwareBegin(signed)).result,
        Err(Error::BadSignature.code())
    );
    success(send(
        &mut d,
        1,
        Action::FirmwareBegin(signed_image(bytes, 1)),
    ));
    assert_eq!(
        send(&mut d, 2, Action::FirmwareFinish).result,
        Err(Error::FirmwareIncomplete.code())
    );
    success(send(
        &mut d,
        2,
        Action::FirmwareChunk {
            offset: 0,
            data: bytes.to_vec(),
        },
    ));
    success(send(&mut d, 3, Action::FirmwareFinish));
    d.platform_mut().power_ok = false;
    assert_eq!(
        send(&mut d, 4, Action::FirmwareActivate).result,
        Err(Error::PowerInsufficient.code())
    );
    d.platform_mut().power_ok = true;
    success(send(&mut d, 4, Action::FirmwareActivate));
    d.platform_mut().boot = BootOutcome::RolledBack;
    d.poll().unwrap();
    assert_eq!(d.snapshot().firmware.phase, FirmwarePhase::Failed);
    assert_eq!(d.snapshot().firmware.security_version, 0);
}
#[test]
fn existing_or_corrupt_storage_cannot_be_silently_initialized() {
    let d = ready();
    let (s, h) = d.into_parts();
    assert!(matches!(
        DeviceController::provision(factory(), s.clone(), h.clone()),
        Err(Error::AlreadyProvisioned)
    ));
    s.state.borrow_mut().as_mut().unwrap().next_cursor = 0;
    assert!(matches!(
        DeviceController::open(factory(), s, h),
        Err(Error::StorageUnavailable)
    ));
}

#[test]
fn every_constructor_stops_before_fallible_configuration_or_storage_access() {
    for constructor in 0..3 {
        for failure in 0..3 {
            let mut f = factory();
            let s = MemoryStore::default();
            let trace = s.trace.clone();
            let mut h = Hardware {
                trace: trace.clone(),
                ..Hardware::default()
            };
            let expected = match failure {
                0 => {
                    s.fail_load.set(true);
                    Error::StorageUnavailable
                }
                1 => {
                    f.info.model.clear();
                    Error::InvalidConfig
                }
                _ => {
                    h.fail_stop = true;
                    Error::ActuatorFailed
                }
            };
            let result = match constructor {
                0 => DeviceController::open(f, s, h),
                1 => DeviceController::provision(f, s, h),
                _ => DeviceController::migrate_legacy(
                    f,
                    s,
                    h,
                    &openlock_core::LockSnapshot {
                        epoch: 0,
                        policy_version: 0,
                        revoked: Default::default(),
                        usage: Default::default(),
                    },
                    SigningKey::from_bytes(&[9; 32]).verifying_key(),
                    peer(),
                ),
            };
            assert!(matches!(result, Err(error) if error == expected));
            assert_eq!(
                trace.borrow().as_slice(),
                if failure == 0 {
                    &["stop", "load"][..]
                } else {
                    &["stop"][..]
                }
            );
        }
    }
}

#[test]
fn startup_stops_before_loading_and_validating_any_recovery_snapshot() {
    for corrupt in [false, true] {
        let mut d = ready();
        success(send(&mut d, 1, Action::Unlock));
        let (s, mut h) = d.into_parts();
        let trace = s.trace.clone();
        h.trace = trace.clone();
        if corrupt {
            s.state.borrow_mut().as_mut().unwrap().next_cursor = 0;
        }
        trace.borrow_mut().clear();
        let result = DeviceController::open(factory(), s, h);
        if corrupt {
            assert!(matches!(result, Err(Error::StorageUnavailable)));
            assert_eq!(trace.borrow().as_slice(), &["stop", "load"]);
        } else {
            let d = result.unwrap();
            assert_eq!(d.platform().stop_count, 1);
            assert_eq!(trace.borrow().as_slice(), &["stop", "load", "commit"]);
            assert!(d.status().active.is_none());
        }
    }
}

#[test]
fn legacy_migration_preserves_epoch_revocations_and_consumed_uses() {
    let legacy = openlock_core::LockSnapshot {
        epoch: 7,
        policy_version: 9,
        revoked: [CredentialId([4; 16])].into_iter().collect(),
        usage: [(CredentialId([3; 16]), 2)].into_iter().collect(),
    };
    let mut d = DeviceController::migrate_legacy(
        factory(),
        MemoryStore::default(),
        Hardware::default(),
        &legacy,
        SigningKey::from_bytes(&[9; 32]).verifying_key(),
        peer(),
    )
    .unwrap();
    assert_eq!(d.snapshot().epoch, 7);
    assert_eq!(d.snapshot().policy_version, 9);
    let c = request(
        grant(3, RIGHTS_UNLOCK | RIGHTS_STATUS, Some(2), 7),
        1,
        Action::Unlock,
    );
    assert_eq!(
        d.handle(d.context(peer()), &c).result,
        Err(Error::UsageExhausted.code())
    );
    let c = request(grant(4, RIGHTS_STATUS, None, 7), 0, Action::Status);
    assert_eq!(
        d.handle(d.context(peer()), &c).result,
        Err(Error::Revoked.code())
    );
}
#[test]
fn expired_time_is_not_revived_by_clock_rollback_and_admin_can_repair() {
    let mut d = ready();
    d.platform_mut().unix = Some(2000);
    assert!(send(&mut d, 0, Action::Status).result.is_ok());
    d.platform_mut().unix = Some(1000);
    assert!(send(&mut d, 0, Action::Status).result.is_ok());
    assert!(!d.status().clock_trusted);
    let timed = sign_grant(
        &SigningKey::from_bytes(&[9; 32]),
        &Grant {
            credential_id: CredentialId([5; 16]),
            lock_id: LockId([1; 16]),
            subject_key: peer(),
            rights: RIGHTS_STATUS,
            epoch: 0,
            validity: Some(Validity {
                not_before: 100,
                not_after: 1500,
            }),
            max_uses: None,
        },
    )
    .unwrap();
    assert_eq!(
        d.handle(d.context(peer()), &request(timed, 0, Action::Status))
            .result,
        Err(Error::ClockUntrusted.code())
    );
    assert_eq!(
        send(&mut d, 1, Action::SetClock(1500)).result,
        Err(Error::ClockRollback.code())
    );
    success(send(&mut d, 1, Action::SetClock(2100)));
    assert!(d.status().clock_trusted);
}
#[test]
fn failed_start_stays_busy_until_hardware_is_stopped() {
    let mut d = ready();
    d.platform_mut().fail_start = true;
    let r = send(&mut d, 1, Action::Unlock);
    assert!(matches!(
        r.result,
        Ok(Reply::Operation(OperationStatus {
            phase: OperationPhase::Unknown,
            ..
        }))
    ));
    assert_eq!(
        send(&mut d, 2, Action::Unlock).result,
        Err(Error::Busy.code())
    );
    d.platform_mut().ms += 40_000;
    d.poll().unwrap();
    assert_eq!(d.platform().stop_count, 1);
}
#[test]
fn timeout_updates_the_active_operation_not_a_later_management_record() {
    let mut d = ready();
    success(send(&mut d, 1, Action::Unlock));
    success(send(&mut d, 2, Action::SetClock(2000)));
    d.platform_mut().ms += 40_000;
    d.poll().unwrap();
    let first = send(&mut d, 0, Action::Operation(1));
    assert!(matches!(
        first.result,
        Ok(Reply::Operation(OperationStatus { error: 36, .. }))
    ));
    assert_eq!(success(send(&mut d, 2, Action::SetClock(2000))).error, 0);
}
#[test]
fn administrator_root_replacement_requires_new_epoch_and_new_signature() {
    let mut d = ready();
    let old = d.context(peer());
    let new_key = SigningKey::from_bytes(&[11; 32]);
    let c = request(
        grant(2, KNOWN_RIGHTS, None, 0),
        1,
        Action::ReplaceIssuer(new_key.verifying_key().to_bytes()),
    );
    assert_eq!(
        d.handle(old, &c).result,
        Err(Error::PhysicalConfirmationRequired.code())
    );
    d.confirm_physical(old, &c).unwrap();
    success(d.handle(old, &c));
    assert_eq!(d.snapshot().epoch, 1);
    assert_eq!(
        d.handle(
            old,
            &request(grant(2, KNOWN_RIGHTS, None, 0), 0, Action::Status)
        )
        .result,
        Err(Error::InvalidState.code())
    );
    let new_grant = sign_grant(
        &new_key,
        &Grant {
            credential_id: CredentialId([2; 16]),
            lock_id: LockId([1; 16]),
            subject_key: peer(),
            rights: KNOWN_RIGHTS,
            epoch: 1,
            validity: None,
            max_uses: None,
        },
    )
    .unwrap();
    assert!(d
        .handle(d.context(peer()), &request(new_grant, 0, Action::Status))
        .result
        .is_ok());
}
#[test]
fn firmware_wrong_target_hash_and_uncommitted_chunk_are_recoverable() {
    let mut d = ready();
    let mut manifest = FirmwareManifest {
        model: "wrong-model".into(),
        hardware: "rev-a".into(),
        version: "2.0".into(),
        size: 3,
        sha256: openlock_crypto::sha256(b"abc"),
        security_version: 1,
    };
    let signed =
        openlock_crypto::firmware::sign_manifest(&SigningKey::from_bytes(&[8; 32]), &manifest)
            .unwrap();
    assert_eq!(
        send(&mut d, 1, Action::FirmwareBegin(signed)).result,
        Err(Error::FirmwareTargetMismatch.code())
    );
    manifest.model = "reference-lock".into();
    success(send(
        &mut d,
        1,
        Action::FirmwareBegin(signed_image(b"abc", 1)),
    ));
    let (s, h) = d.into_parts();
    let access = s.clone();
    let mut d = DeviceController::open(factory(), s, h).unwrap();
    // Reserve succeeds, flash write succeeds, acknowledgment snapshot fails.
    access.fail_at.set(Some(access.commits.get() + 2));
    assert_eq!(
        send(
            &mut d,
            2,
            Action::FirmwareChunk {
                offset: 0,
                data: b"abc".to_vec()
            }
        )
        .result,
        Err(Error::StorageUnavailable.code())
    );
    access.fail_at.set(None);
    let (s, h) = d.into_parts();
    let mut d = DeviceController::open(factory(), s, h).unwrap();
    assert_eq!(d.snapshot().firmware.received, 0);
    success(send(
        &mut d,
        3,
        Action::FirmwareChunk {
            offset: 0,
            data: b"bad".to_vec(),
        },
    ));
    assert!(matches!(
        send(&mut d, 4, Action::FirmwareFinish).result,
        Ok(Reply::Operation(OperationStatus { error: 47, .. }))
    ));
    success(send(&mut d, 5, Action::FirmwareAbort));
    assert_eq!(d.snapshot().firmware.phase, FirmwarePhase::Empty);
}
#[test]
fn configuration_constraints_and_local_hardware_changes() {
    let mut d = ready();
    let mut config = d.snapshot().config.clone();
    config.version = 1;
    config.release_ms = 0;
    assert_eq!(
        send(&mut d, 1, Action::SetConfig(config)).result,
        Err(Error::InvalidConfig.code())
    );
    d.platform_mut().sample.bolt = Reading::Known(BoltState::Unlocked);
    d.hardware_changed().unwrap();
    assert_eq!(d.status().bolt, Reading::Known(BoltState::Unlocked));
    let mut config = d.snapshot().config.clone();
    config.version = 1;
    config.auto_relock = AutoRelock::Delay(500);
    success(send(&mut d, 1, Action::SetConfig(config)));
    assert!(d.snapshot().pending_relock);
    d.platform_mut().sample.door = Reading::Unknown;
    d.platform_mut().ms += 1000;
    d.poll().unwrap();
    assert!(d.platform().actions.is_empty());
    d.platform_mut().sample.door = Reading::Known(DoorState::Closed);
    d.poll().unwrap();
    assert_eq!(d.platform().actions, [ActionTarget::Lock]);
    assert!(d.status().active.is_some());
}

#[test]
fn signed_device_rotation_preserves_grants_but_invalidates_old_sessions() {
    let mut d = ready();
    let issuer = SigningKey::from_bytes(&[9; 32]);
    let old_context = d.context(peer());
    let mut key = d.snapshot().device_key.clone();
    key.key_id = 2;
    key.key_version = 2;
    key.x25519_public_key = openlock_crypto::static_public(&[12; 32]);
    let record = openlock_crypto::sign_device_key(&issuer, &key, 1).unwrap();
    let update = openlock_crypto::sign_key_update(
        &issuer,
        KeyUpdate {
            old_key_id: 1,
            new_record: record,
            not_before: 900,
            retire_after: 1100,
            issuer_key_id: Some(1),
            signature: vec![],
        },
    )
    .unwrap();
    let bytes = openlock_crypto::encode_key_update(&update).unwrap();
    success(send(&mut d, 1, Action::RotateDeviceKey(bytes.clone())));
    assert_eq!(d.snapshot().device_key, key);
    assert_eq!(d.snapshot().epoch, 0);
    assert_eq!(
        d.handle(
            old_context,
            &request(grant(2, KNOWN_RIGHTS, None, 0), 0, Action::Status)
        )
        .result,
        Err(Error::InvalidState.code())
    );
    assert!(send(&mut d, 0, Action::Status).result.is_ok());
    assert!(matches!(
        send(&mut d, 2, Action::RotateDeviceKey(bytes)).result,
        Ok(Reply::Operation(OperationStatus { error: 20, .. }))
    ));
}

#[test]
fn invalid_sensor_sample_stops_motor_instead_of_starving_the_timeout() {
    let mut d = ready();
    success(send(&mut d, 1, Action::Unlock));
    d.platform_mut().sample.battery_percent = Reading::Known(101);
    assert_eq!(d.poll(), Err(Error::SensorConflict));
    assert_eq!(d.platform().stop_count, 1);
    assert!(d.status().active.is_none());
    assert_eq!(d.status().bolt, Reading::Unknown);
    assert!(matches!(
        send(&mut d, 0, Action::Operation(1)).result,
        Ok(Reply::Operation(OperationStatus {
            error: 37,
            phase: OperationPhase::Failed,
            ..
        }))
    ));
}
#[test]
fn interrupted_automatic_lock_is_stopped_and_never_replayed() {
    let mut d = ready();
    let mut config = d.snapshot().config.clone();
    config.version = 1;
    config.auto_relock = AutoRelock::Delay(500);
    success(send(&mut d, 1, Action::SetConfig(config)));
    success(send(&mut d, 2, Action::Unlock));
    complete(&mut d, BoltState::Unlocked);
    d.platform_mut().ms += 500;
    d.poll().unwrap();
    assert!(d.snapshot().automatic_inflight);
    assert_eq!(d.platform().actions.len(), 2);
    let (s, h) = d.into_parts();
    let mut d = DeviceController::open(factory(), s, h).unwrap();
    assert_eq!(d.platform().stop_count, 1);
    assert!(!d.snapshot().automatic_inflight);
    d.poll().unwrap();
    assert_eq!(d.platform().actions.len(), 2);
}

#[test]
fn lost_completion_commits_never_restore_uses_or_repeat_drive() {
    for after_write in [false, true] {
        for delta in 1..=3 {
            let d = ready();
            let (s, h) = d.into_parts();
            let access = s.clone();
            let mut d = DeviceController::open(factory(), s, h).unwrap();
            let c = request(
                grant(3, RIGHTS_UNLOCK | RIGHTS_STATUS, Some(1), 0),
                1,
                Action::Unlock,
            );
            success(d.handle(d.context(peer()), &c));
            access.fail_at.set(Some(access.commits.get() + delta));
            access.after_write.set(after_write);
            d.platform_mut().sample.bolt = Reading::Known(BoltState::Unlocked);
            assert_eq!(
                d.actuator_finished(d.platform().action_id.unwrap(), ActuatorResult::Completed),
                Err(Error::StorageUnavailable)
            );
            access.fail_at.set(None);
            let (s, h) = d.into_parts();
            let mut d = DeviceController::open(factory(), s, h).unwrap();
            let r = d.handle(d.context(peer()), &c);
            assert!(matches!(
                r.result,
                Ok(Reply::Operation(OperationStatus {
                    phase: OperationPhase::Unknown | OperationPhase::Completed,
                    ..
                }))
            ));
            assert_eq!(d.platform().actions.len(), 1);
            assert_eq!(d.snapshot().uses[&CredentialId([3; 16])], 1);
        }
    }
}
#[test]
fn revoked_grant_cannot_open_and_epoch_change_cannot_orphan_an_active_action() {
    let mut d = ready();
    let issuer = SigningKey::from_bytes(&[9; 32]);
    let policy = |epoch, version| {
        openlock_crypto::sign_policy(
            &issuer,
            &PolicyUpdate {
                lock_id: LockId([1; 16]),
                epoch,
                version,
                revoked: [CredentialId([3; 16])].into_iter().collect(),
            },
        )
        .unwrap()
    };
    success(send(&mut d, 1, Action::ApplyPolicy(policy(0, 1))));
    let c = request(grant(3, RIGHTS_UNLOCK, None, 0), 1, Action::Unlock);
    assert_eq!(
        d.handle(d.context(peer()), &c).result,
        Err(Error::Revoked.code())
    );
    assert_eq!(
        send(&mut d, 2, Action::ApplyPolicy(policy(0, 1))).result,
        Err(Error::StalePolicy.code())
    );
    success(send(&mut d, 2, Action::Unlock));
    assert_eq!(
        send(&mut d, 3, Action::ApplyPolicy(policy(1, 1))).result,
        Err(Error::Busy.code())
    );
    complete(&mut d, BoltState::Unlocked);
    success(send(&mut d, 3, Action::ApplyPolicy(policy(1, 1))));
    assert_eq!(d.snapshot().epoch, 1);
}
#[test]
fn ble_then_nfc_reconnect_has_one_shared_consumption_record() {
    use openlock_protocol::{Session, SessionEvent};
    use openlock_transport::FrameCodec;
    fn frame<C: FrameCodec>(codec: &mut C, bytes: &[u8]) -> Vec<u8>
    where
        C::Error: core::fmt::Debug,
    {
        let frames = codec.encode(bytes).unwrap();
        codec.reset();
        let mut out = None;
        for f in frames {
            if let Some(message) = codec.push(&f).unwrap() {
                out = Some(message);
            }
        }
        out.unwrap()
    }
    fn exchange<C: FrameCodec>(d: &mut Device, codec: &mut C, c: Command) -> Response
    where
        C::Error: core::fmt::Debug,
    {
        let mut client = Session::initiator(
            &[3; 32],
            &openlock_crypto::static_public(&[4; 32]),
            KNOWN_CAPABILITIES,
        )
        .unwrap();
        let mut lock = Session::responder(&[4; 32], KNOWN_CAPABILITIES).unwrap();
        let input = frame(codec, &client.start().unwrap());
        let (events, reply) = lock.receive(&input).unwrap();
        let authenticated = match events[0] {
            SessionEvent::HandshakeComplete { peer } => d.context(peer),
            _ => panic!(),
        };
        client.receive(&frame(codec, &reply.unwrap())).unwrap();
        let (_, packet) = client.send(c).unwrap();
        let (events, _) = lock.receive(&frame(codec, &packet)).unwrap();
        let SessionEvent::Request {
            request_id,
            command,
            ..
        } = events.into_iter().next().unwrap()
        else {
            panic!()
        };
        let result = d.handle(authenticated, &command);
        let packet = lock.respond(request_id, result).unwrap();
        let (events, _) = client.receive(&frame(codec, &packet)).unwrap();
        let SessionEvent::Response { response, .. } = events.into_iter().next().unwrap() else {
            panic!()
        };
        response
    }
    let mut d = ready();
    let c = request(
        grant(3, RIGHTS_UNLOCK | RIGHTS_STATUS, Some(1), 0),
        1,
        Action::Unlock,
    );
    let first = exchange(
        &mut d,
        &mut openlock_transport_ble::BleCodec::default(),
        c.clone(),
    );
    assert_eq!(success(first).phase, OperationPhase::Running);
    complete(&mut d, BoltState::Unlocked);
    let (s, h) = d.into_parts();
    let mut d = DeviceController::open(factory(), s, h).unwrap();
    let replay = exchange(
        &mut d,
        &mut openlock_transport_nfc::IsoDepCodec::default(),
        c,
    );
    assert_eq!(success(replay).phase, OperationPhase::Completed);
    assert_eq!(d.platform().actions.len(), 1);
}

#[test]
fn poisoned_storage_stops_an_active_drive_before_returning() {
    for after_write in [false, true] {
        let mut d = ready();
        d.platform_mut().sample.bolt = Reading::Known(BoltState::Unlocked);
        d.hardware_changed().unwrap();
        let (s, h) = d.into_parts();
        let access = s.clone();
        let mut d = DeviceController::open(factory(), s, h).unwrap();
        success(send(&mut d, 1, Action::Lock));
        let stops_before_fault = d.platform().stop_count;
        access.fail_at.set(Some(access.commits.get() + 1));
        access.after_write.set(after_write);
        d.platform_mut().sample.door = Reading::Known(DoorState::Open);
        assert_eq!(d.poll(), Err(Error::StorageUnavailable));
        assert_eq!(d.platform().stop_count, stops_before_fault + 1);
        assert_eq!(
            send(&mut d, 2, Action::Unlock).result,
            Err(Error::StorageUnavailable.code())
        );
        assert_eq!(d.platform().actions, [ActionTarget::Lock]);
    }
}

#[test]
fn interrupted_unlock_keeps_relock_obligation_without_replaying_unlock() {
    for mode in [AutoRelock::Delay(500), AutoRelock::AfterClose(500)] {
        let mut d = ready();
        let mut config = d.snapshot().config.clone();
        config.version = 1;
        config.auto_relock = mode;
        success(send(&mut d, 1, Action::SetConfig(config)));
        success(send(&mut d, 2, Action::Unlock));
        assert!(d.snapshot().pending_relock);
        // A motor can start before its locked limit switch is released.
        d.platform_mut().sample.bolt = Reading::Known(BoltState::Locked);
        d.poll().unwrap();
        assert!(d.snapshot().pending_relock);
        d.platform_mut().sample.bolt = Reading::Known(BoltState::Unlocked);
        let (s, h) = d.into_parts();
        let mut d = DeviceController::open(factory(), s, h).unwrap();
        assert_eq!(d.platform().stop_count, 1);
        d.poll().unwrap();
        assert_eq!(
            d.platform().actions,
            [ActionTarget::Unlock, ActionTarget::Lock]
        );
        assert_eq!(d.snapshot().uses[&CredentialId([2; 16])], 1);
    }
}

#[test]
fn boot_with_locked_bolt_clears_pending_relock_without_driving() {
    let mut d = ready();
    let mut config = d.snapshot().config.clone();
    config.version = 1;
    config.auto_relock = AutoRelock::Delay(500);
    success(send(&mut d, 1, Action::SetConfig(config)));
    success(send(&mut d, 2, Action::Unlock));
    complete(&mut d, BoltState::Unlocked);
    let (s, mut h) = d.into_parts();
    h.sample.bolt = Reading::Known(BoltState::Locked);
    let mut d = DeviceController::open(factory(), s, h).unwrap();
    d.platform_mut().ms += 100_000;
    d.poll().unwrap();
    assert!(!d.snapshot().pending_relock);
    assert_eq!(d.platform().actions, [ActionTarget::Unlock]);
}

#[test]
fn background_clock_observations_prevent_reviving_expired_grants() {
    for hardware_event in [false, true] {
        let mut d = ready();
        d.platform_mut().unix = Some(2000);
        if hardware_event {
            d.platform_mut().sample.door = Reading::Known(DoorState::Open);
            d.hardware_changed().unwrap();
        } else {
            d.poll().unwrap();
        }
        assert_eq!(d.snapshot().clock_floor, Some(2000));
        let (s, mut h) = d.into_parts();
        h.unix = Some(1500);
        let mut d = DeviceController::open(factory(), s, h).unwrap();
        let timed = sign_grant(
            &SigningKey::from_bytes(&[9; 32]),
            &Grant {
                credential_id: CredentialId([5; 16]),
                lock_id: LockId([1; 16]),
                subject_key: peer(),
                rights: RIGHTS_UNLOCK,
                epoch: 0,
                validity: Some(Validity {
                    not_before: 1400,
                    not_after: 1600,
                }),
                max_uses: None,
            },
        )
        .unwrap();
        let c = request(timed, 1, Action::Unlock);
        assert_eq!(
            d.handle(d.context(peer()), &c).result,
            Err(Error::ClockUntrusted.code())
        );
        assert!(d.platform().actions.is_empty());
    }
}

#[test]
fn old_boot_confirmation_cannot_confirm_an_unactivated_candidate() {
    let mut d = ready();
    success(send(
        &mut d,
        1,
        Action::FirmwareBegin(signed_image(b"old", 1)),
    ));
    success(send(
        &mut d,
        2,
        Action::FirmwareChunk {
            offset: 0,
            data: b"old".to_vec(),
        },
    ));
    success(send(&mut d, 3, Action::FirmwareFinish));
    success(send(&mut d, 4, Action::FirmwareActivate));
    d.platform_mut().boot = BootOutcome::Confirmed;
    d.poll().unwrap();
    success(send(
        &mut d,
        5,
        Action::FirmwareBegin(signed_image(b"new", 2)),
    ));
    success(send(
        &mut d,
        6,
        Action::FirmwareChunk {
            offset: 0,
            data: b"new".to_vec(),
        },
    ));
    success(send(&mut d, 7, Action::FirmwareFinish));
    let (s, h) = d.into_parts();
    let access = s.clone();
    let mut d = DeviceController::open(factory(), s, h).unwrap();
    access.fail_at.set(Some(access.commits.get() + 2));
    access.after_write.set(true);
    assert_eq!(
        send(&mut d, 8, Action::FirmwareActivate).result,
        Err(Error::StorageUnavailable.code())
    );
    access.fail_at.set(None);
    let (s, h) = d.into_parts();
    let d = DeviceController::open(factory(), s, h).unwrap();
    assert_eq!(d.platform().activation_count, 1);
    assert_eq!(d.snapshot().firmware.phase, FirmwarePhase::Failed);
    assert_eq!(d.snapshot().firmware.security_version, 1);
}

#[test]
fn epoch_change_allows_reissued_credential_to_start_at_sequence_one() {
    let mut d = ready();
    let policy = openlock_crypto::sign_policy(
        &SigningKey::from_bytes(&[9; 32]),
        &PolicyUpdate {
            lock_id: LockId([1; 16]),
            epoch: 1,
            version: 1,
            revoked: Default::default(),
        },
    )
    .unwrap();
    let result = success(send(&mut d, 100, Action::ApplyPolicy(policy)));
    assert_eq!(result.phase, OperationPhase::Completed);
    assert!(d.snapshot().watermarks.is_empty());
    assert!(d.snapshot().operations.is_empty());
    success(send(&mut d, 1, Action::Unlock));
    assert_eq!(d.platform().actions, [ActionTarget::Unlock]);
}

#[test]
fn poisoned_controller_retries_a_failed_stop_without_new_drive() {
    let mut d = ready();
    success(send(&mut d, 1, Action::Unlock));
    d.platform_mut().fail_stop = true;
    d.platform_mut().sample.battery_percent = Reading::Known(101);
    assert_eq!(d.poll(), Err(Error::ActuatorFailed));
    assert!(d.status().active.is_some());
    d.platform_mut().fail_stop = false;
    assert_eq!(d.poll(), Err(Error::StorageUnavailable));
    assert!(d.status().active.is_none());
    assert_eq!(d.platform().stop_count, 2);
    assert_eq!(d.platform().actions, [ActionTarget::Unlock]);
}

#[test]
fn sensor_recovery_after_interrupted_relock_does_not_retry_the_motor() {
    for reboot in [false, true] {
        for mode in [AutoRelock::Delay(500), AutoRelock::AfterClose(500)] {
            let mut d = ready();
            let mut config = d.snapshot().config.clone();
            config.version = 1;
            config.auto_relock = mode;
            success(send(&mut d, 1, Action::SetConfig(config)));
            success(send(&mut d, 2, Action::Unlock));
            complete(&mut d, BoltState::Unlocked);
            d.platform_mut().ms += 500;
            d.poll().unwrap();
            assert_eq!(
                d.platform().actions,
                [ActionTarget::Unlock, ActionTarget::Lock]
            );
            if reboot {
                let (s, h) = d.into_parts();
                d = DeviceController::open(factory(), s, h).unwrap();
            } else {
                d.platform_mut().sample.door = Reading::Known(DoorState::Open);
                d.poll().unwrap();
                d.platform_mut().sample.door = Reading::Known(DoorState::Closed);
            }
            d.platform_mut().sample.bolt = Reading::Known(BoltState::Unlocked);
            d.poll().unwrap();
            d.platform_mut().ms += 10_000;
            d.poll().unwrap();
            assert!(!d.snapshot().pending_relock);
            assert_eq!(
                d.platform().actions,
                [ActionTarget::Unlock, ActionTarget::Lock]
            );
            // A subsequent genuine local locked -> unknown -> unlocked cycle
            // must still arm relock, even with an intermediate unavailable reading.
            d.platform_mut().sample.bolt = Reading::Known(BoltState::Locked);
            d.hardware_changed().unwrap();
            d.platform_mut().sample.bolt = Reading::Unknown;
            d.hardware_changed().unwrap();
            d.platform_mut().sample.bolt = Reading::Known(BoltState::Unlocked);
            d.hardware_changed().unwrap();
            d.platform_mut().ms += 500;
            d.poll().unwrap();
            assert_eq!(d.platform().actions.len(), 3);
        }
    }
}

#[test]
fn door_ajar_reminder_rearms_after_each_confirmed_close() {
    let mut d = ready();
    let mut config = d.snapshot().config.clone();
    config.version = 1;
    config.door_ajar_ms = 500;
    success(send(&mut d, 1, Action::SetConfig(config)));
    for cycle in 1..=2 {
        d.platform_mut().sample.door = Reading::Known(DoorState::Open);
        d.poll().unwrap();
        d.platform_mut().ms += 500;
        d.poll().unwrap();
        assert_eq!(d.status().fault, Fault::DoorAjar);
        d.poll().unwrap();
        assert_eq!(
            d.snapshot()
                .events
                .iter()
                .filter(|e| e.kind == AuditKind::Hardware && e.code == Error::DoorOpen.code())
                .count(),
            cycle
        );
        d.platform_mut().sample.door = Reading::Known(DoorState::Closed);
        d.poll().unwrap();
        assert_eq!(d.status().fault, Fault::None);
    }
}

#[test]
fn interrupted_manual_lock_claims_and_does_not_replay_pending_relock() {
    for bolt in [Reading::Unknown, Reading::Known(BoltState::Unlocked)] {
        for mode in [AutoRelock::Delay(500), AutoRelock::AfterClose(500)] {
            let mut d = ready();
            let mut config = d.snapshot().config.clone();
            config.version = 1;
            config.auto_relock = mode;
            success(send(&mut d, 1, Action::SetConfig(config)));
            success(send(&mut d, 2, Action::Unlock));
            complete(&mut d, BoltState::Unlocked);
            assert!(d.snapshot().pending_relock);
            success(send(&mut d, 3, Action::Lock));
            assert!(!d.snapshot().pending_relock);
            let (s, mut h) = d.into_parts();
            h.sample.bolt = bolt;
            let mut d = DeviceController::open(factory(), s, h).unwrap();
            d.poll().unwrap();
            d.platform_mut().sample.bolt = Reading::Known(BoltState::Unlocked);
            d.platform_mut().ms += 10_000;
            d.poll().unwrap();
            assert_eq!(
                d.platform().actions,
                [ActionTarget::Unlock, ActionTarget::Lock]
            );
            assert!(!d.snapshot().pending_relock);
        }
    }
}

#[test]
fn local_unlock_immediately_after_lock_completion_arms_relock() {
    for automatic in [false, true] {
        let mut d = ready();
        let mut config = d.snapshot().config.clone();
        config.version = 1;
        config.auto_relock = AutoRelock::Delay(500);
        success(send(&mut d, 1, Action::SetConfig(config)));
        success(send(&mut d, 2, Action::Unlock));
        complete(&mut d, BoltState::Unlocked);
        if automatic {
            d.platform_mut().ms += 500;
            d.poll().unwrap();
        } else {
            success(send(&mut d, 3, Action::Lock));
        }
        complete(&mut d, BoltState::Locked);
        // The mechanical unlock arrives before any idle poll can cache Locked.
        d.platform_mut().sample.bolt = Reading::Known(BoltState::Unlocked);
        d.hardware_changed().unwrap();
        assert!(d.snapshot().pending_relock);
        d.platform_mut().ms += 500;
        d.poll().unwrap();
        assert_eq!(
            d.platform().actions,
            [ActionTarget::Unlock, ActionTarget::Lock, ActionTarget::Lock]
        );
    }
}

#[test]
fn interlocks_and_timeouts_stop_before_any_background_storage_commit() {
    for trigger in 0..4 {
        let mut d = ready();
        d.platform_mut().sample.bolt = Reading::Known(BoltState::Unlocked);
        d.hardware_changed().unwrap();
        let (s, mut h) = d.into_parts();
        h.trace = s.trace.clone();
        let trace = s.trace.clone();
        let mut d = DeviceController::open(factory(), s, h).unwrap();
        success(send(&mut d, 1, Action::Lock));
        trace.borrow_mut().clear();
        // Advancing the RTC forces background watermark persistence too.
        d.platform_mut().unix = Some(2000);
        match trigger {
            0 => d.platform_mut().sample.door = Reading::Known(DoorState::Open),
            1 => d.platform_mut().sample.door = Reading::Unknown,
            2 => d.platform_mut().sample.battery_percent = Reading::Known(101),
            _ => d.platform_mut().ms += 100_000,
        }
        let result = d.poll();
        if trigger == 2 {
            assert_eq!(result, Err(Error::SensorConflict));
        } else {
            result.unwrap();
        }
        let events = trace.borrow();
        assert_eq!(events.first(), Some(&"stop"), "{events:?}");
        assert!(events.contains(&"commit"));
        assert!(d.status().active.is_none());
    }
}

#[test]
fn all_request_paths_service_interlocks_before_persistence() {
    for kind in 0..3 {
        let mut d = ready();
        d.platform_mut().sample.bolt = Reading::Known(BoltState::Unlocked);
        d.hardware_changed().unwrap();
        let (s, mut h) = d.into_parts();
        h.trace = s.trace.clone();
        let trace = s.trace.clone();
        let mut d = DeviceController::open(factory(), s, h).unwrap();
        success(send(&mut d, 1, Action::Lock));
        let stops_before_fault = d.platform().stop_count;
        trace.borrow_mut().clear();
        d.platform_mut().unix = Some(2000);
        d.platform_mut().sample.door = Reading::Known(DoorState::Open);
        match kind {
            0 => {
                success(send(&mut d, 2, Action::SetClock(2000)));
            }
            1 => {
                assert!(send(&mut d, 0, Action::Status).result.is_ok());
            }
            _ => {
                let c = request(Vec::new(), 0, Action::Status);
                assert!(d.handle(d.context(peer()), &c).result.is_err());
            }
        }
        assert_eq!(trace.borrow().first(), Some(&"stop"));
        assert_eq!(d.platform().stop_count, stops_before_fault + 1);
        assert!(d.status().active.is_none());
    }
}

#[test]
fn simultaneous_timeout_and_interlock_complete_the_action_once() {
    for callback in [false, true] {
        for door in [Reading::Known(DoorState::Open), Reading::Unknown] {
            let mut d = ready();
            d.platform_mut().sample.bolt = Reading::Known(BoltState::Unlocked);
            d.hardware_changed().unwrap();
            success(send(&mut d, 1, Action::Lock));
            d.platform_mut().ms += 100_000;
            d.platform_mut().sample.door = door;
            if callback {
                d.actuator_finished(d.platform().action_id.unwrap(), ActuatorResult::Completed)
                    .unwrap();
            } else {
                d.poll().unwrap();
            }
            assert_eq!(d.platform().stop_count, 1);
            assert!(d.status().active.is_none());
            let op = d.snapshot().operations.last().unwrap();
            assert_eq!(op.status.phase, OperationPhase::Failed);
            assert_eq!(
                op.status.error,
                if door == Reading::Unknown {
                    Error::SensorConflict.code()
                } else {
                    Error::DoorOpen.code()
                }
            );
            d.poll().unwrap();
            assert_eq!(d.platform().stop_count, 1);
        }
    }
}

#[test]
fn stale_completion_cannot_release_a_new_manual_or_automatic_drive() {
    for automatic in [false, true] {
        let mut d = ready();
        if automatic {
            let mut config = d.snapshot().config.clone();
            config.version = 1;
            config.auto_relock = AutoRelock::Delay(500);
            success(send(&mut d, 1, Action::SetConfig(config)));
        }
        success(send(&mut d, 2, Action::Unlock));
        let old_id = d.platform().action_id.unwrap();
        d.platform_mut().ms += 10_001;
        d.poll().unwrap();
        if !automatic {
            success(send(&mut d, 3, Action::Lock));
        }
        let new_id = d.platform().action_id.unwrap();
        assert_ne!(old_id, new_id);
        assert_eq!(
            d.actuator_finished(old_id, ActuatorResult::Completed),
            Err(Error::InvalidState)
        );
        assert!(d.status().active.is_some());
        d.platform_mut().ms += 10_001;
        d.poll().unwrap();
        assert_eq!(d.platform().stop_count, 2);
        assert!(d.status().active.is_none());
        assert_eq!(d.status().fault, Fault::Timeout);
    }
}

#[test]
fn drive_identity_is_not_reused_after_reboot_or_factory_reset() {
    let mut d = ready();
    success(send(&mut d, 1, Action::Unlock));
    let original = d.platform().action_id.unwrap();
    let (s, h) = d.into_parts();
    let mut d = DeviceController::open(factory(), s, h).unwrap();
    success(send(&mut d, 2, Action::Lock));
    let after_reboot = d.platform().action_id.unwrap();
    assert_ne!(original, after_reboot);
    assert_eq!(
        d.actuator_finished(original, ActuatorResult::Completed),
        Err(Error::InvalidState)
    );
    complete(&mut d, BoltState::Locked);
    let reset = request(grant(2, KNOWN_RIGHTS, None, 0), 3, Action::FactoryReset);
    d.confirm_physical(d.context(peer()), &reset).unwrap();
    success(d.handle(d.context(peer()), &reset));
    claim(&mut d);
    success(send(&mut d, 1, Action::Unlock));
    assert_ne!(original, d.platform().action_id.unwrap());
    assert_eq!(
        d.actuator_finished(original, ActuatorResult::Completed),
        Err(Error::InvalidState)
    );
    assert!(d.status().active.is_some());
}

#[test]
fn transient_sensor_fault_during_unlock_preserves_relock_across_recovery() {
    for reboot in [false, true] {
        for mode in [AutoRelock::Delay(500), AutoRelock::AfterClose(500)] {
            let mut d = ready();
            let mut config = d.snapshot().config.clone();
            config.version = 1;
            config.auto_relock = mode;
            success(send(&mut d, 1, Action::SetConfig(config)));
            success(send(&mut d, 2, Action::Unlock));
            d.platform_mut().sample.bolt = Reading::Known(BoltState::Unlocked);
            d.platform_mut().sample.battery_percent = Reading::Known(101);
            assert_eq!(d.poll(), Err(Error::SensorConflict));
            assert!(d.snapshot().pending_relock);
            d.platform_mut().sample.battery_percent = Reading::Known(80);
            if reboot {
                let (s, h) = d.into_parts();
                d = DeviceController::open(factory(), s, h).unwrap();
            }
            d.platform_mut().ms += 20_000;
            d.poll().unwrap();
            // AfterClose starts a fresh delay if fault sanitization obscured
            // the door reading; a subsequent poll must still perform relock.
            d.platform_mut().ms += 500;
            d.poll().unwrap();
            assert_eq!(
                d.platform().actions,
                [ActionTarget::Unlock, ActionTarget::Lock]
            );
        }
    }
}

fn epoch_policy(epoch: u64) -> Action {
    Action::ApplyPolicy(
        openlock_crypto::sign_policy(
            &SigningKey::from_bytes(&[9; 32]),
            &PolicyUpdate {
                lock_id: LockId([1; 16]),
                epoch,
                version: 1,
                revoked: Default::default(),
            },
        )
        .unwrap(),
    )
}
fn saturated_epoch() -> Device {
    let mut d = ready();
    success(send(&mut d, 1, epoch_policy(1)));
    d.platform_mut().sample.bolt = Reading::Known(BoltState::Unlocked);
    d.hardware_changed().unwrap();
    for id in 10..10 + d.info().credential_capacity as u8 {
        let c = request(
            grant(id, RIGHTS_UNLOCK | RIGHTS_STATUS, None, 1),
            1,
            Action::Unlock,
        );
        success(d.handle(d.context(peer()), &c));
    }
    assert_eq!(
        d.snapshot().bindings.len(),
        d.info().credential_capacity as usize
    );
    assert_eq!(
        d.snapshot().watermarks.len(),
        d.info().credential_capacity as usize
    );
    d
}

#[test]
fn full_credential_tables_leave_authorized_domain_recovery_available() {
    for reopen in [false, true] {
        for rescue in 0..3 {
            let mut d = saturated_epoch();
            if reopen {
                let (s, h) = d.into_parts();
                d = DeviceController::open(factory(), s, h).unwrap();
            }
            let action = match rescue {
                0 => epoch_policy(2),
                1 => Action::ReplaceIssuer(
                    SigningKey::from_bytes(&[10; 32]).verifying_key().to_bytes(),
                ),
                _ => Action::FactoryReset,
            };
            let c = request(grant(2, KNOWN_RIGHTS, None, 1), 1, action);
            if rescue != 0 {
                d.confirm_physical(d.context(peer()), &c).unwrap();
            }
            let context = d.context(peer());
            assert_eq!(
                success(d.handle(context, &c)).phase,
                OperationPhase::Completed
            );
            assert_eq!(d.snapshot().epoch, 2);
            assert!(d.snapshot().bindings.is_empty());
            assert!(d.snapshot().watermarks.is_empty());
            assert!(d.snapshot().operations.is_empty());
            assert!(d.handle(context, &c).result.is_err());
            if rescue == 2 {
                assert!(d.snapshot().owner.is_none());
            }
        }
    }
}

#[test]
fn full_capacity_epoch_recovery_remains_atomic_on_ambiguous_commit() {
    for after_write in [false, true] {
        let d = saturated_epoch();
        let (s, h) = d.into_parts();
        let access = s.clone();
        let mut d = DeviceController::open(factory(), s, h).unwrap();
        access.fail_at.set(Some(access.commits.get() + 1));
        access.after_write.set(after_write);
        assert_eq!(
            send(&mut d, 1, epoch_policy(2)).result,
            Err(Error::StorageUnavailable.code())
        );
        assert_eq!(
            send(&mut d, 1, epoch_policy(2)).result,
            Err(Error::StorageUnavailable.code())
        );
        access.fail_at.set(None);
        let (s, h) = d.into_parts();
        let mut d = DeviceController::open(factory(), s, h).unwrap();
        assert_eq!(d.snapshot().epoch, if after_write { 2 } else { 1 });
        if !after_write {
            success(send(&mut d, 1, epoch_policy(2)));
        }
        assert!(d.snapshot().bindings.is_empty());
        assert!(d.snapshot().watermarks.is_empty());
    }
}

#[test]
fn locking_rechecks_interlocks_changed_during_acceptance_without_retrying() {
    for automatic in [false, true] {
        for fault in 0..4 {
            let mut d = ready();
            if automatic {
                let mut config = d.snapshot().config.clone();
                config.version = 1;
                config.auto_relock = AutoRelock::Delay(500);
                success(send(&mut d, 1, Action::SetConfig(config)));
            }
            d.platform_mut().sample.bolt = Reading::Known(BoltState::Unlocked);
            d.hardware_changed().unwrap();
            let (s, h) = d.into_parts();
            let hook = s.commit_hook.clone();
            let mut d = DeviceController::open(factory(), s, h).unwrap();
            let sensor = d.platform().sample_override.clone();
            let mut changed = d.platform().sample;
            let error = match fault {
                0 => {
                    changed.door = Reading::Known(DoorState::Open);
                    Error::DoorOpen
                }
                1 => {
                    changed.door = Reading::Unknown;
                    Error::SensorConflict
                }
                2 => {
                    changed.door = Reading::Unsupported;
                    Error::SensorConflict
                }
                _ => {
                    changed.battery_percent = Reading::Known(101);
                    Error::SensorConflict
                }
            };
            *hook.borrow_mut() = Some(Box::new(move || sensor.set(Some(changed))));
            if automatic {
                assert_eq!(d.poll().map_err(|e| e.code()), Err(error.code()));
                let status = d
                    .snapshot()
                    .events
                    .last()
                    .unwrap()
                    .operation
                    .as_ref()
                    .unwrap();
                assert_eq!(status.phase, OperationPhase::Failed);
                assert_eq!(status.error, error.code());
            } else {
                let response = send(&mut d, 2, Action::Lock);
                let Ok(Reply::Operation(status)) = &response.result else {
                    panic!("{response:?}")
                };
                assert_eq!(status.phase, OperationPhase::Failed);
                assert_eq!(status.error, error.code());
                assert_eq!(d.snapshot().watermarks[&CredentialId([2; 16])], 2);
                d.platform().sample_override.set(None);
                assert_eq!(send(&mut d, 2, Action::Lock), response);
            }
            assert!(d.platform().actions.is_empty());
            assert!(d.status().active.is_none());
            assert!(!d.snapshot().automatic_inflight);
            assert!(!d.snapshot().pending_relock);
            d.platform().sample_override.set(None);
            d.platform_mut().ms += 100_000;
            d.poll().unwrap();
            let (s, h) = d.into_parts();
            let mut d = DeviceController::open(factory(), s, h).unwrap();
            d.poll().unwrap();
            assert!(d.platform().actions.is_empty());
        }
    }
}

#[test]
fn unlock_rechecks_privacy_after_acceptance_and_retains_consumption() {
    for privacy in [Reading::Known(true), Reading::Unknown, Reading::Unsupported] {
        let mut d = ready();
        let mut config = d.snapshot().config.clone();
        config.version = 1;
        config.auto_relock = AutoRelock::Delay(500);
        success(send(&mut d, 1, Action::SetConfig(config)));
        let (s, h) = d.into_parts();
        let hook = s.commit_hook.clone();
        let mut d = DeviceController::open(factory(), s, h).unwrap();
        let sensor = d.platform().sample_override.clone();
        let mut changed = d.platform().sample;
        changed.privacy = privacy;
        *hook.borrow_mut() = Some(Box::new(move || sensor.set(Some(changed))));
        let response = send(&mut d, 2, Action::Unlock);
        let Ok(Reply::Operation(status)) = &response.result else {
            panic!("{response:?}")
        };
        assert_eq!(status.phase, OperationPhase::Failed);
        assert_eq!(
            status.error,
            if privacy == Reading::Known(true) {
                Error::PrivacyActive
            } else {
                Error::SensorConflict
            }
            .code()
        );
        assert!(d.platform().actions.is_empty());
        assert!(d.status().active.is_none());
        assert_eq!(d.snapshot().uses[&CredentialId([2; 16])], 1);
        assert!(d.snapshot().pending_relock);
        // The transient privacy input returns to its original value, leaving
        // the exact cached Locked sample. That still cancels the reservation.
        d.platform().sample_override.set(None);
        d.platform_mut().ms += 1000;
        d.poll().unwrap();
        assert!(!d.snapshot().pending_relock);
        assert_eq!(send(&mut d, 2, Action::Unlock), response);
        let (s, h) = d.into_parts();
        let mut d = DeviceController::open(factory(), s, h).unwrap();
        d.poll().unwrap();
        assert_eq!(d.snapshot().uses[&CredentialId([2; 16])], 1);
        assert!(!d.snapshot().pending_relock);
        assert!(d.platform().actions.is_empty());
    }
}

#[test]
fn slow_acceptance_starts_the_actuator_timeout_at_the_actual_drive() {
    for automatic in [false, true] {
        let mut d = ready();
        if automatic {
            let mut config = d.snapshot().config.clone();
            config.version = 1;
            config.auto_relock = AutoRelock::Delay(500);
            success(send(&mut d, 1, Action::SetConfig(config)));
        }
        d.platform_mut().sample.bolt = Reading::Known(BoltState::Unlocked);
        d.hardware_changed().unwrap();
        let (s, h) = d.into_parts();
        let hook = s.commit_hook.clone();
        let mut d = DeviceController::open(factory(), s, h).unwrap();
        let clock = d.platform().monotonic_override.clone();
        *hook.borrow_mut() = Some(Box::new(move || clock.set(Some(100_000))));
        if automatic {
            d.poll().unwrap();
        } else {
            success(send(&mut d, 2, Action::Lock));
        }
        assert_eq!(d.platform().actions, [ActionTarget::Lock]);
        let deadline = 100_000 + d.snapshot().config.action_timeout_ms as u64;
        d.platform().monotonic_override.set(Some(deadline - 1));
        d.poll().unwrap();
        assert!(d.status().active.is_some());
        d.platform().monotonic_override.set(Some(deadline));
        d.poll().unwrap();
        assert!(d.status().active.is_none());
        assert_eq!(d.status().fault, Fault::Timeout);
    }
}

#[test]
fn clock_tick_during_acceptance_cannot_lower_the_floor_or_revive_a_grant() {
    for during_write in [false, true] {
        let (s, h) = ready().into_parts();
        let hook = s.commit_hook.clone();
        let mut d = DeviceController::open(factory(), s, h).unwrap();
        if during_write {
            let clock = d.platform().wall_override.clone();
            *hook.borrow_mut() = Some(Box::new(move || clock.set(Some(1001))));
        } else {
            // Tick after preflight, when acceptance records the trusted time.
            d.platform().wall_reads.set(0);
            d.platform().wall_tick_on_read.set(Some((4, 1001)));
        }
        let response = send(&mut d, 1, Action::SetClock(1000));
        let Ok(Reply::Operation(status)) = response.result else {
            panic!("{response:?}")
        };
        assert_eq!(status.phase, OperationPhase::Failed);
        assert_eq!(status.error, Error::ClockRollback.code());
        assert_eq!(d.snapshot().clock_floor, Some(1001));
        assert_eq!(d.platform().wall_clock().unwrap().lower, 1001);
        let timed = sign_grant(
            &SigningKey::from_bytes(&[9; 32]),
            &Grant {
                credential_id: CredentialId([5; 16]),
                lock_id: LockId([1; 16]),
                subject_key: peer(),
                rights: RIGHTS_UNLOCK,
                epoch: 0,
                validity: Some(Validity {
                    not_before: 900,
                    not_after: 1001,
                }),
                max_uses: None,
            },
        )
        .unwrap();
        let c = request(timed, 1, Action::Unlock);
        assert_eq!(
            d.handle(d.context(peer()), &c).result,
            Err(Error::Expired.code())
        );
        assert!(d.platform().actions.is_empty());
        let (s, h) = d.into_parts();
        let mut d = DeviceController::open(factory(), s, h).unwrap();
        assert_eq!(d.snapshot().clock_floor, Some(1001));
        assert_eq!(
            d.handle(d.context(peer()), &c).result,
            Err(Error::Expired.code())
        );
    }
}

#[test]
fn firmware_abort_never_recovers_erased_bytes_as_received_or_verified() {
    for verified in [false, true] {
        for boundary in 1..=3 {
            for after_write in [false, true] {
                let mut d = ready();
                success(send(
                    &mut d,
                    1,
                    Action::FirmwareBegin(signed_image(b"abc", 1)),
                ));
                success(send(
                    &mut d,
                    2,
                    Action::FirmwareChunk {
                        offset: 0,
                        data: b"abc".to_vec(),
                    },
                ));
                if verified {
                    success(send(&mut d, 3, Action::FirmwareFinish));
                }
                let image = d.platform().image.clone();
                let previous = d.snapshot().firmware.clone();
                let (s, h) = d.into_parts();
                let access = s.clone();
                let mut d = DeviceController::open(factory(), s, h).unwrap();
                access.fail_at.set(Some(access.commits.get() + boundary));
                access.after_write.set(after_write);
                assert_eq!(
                    send(&mut d, 4, Action::FirmwareAbort).result,
                    Err(Error::StorageUnavailable.code())
                );
                access.fail_at.set(None);
                let (s, h) = d.into_parts();
                let mut d = DeviceController::open(factory(), s, h).unwrap();
                if d.snapshot().firmware.phase == FirmwarePhase::Empty {
                    assert_eq!(d.snapshot().firmware.received, 0);
                    assert!(d.snapshot().firmware.manifest.is_none());
                    assert!(d.snapshot().signed_manifest.is_empty());
                    assert_eq!(
                        send(&mut d, 5, Action::FirmwareActivate).result,
                        Err(Error::FirmwareIncomplete.code())
                    );
                    success(send(
                        &mut d,
                        6,
                        Action::FirmwareBegin(signed_image(b"abc", 1)),
                    ));
                    assert_eq!(d.snapshot().firmware.received, 0);
                } else {
                    assert_eq!(d.snapshot().firmware, previous);
                    assert_eq!(d.platform().image, image);
                }
            }
        }
    }
}

#[test]
fn authorization_clock_observation_survives_rtc_recovery_and_reopen() {
    for reopen in [false, true] {
        for observed in [Some(1001), None, Some(999)] {
            let mut d = ready();
            let timed = sign_grant(
                &SigningKey::from_bytes(&[9; 32]),
                &Grant {
                    credential_id: CredentialId([5; 16]),
                    lock_id: LockId([1; 16]),
                    subject_key: peer(),
                    rights: RIGHTS_UNLOCK | RIGHTS_STATUS,
                    epoch: 0,
                    validity: Some(Validity {
                        not_before: 900,
                        not_after: 1001,
                    }),
                    max_uses: None,
                },
            )
            .unwrap();
            // Request servicing sees 1000, authorization sees the transient
            // expiration/failure, then audit sees the RTC restored to 1000.
            d.platform().wall_samples.borrow_mut().extend(
                [Some(1000), observed, Some(1000), Some(1000)].map(|value| {
                    value.map(|time| ClockSample {
                        lower: time,
                        upper: time,
                    })
                }),
            );
            let query = request(timed.clone(), 0, Action::Status);
            let error = if observed == Some(1001) {
                Error::Expired
            } else {
                Error::ClockUntrusted
            };
            assert_eq!(
                d.handle(d.context(peer()), &query).result,
                Err(error.code())
            );
            let floor = if observed == Some(1001) { 1001 } else { 1000 };
            assert_eq!(d.snapshot().clock_floor, Some(floor));
            d.platform().wall_samples.borrow_mut().clear();
            if reopen {
                let (s, h) = d.into_parts();
                d = DeviceController::open(factory(), s, h).unwrap();
            }
            let unlock = request(timed, 1, Action::Unlock);
            assert_eq!(
                d.handle(d.context(peer()), &unlock).result,
                Err(Error::ClockUntrusted.code())
            );
            assert_eq!(d.snapshot().clock_floor, Some(floor));
            assert!(d.platform().actions.is_empty());
        }
    }
}

#[test]
fn timed_status_remains_available_after_a_safely_handled_sensor_fault() {
    let mut d = ready();
    let timed = sign_grant(
        &SigningKey::from_bytes(&[9; 32]),
        &Grant {
            credential_id: CredentialId([5; 16]),
            lock_id: LockId([1; 16]),
            subject_key: peer(),
            rights: RIGHTS_UNLOCK | RIGHTS_STATUS,
            epoch: 0,
            validity: Some(Validity {
                not_before: 900,
                not_after: 2000,
            }),
            max_uses: None,
        },
    )
    .unwrap();
    d.platform_mut().sample.battery_percent = Reading::Known(101);
    let query = request(timed.clone(), 0, Action::Status);
    assert!(matches!(
        d.handle(d.context(peer()), &query).result,
        Ok(Reply::Status(_))
    ));
    let unlock = request(timed, 1, Action::Unlock);
    assert_eq!(
        d.handle(d.context(peer()), &unlock).result,
        Err(Error::SensorConflict.code())
    );
    assert!(d.platform().actions.is_empty());
}

#[test]
fn preflight_rejects_timed_mutations_when_its_clock_observation_invalidates_them() {
    for clock in [Some(1001), None, Some(999)] {
        for unlock in [false, true] {
            let mut d = ready();
            let timed = sign_grant(
                &SigningKey::from_bytes(&[9; 32]),
                &Grant {
                    credential_id: CredentialId([5; 16]),
                    lock_id: LockId([1; 16]),
                    subject_key: peer(),
                    rights: KNOWN_RIGHTS,
                    epoch: 0,
                    validity: Some(Validity {
                        not_before: 900,
                        not_after: 1001,
                    }),
                    max_uses: Some(1),
                },
            )
            .unwrap();
            d.platform()
                .wall_samples
                .borrow_mut()
                .extend([Some(1000), Some(1000), clock].map(|value| {
                    value.map(|time| ClockSample {
                        lower: time,
                        upper: time,
                    })
                }));
            let action = if unlock {
                Action::Unlock
            } else {
                let mut config = d.snapshot().config.clone();
                config.version = 1;
                Action::SetConfig(config)
            };
            let command = request(timed, 1, action);
            let error = if clock == Some(1001) {
                Error::Expired
            } else {
                Error::ClockUntrusted
            };
            assert_eq!(
                d.handle(d.context(peer()), &command).result,
                Err(error.code())
            );
            assert!(d.platform().actions.is_empty());
            assert!(!d.snapshot().watermarks.contains_key(&CredentialId([5; 16])));
            assert!(!d.snapshot().uses.contains_key(&CredentialId([5; 16])));
            assert_eq!(d.snapshot().config.version, 0);
        }
    }
}

#[test]
fn unrelated_config_preserves_relock_obligation_and_deadline_without_bolt_evidence() {
    for sensor in [false, true] {
        for reopen in [false, true] {
            let mut f = factory();
            f.info.bolt_sensor = sensor;
            let mut h = Hardware::default();
            h.sample.bolt = if sensor {
                Reading::Unknown
            } else {
                Reading::Unsupported
            };
            let mut d = DeviceController::provision(f.clone(), MemoryStore::default(), h).unwrap();
            claim(&mut d);
            let mut config = d.snapshot().config.clone();
            config.version = 1;
            config.auto_relock = AutoRelock::Delay(500);
            success(send(&mut d, 1, Action::SetConfig(config.clone())));
            success(send(&mut d, 2, Action::Unlock));
            d.actuator_finished(d.platform().action_id.unwrap(), ActuatorResult::Completed)
                .unwrap();
            assert!(d.snapshot().pending_relock);
            d.platform_mut().ms += 250;
            config.version = 2;
            config.door_ajar_ms = 1000;
            success(send(&mut d, 3, Action::SetConfig(config)));
            assert!(d.snapshot().pending_relock);
            if reopen {
                let (s, h) = d.into_parts();
                d = DeviceController::open(f, s, h).unwrap();
            } else {
                d.platform_mut().ms += 250;
            }
            d.poll().unwrap();
            assert_eq!(
                d.platform().actions,
                [ActionTarget::Unlock, ActionTarget::Lock]
            );
            assert!(!d.snapshot().pending_relock);
        }
    }
}

#[test]
fn manual_drive_skips_a_target_reached_during_acceptance_and_retains_reservation() {
    for target in [ActionTarget::Lock, ActionTarget::Unlock] {
        let mut d = ready();
        d.platform_mut().sample.bolt = Reading::Known(if target == ActionTarget::Lock {
            BoltState::Unlocked
        } else {
            BoltState::Locked
        });
        d.hardware_changed().unwrap();
        let (s, h) = d.into_parts();
        let hook = s.commit_hook.clone();
        let mut d = DeviceController::open(factory(), s, h).unwrap();
        let sensor = d.platform().sample_override.clone();
        let mut sample = d.platform().sample;
        sample.bolt = Reading::Known(if target == ActionTarget::Lock {
            BoltState::Locked
        } else {
            BoltState::Unlocked
        });
        *hook.borrow_mut() = Some(Box::new(move || sensor.set(Some(sample))));
        let action = if target == ActionTarget::Lock {
            Action::Lock
        } else {
            Action::Unlock
        };
        let result = success(send(&mut d, 1, action.clone()));
        assert_eq!(result.phase, OperationPhase::Completed);
        assert_eq!(result.evidence, CompletionEvidence::Sensor);
        assert!(d.platform().actions.is_empty());
        assert!(d.status().active.is_none());
        assert_eq!(d.status().bolt, sample.bolt);
        assert_eq!(
            d.snapshot()
                .uses
                .get(&CredentialId([2; 16]))
                .copied()
                .unwrap_or(0),
            if target == ActionTarget::Unlock { 1 } else { 0 }
        );
        assert_eq!(success(send(&mut d, 1, action)), result);
        assert!(d.platform().actions.is_empty());
    }
}

#[test]
fn automatic_drive_completes_without_driving_if_acceptance_observes_locked_target() {
    let mut d = ready();
    let mut config = d.snapshot().config.clone();
    config.version = 1;
    config.auto_relock = AutoRelock::Delay(500);
    success(send(&mut d, 1, Action::SetConfig(config)));
    d.platform_mut().sample.bolt = Reading::Known(BoltState::Unlocked);
    d.hardware_changed().unwrap();
    let (s, h) = d.into_parts();
    let hook = s.commit_hook.clone();
    let mut d = DeviceController::open(factory(), s, h).unwrap();
    let sensor = d.platform().sample_override.clone();
    let mut sample = d.platform().sample;
    sample.bolt = Reading::Known(BoltState::Locked);
    *hook.borrow_mut() = Some(Box::new(move || sensor.set(Some(sample))));
    d.poll().unwrap();
    assert!(!d.snapshot().pending_relock);
    assert!(!d.snapshot().automatic_inflight);
    assert!(d.status().active.is_none());
    assert!(d.platform().actions.is_empty());
    let result = d
        .snapshot()
        .events
        .last()
        .unwrap()
        .operation
        .as_ref()
        .unwrap();
    assert_eq!(result.phase, OperationPhase::Completed);
    assert_eq!(result.evidence, CompletionEvidence::Sensor);
    // A later genuine local unlock must still create a fresh obligation.
    sample.bolt = Reading::Known(BoltState::Unlocked);
    d.platform().sample_override.set(Some(sample));
    d.hardware_changed().unwrap();
    assert!(d.snapshot().pending_relock);
}
