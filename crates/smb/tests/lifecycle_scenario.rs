#![cfg(feature = "test-support")]

use bytes::Bytes;
use futures_util::poll;
use smb::test_support::{
    Clock, LifecycleScenario, ScenarioError, ScenarioEvent, ScenarioTaskError,
    ScriptedTransportControl, TerminalOutcome, TerminalProbe,
};
use smb::transport::{IoVec, SmbTransport};
use std::io::ErrorKind;
use std::task::Poll;
use std::time::Duration;

#[tokio::test]
async fn scenario_combines_scripted_transport_manual_time_and_owned_tasks() {
    let mut scenario = LifecycleScenario::new();
    let control: ScriptedTransportControl = scenario.transport_control();
    control.push_server_frame(Bytes::from_static(b"server"));
    let transport = scenario.take_transport().expect("transport is unique");
    let (mut read, mut write) = transport.split().expect("transport splits");

    scenario
        .spawn("exchange", move |_cancel| async move {
            let received = read.receive().await.map_err(ScenarioTaskError::from)?;
            if received.as_bytes() != &Bytes::from_static(b"server") {
                return Err(ScenarioTaskError::failed("unexpected-frame"));
            }
            write
                .send(&IoVec::from(b"client".to_vec()))
                .await
                .map_err(ScenarioTaskError::from)?;
            Ok(())
        })
        .expect("task name is unique");

    let deadline = scenario
        .clock()
        .now()
        .saturating_add(Duration::from_secs(1));
    let report = scenario.shutdown(deadline).await;

    assert!(!report.timed_out);
    assert_eq!(report.remaining_tasks, 0);
    assert_eq!(
        control.captured_client_frames(),
        vec![Bytes::from_static(b"client")]
    );
    assert!(
        report.events.iter().any(
            |event| matches!(event, ScenarioEvent::TaskSucceeded { name } if name == "exchange")
        )
    );
}

#[tokio::test]
async fn success_failure_panic_and_cooperative_cancel_have_stable_events() {
    let mut scenario = LifecycleScenario::new();
    scenario
        .spawn("success", |_cancel| async { Ok(()) })
        .expect("unique task");
    scenario
        .spawn("failure", |_cancel| async {
            Err(ScenarioTaskError::failed("expected-failure"))
        })
        .expect("unique task");
    scenario
        .spawn("panic", |_cancel| async {
            panic!("test panic must not escape scenario");
        })
        .expect("unique task");
    scenario
        .spawn("cancel", |cancel| async move {
            cancel.cancelled().await;
            Err(ScenarioTaskError::cancelled())
        })
        .expect("unique task");

    let deadline = scenario
        .clock()
        .now()
        .saturating_add(Duration::from_secs(1));
    let report = scenario.shutdown(deadline).await;
    let json = serde_json::to_value(&report).expect("report serializes");

    assert!(
        report.events.iter().any(
            |event| matches!(event, ScenarioEvent::TaskSucceeded { name } if name == "success")
        )
    );
    assert!(report.events.iter().any(|event| matches!(
        event,
        ScenarioEvent::TaskFailed { name, code }
            if name == "failure" && code == "expected-failure"
    )));
    assert!(
        report
            .events
            .iter()
            .any(|event| matches!(event, ScenarioEvent::TaskPanicked { name } if name == "panic"))
    );
    assert!(
        report.events.iter().any(
            |event| matches!(event, ScenarioEvent::TaskCancelled { name } if name == "cancel")
        )
    );
    assert!(json.get("events").is_some());
    assert!(json.get("timed_out").is_some());
    assert!(json.get("remaining_tasks").is_some());
}

#[tokio::test]
async fn shutdown_deadline_aborts_and_joins_a_non_cooperative_task() {
    let mut scenario = LifecycleScenario::new();
    scenario
        .spawn("stuck", |_cancel| std::future::pending())
        .expect("unique task");
    let clock = scenario.clock();
    let deadline = clock.now().saturating_add(Duration::from_secs(5));
    let mut shutdown = std::pin::pin!(scenario.shutdown(deadline));

    assert!(matches!(poll!(&mut shutdown), Poll::Pending));
    clock
        .advance(Duration::from_secs(5))
        .await
        .expect("manual deadline advances");
    let report = shutdown.await;

    assert!(report.timed_out);
    assert_eq!(report.remaining_tasks, 0);
    assert!(
        report
            .events
            .iter()
            .any(|event| matches!(event, ScenarioEvent::TaskCancelled { name } if name == "stuck"))
    );
}

#[tokio::test]
async fn transport_faults_support_partial_write_and_close_scenarios() {
    let mut scenario = LifecycleScenario::new();
    let control = scenario.transport_control();
    control.fail_write_on(2, ErrorKind::BrokenPipe);
    control.fail_read_on(1, ErrorKind::ConnectionReset);
    let transport = scenario.take_transport().expect("transport is unique");
    let (mut read, mut write) = transport.split().expect("transport splits");

    let read_error = read.receive().await.expect_err("close-like read fault");
    let write_error = write
        .send(&IoVec::from(vec![b"header".to_vec(), b"payload".to_vec()]))
        .await
        .expect_err("body send_raw fault");

    assert!(matches!(
        read_error,
        smb::transport::TransportError::IoError(error)
            if error.kind() == ErrorKind::ConnectionReset
    ));
    assert!(matches!(
        write_error,
        smb::transport::TransportError::IoError(error) if error.kind() == ErrorKind::BrokenPipe
    ));
    assert!(control.captured_client_frames().is_empty());
}

#[tokio::test]
async fn cancellation_before_send_leaves_no_client_frame() {
    let mut scenario = LifecycleScenario::new();
    let control = scenario.transport_control();
    let transport = scenario.take_transport().expect("transport is unique");
    let (_, mut write) = transport.split().expect("transport splits");
    scenario
        .spawn("cancel-before-send", move |cancel| async move {
            let payload = IoVec::from(b"must-not-send".to_vec());
            tokio::select! {
                biased;
                _ = cancel.cancelled() => Err(ScenarioTaskError::cancelled()),
                result = write.send(&payload) => {
                    result.map_err(ScenarioTaskError::from)
                }
            }
        })
        .expect("unique task");
    let deadline = scenario
        .clock()
        .now()
        .saturating_add(Duration::from_secs(1));

    let report = scenario.shutdown(deadline).await;

    assert!(control.captured_client_frames().is_empty());
    assert!(report.events.iter().any(|event| matches!(
        event,
        ScenarioEvent::TaskCancelled { name } if name == "cancel-before-send"
    )));
}

#[tokio::test]
async fn equal_time_response_and_timeout_commit_only_the_first_terminal_outcome() {
    let mut scenario = LifecycleScenario::new();
    let clock = scenario.clock();
    let deadline = clock.now().saturating_add(Duration::from_secs(2));
    let response_sleep = clock.sleep_until(deadline);
    let timeout_sleep = clock.sleep_until(deadline);
    let terminal = TerminalProbe::default();
    let response_terminal = terminal.clone();
    scenario
        .spawn("response", move |_cancel| async move {
            response_sleep.await;
            response_terminal.try_commit(TerminalOutcome::Response);
            Ok(())
        })
        .expect("unique task");
    let timeout_terminal = terminal.clone();
    scenario
        .spawn("timeout", move |_cancel| async move {
            timeout_sleep.await;
            timeout_terminal.try_commit(TerminalOutcome::TimedOut);
            Ok(())
        })
        .expect("unique task");

    clock
        .advance(Duration::from_secs(2))
        .await
        .expect("race deadline advances");
    let shutdown_deadline = clock.now().saturating_add(Duration::from_secs(1));
    let report = scenario.shutdown(shutdown_deadline).await;

    assert!(!report.timed_out);
    assert_eq!(terminal.outcome(), Some(TerminalOutcome::Response));
}

#[tokio::test]
async fn report_rejects_payload_like_task_names_and_sanitizes_failure_codes() {
    let mut scenario = LifecycleScenario::new();
    let invalid = scenario.spawn("contains secret", |_cancel| async { Ok(()) });
    assert_eq!(invalid, Err(ScenarioError::InvalidTaskName));
    scenario
        .spawn("safe-name", |_cancel| async {
            Err(ScenarioTaskError::failed("contains secret payload"))
        })
        .expect("stable name is accepted");
    let deadline = scenario
        .clock()
        .now()
        .saturating_add(Duration::from_secs(1));

    let report = scenario.shutdown(deadline).await;

    assert!(report.events.iter().any(|event| matches!(
        event,
        ScenarioEvent::TaskFailed { name, code }
            if name == "safe-name" && code == "invalid-failure-code"
    )));
}
