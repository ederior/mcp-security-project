import pytest

from mcp_server.session import (
    SessionError,
    SessionStore,
    SessionValidationMode,
)


def test_create_session_binds_owner_and_hides_raw_session_id() -> None:
    store = SessionStore()

    session = store.create_session(
        "user_1",
        session_id="raw_session_1",
    )
    context = store.begin_request(
        actor_user_id="user_1",
        session_id=session.session_id,
        nonce="raw_nonce_1",
        validation_mode=SessionValidationMode.VALIDATED,
        request_id="request_1",
    )

    assert session.owner_user_id == "user_1"
    assert context.session_owner_user_id == "user_1"
    assert context.session_fingerprint != "raw_session_1"
    assert context.nonce_fingerprint != "raw_nonce_1"


def test_distinct_requests_share_one_session_context() -> None:
    store = SessionStore()
    session = store.create_session("user_1", session_id="session_shared")

    first = store.begin_request(
        actor_user_id="user_1",
        session_id=session.session_id,
        nonce="nonce_1",
        validation_mode=SessionValidationMode.VALIDATED,
        request_id="request_1",
    )
    second = store.begin_request(
        actor_user_id="user_1",
        session_id=session.session_id,
        nonce="nonce_2",
        validation_mode=SessionValidationMode.VALIDATED,
        request_id="request_2",
    )

    assert first.accepted is True
    assert second.accepted is True
    assert first.session_fingerprint == second.session_fingerprint
    assert first.nonce_fingerprint != second.nonce_fingerprint
    assert session.used_nonces == {"nonce_1", "nonce_2"}


def test_validated_mode_rejects_user_mismatch() -> None:
    store = SessionStore()
    session = store.create_session("user_1", session_id="session_user_1")

    context = store.begin_request(
        actor_user_id="user_2",
        session_id=session.session_id,
        nonce="nonce_1",
        validation_mode=SessionValidationMode.VALIDATED,
    )

    assert context.accepted is False
    assert context.user_mismatch is True
    assert context.reason_code == "session_user_mismatch"
    assert session.used_nonces == set()


def test_vulnerable_mode_marks_user_mismatch_but_allows_request() -> None:
    store = SessionStore()
    session = store.create_session("user_1", session_id="session_user_1")

    context = store.begin_request(
        actor_user_id="user_2",
        session_id=session.session_id,
        nonce="nonce_1",
        validation_mode=SessionValidationMode.VULNERABLE,
    )

    assert context.accepted is True
    assert context.user_mismatch is True
    assert context.reason_code is None
    assert session.used_nonces == {"nonce_1"}


def test_validated_mode_rejects_duplicate_nonce() -> None:
    store = SessionStore()
    session = store.create_session("user_1", session_id="session_user_1")

    first = store.begin_request(
        actor_user_id="user_1",
        session_id=session.session_id,
        nonce="nonce_1",
        validation_mode=SessionValidationMode.VALIDATED,
    )
    replay = store.begin_request(
        actor_user_id="user_1",
        session_id=session.session_id,
        nonce="nonce_1",
        validation_mode=SessionValidationMode.VALIDATED,
    )

    assert first.accepted is True
    assert replay.accepted is False
    assert replay.replay_detected is True
    assert replay.reason_code == "duplicate_nonce"
    assert session.used_nonces == {"nonce_1"}


def test_vulnerable_mode_marks_duplicate_nonce_but_allows_replay() -> None:
    store = SessionStore()
    session = store.create_session("user_1", session_id="session_user_1")

    store.begin_request(
        actor_user_id="user_1",
        session_id=session.session_id,
        nonce="nonce_1",
        validation_mode=SessionValidationMode.VULNERABLE,
    )
    replay = store.begin_request(
        actor_user_id="user_1",
        session_id=session.session_id,
        nonce="nonce_1",
        validation_mode=SessionValidationMode.VULNERABLE,
    )

    assert replay.accepted is True
    assert replay.replay_detected is True
    assert replay.reason_code is None


def test_unknown_session_is_rejected() -> None:
    store = SessionStore()

    with pytest.raises(SessionError):
        store.begin_request(
            actor_user_id="user_1",
            session_id="missing_session",
            nonce="nonce_1",
            validation_mode=SessionValidationMode.VALIDATED,
        )
