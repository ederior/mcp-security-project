from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from hashlib import sha256
from secrets import token_urlsafe


class SessionValidationMode(str, Enum):
    VULNERABLE = "vulnerable"
    VALIDATED = "validated"


class SessionError(ValueError):
    pass


@dataclass
class ServerSession:
    session_id: str
    owner_user_id: str
    created_at: datetime
    used_nonces: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class RequestContext:
    request_id: str
    actor_user_id: str
    session_owner_user_id: str
    session_id: str
    session_fingerprint: str
    nonce: str
    nonce_fingerprint: str
    validation_mode: SessionValidationMode
    user_mismatch: bool
    replay_detected: bool
    accepted: bool
    reason_code: str | None


class SessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, ServerSession] = {}

    def create_session(
        self,
        owner_user_id: str,
        *,
        session_id: str | None = None,
    ) -> ServerSession:
        if not owner_user_id:
            raise SessionError("owner_user_id is required")

        new_session_id = session_id or self._new_identifier("session")

        if new_session_id in self._sessions:
            raise SessionError("session_id already exists")

        session = ServerSession(
            session_id=new_session_id,
            owner_user_id=owner_user_id,
            created_at=datetime.now(UTC),
        )
        self._sessions[new_session_id] = session

        return session

    def used_nonces(self, session_id: str) -> frozenset[str]:
        """Read-only copy of the nonces already accepted for a session."""
        session = self._sessions.get(session_id)

        if session is None:
            raise SessionError("unknown session_id")

        return frozenset(session.used_nonces)

    def begin_request(
        self,
        *,
        actor_user_id: str,
        session_id: str,
        nonce: str,
        validation_mode: SessionValidationMode,
        request_id: str | None = None,
    ) -> RequestContext:
        if not actor_user_id:
            raise SessionError("actor_user_id is required")
        if not nonce:
            raise SessionError("nonce is required")

        session = self._sessions.get(session_id)

        if session is None:
            raise SessionError("unknown session_id")

        user_mismatch = actor_user_id != session.owner_user_id
        replay_detected = nonce in session.used_nonces
        accepted = True
        reason_code = None

        if validation_mode == SessionValidationMode.VALIDATED:
            if user_mismatch:
                accepted = False
                reason_code = "session_user_mismatch"
            elif replay_detected:
                accepted = False
                reason_code = "duplicate_nonce"
        elif validation_mode != SessionValidationMode.VULNERABLE:
            raise SessionError("unknown validation_mode")

        if accepted:
            session.used_nonces.add(nonce)

        return RequestContext(
            request_id=request_id or self._new_identifier("request"),
            actor_user_id=actor_user_id,
            session_owner_user_id=session.owner_user_id,
            session_id=session.session_id,
            session_fingerprint=self.fingerprint(session.session_id),
            nonce=nonce,
            nonce_fingerprint=self.fingerprint(nonce),
            validation_mode=validation_mode,
            user_mismatch=user_mismatch,
            replay_detected=replay_detected,
            accepted=accepted,
            reason_code=reason_code,
        )

    @staticmethod
    def fingerprint(value: str) -> str:
        digest = sha256(value.encode("utf-8")).hexdigest()
        return f"sha256:{digest[:16]}"

    @staticmethod
    def _new_identifier(prefix: str) -> str:
        return f"{prefix}_{token_urlsafe(18)}"
