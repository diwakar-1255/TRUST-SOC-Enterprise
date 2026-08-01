import base64
import hashlib
import hmac
import json
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
from jose import JWTError, jwt

from trustsoc.config import get_settings

settings = get_settings()
_password_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _password_hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False


def _create_token(
    subject: str, org_id: str, role: str, token_version: int, kind: str, ttl: timedelta
) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": subject,
        "org": org_id,
        "role": role,
        "ver": token_version,
        "typ": kind,
        "iat": int(now.timestamp()),
        "exp": int((now + ttl).timestamp()),
        "jti": secrets.token_urlsafe(16),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def create_access_token(subject: str, org_id: str, role: str, token_version: int) -> str:
    return _create_token(
        subject,
        org_id,
        role,
        token_version,
        "access",
        timedelta(minutes=settings.access_token_minutes),
    )


def create_refresh_token(subject: str, org_id: str, role: str, token_version: int) -> str:
    return _create_token(
        subject, org_id, role, token_version, "refresh", timedelta(days=settings.refresh_token_days)
    )


def decode_token(token: str, expected_kind: str) -> dict[str, Any]:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
    except JWTError as exc:
        raise ValueError("Invalid token") from exc
    if payload.get("typ") != expected_kind:
        raise ValueError("Incorrect token type")
    return payload


def _fernet() -> Fernet:
    digest = hashlib.sha256(settings.encryption_key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_secret(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def decrypt_secret(value: str) -> str:
    return _fernet().decrypt(value.encode()).decode()


def generate_shared_secret() -> str:
    return secrets.token_urlsafe(48)


def canonical_event_payload(event: dict[str, Any]) -> bytes:
    selected = {
        "source_id": str(event["source_id"]),
        "sequence": int(event["sequence"]),
        "event_type": event["event_type"],
        "observed_at": event["observed_at"].isoformat()
        if hasattr(event["observed_at"], "isoformat")
        else event["observed_at"],
        "body": event["body"],
        "previous_hash": event.get("previous_hash"),
    }
    return json.dumps(selected, sort_keys=True, separators=(",", ":"), default=str).encode()


def compute_event_hash(event: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_event_payload(event)).hexdigest()


def compute_signature(secret: str, event_hash: str) -> str:
    return hmac.new(secret.encode(), event_hash.encode(), hashlib.sha256).hexdigest()


def verify_signature(secret: str, event_hash: str, signature: str) -> bool:
    expected = compute_signature(secret, event_hash)
    return hmac.compare_digest(expected, signature)
