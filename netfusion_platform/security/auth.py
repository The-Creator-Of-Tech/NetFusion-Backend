"""
NetFusion Authentication & Session Management Module
Handles JWT generation/verification, API Key management, and Session tracking.
"""

import time
import hmac
import hashlib
import base64
import json
import uuid
from typing import Dict, Any, Optional, Set
from dataclasses import dataclass, field


@dataclass
class UserSession:
    """User authentication session context."""
    session_id: str
    user_id: str
    username: str
    roles: Set[str]
    created_at: float
    expires_at: float
    is_active: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


class AuthenticationError(ValueError):
    """Raised on authentication failures."""
    pass


class AuthManager:
    """Authentication Manager supporting JWT tokens, API Keys, and Sessions."""

    def __init__(self, jwt_secret: str = "netfusion-secret", jwt_algorithm: str = "HS256", expiration_minutes: int = 60):
        self._secret = jwt_secret.encode('utf-8')
        self._algorithm = jwt_algorithm
        self._expiration_seconds = expiration_minutes * 60
        self._api_keys: Dict[str, Dict[str, Any]] = {}
        self._sessions: Dict[str, UserSession] = {}
        self._revoked_tokens: Set[str] = set()

    # --- API KEY MANAGEMENT ---
    def register_api_key(self, api_key: str, user_id: str, roles: Set[str], description: str = "") -> None:
        """Register an API key with associated roles and user context."""
        key_hash = hashlib.sha256(api_key.encode('utf-8')).hexdigest()
        self._api_keys[key_hash] = {
            "user_id": user_id,
            "roles": roles,
            "description": description,
            "created_at": time.time(),
        }

    def validate_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Validate API key and return user context if valid."""
        key_hash = hashlib.sha256(api_key.encode('utf-8')).hexdigest()
        return self._api_keys.get(key_hash)

    # --- JWT MANAGEMENT ---
    def create_jwt(self, user_id: str, username: str, roles: Set[str], custom_claims: Optional[Dict[str, Any]] = None) -> str:
        """Create a signed JWT token."""
        header = {"alg": self._algorithm, "typ": "JWT"}
        now = time.time()
        jti = str(uuid.uuid4())
        
        payload = {
            "sub": user_id,
            "username": username,
            "roles": list(roles),
            "iat": int(now),
            "exp": int(now + self._expiration_seconds),
            "jti": jti,
        }
        if custom_claims:
            payload.update(custom_claims)

        encoded_header = self._b64_encode(json.dumps(header).encode('utf-8'))
        encoded_payload = self._b64_encode(json.dumps(payload).encode('utf-8'))
        
        signing_input = f"{encoded_header}.{encoded_payload}".encode('utf-8')
        signature = self._sign(signing_input)
        encoded_signature = self._b64_encode(signature)

        return f"{encoded_header}.{encoded_payload}.{encoded_signature}"

    def verify_jwt(self, token: str) -> Dict[str, Any]:
        """Verify JWT signature, expiration, and revocation status."""
        parts = token.split('.')
        if len(parts) != 3:
            raise AuthenticationError("Malformed JWT token format")

        encoded_header, encoded_payload, encoded_signature = parts

        if token in self._revoked_tokens:
            raise AuthenticationError("Token has been revoked")

        signing_input = f"{encoded_header}.{encoded_payload}".encode('utf-8')
        expected_sig = self._sign(signing_input)
        actual_sig = self._b64_decode(encoded_signature)

        if not hmac.compare_digest(expected_sig, actual_sig):
            raise AuthenticationError("Invalid JWT token signature")

        payload = json.loads(self._b64_decode(encoded_payload).decode('utf-8'))
        
        if time.time() > payload.get("exp", 0):
            raise AuthenticationError("JWT token has expired")

        return payload

    def revoke_token(self, token: str) -> None:
        """Revoke a JWT token."""
        self._revoked_tokens.add(token)

    # --- SESSION MANAGEMENT ---
    def create_session(self, user_id: str, username: str, roles: Set[str]) -> UserSession:
        """Create a new user session."""
        now = time.time()
        session_id = str(uuid.uuid4())
        session = UserSession(
            session_id=session_id,
            user_id=user_id,
            username=username,
            roles=roles,
            created_at=now,
            expires_at=now + self._expiration_seconds,
        )
        self._sessions[session_id] = session
        return session

    def get_session(self, session_id: str) -> Optional[UserSession]:
        """Retrieve active session."""
        session = self._sessions.get(session_id)
        if not session or not session.is_active:
            return None
        if time.time() > session.expires_at:
            session.is_active = False
            return None
        return session

    def invalidate_session(self, session_id: str) -> None:
        """Invalidate session."""
        if session_id in self._sessions:
            self._sessions[session_id].is_active = False

    # --- HELPERS ---
    def _sign(self, data: bytes) -> bytes:
        return hmac.new(self._secret, data, hashlib.sha256).digest()

    @staticmethod
    def _b64_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

    @staticmethod
    def _b64_decode(data_str: str) -> bytes:
        padding = '=' * (-len(data_str) % 4)
        return base64.urlsafe_b64decode(data_str + padding)
