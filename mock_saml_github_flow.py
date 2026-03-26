import base64
import json
import hmac
import hashlib
import time
from dataclasses import dataclass
from typing import Dict, Any


# ----------------------------
# Helpers
# ----------------------------

def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("utf-8")

def b64d(txt: str) -> bytes:
    return base64.b64decode(txt.encode("utf-8"))

def now() -> int:
    return int(time.time())

def sign_hmac(payload: bytes, secret: bytes) -> str:
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()

def verify_hmac(payload: bytes, signature_hex: str, secret: bytes) -> bool:
    expected = sign_hmac(payload, secret)
    return hmac.compare_digest(expected, signature_hex)


# ----------------------------
# Mock objects
# ----------------------------

@dataclass
class AuthnRequest:
    issuer: str          # SP entity ID (GitHub)
    acs_url: str         # where IdP should POST the Response (GitHub ACS)
    audience: str        # intended SP audience (GitHub entity ID)
    request_id: str
    relay_state: str
    issue_instant: int

    def to_wire(self) -> str:
        """
        Real SAML uses deflate+base64 for Redirect binding, but we just base64 JSON here.
        """
        data = {
            "issuer": self.issuer,
            "acs_url": self.acs_url,
            "audience": self.audience,
            "request_id": self.request_id,
            "relay_state": self.relay_state,
            "issue_instant": self.issue_instant,
        }
        return b64e(json.dumps(data).encode("utf-8"))

    @staticmethod
    def from_wire(wire: str) -> "AuthnRequest":
        data = json.loads(b64d(wire))
        return AuthnRequest(**data)


@dataclass
class SAMLAssertion:
    subject: str                 # user identity (often NameID)
    attributes: Dict[str, Any]   # email, groups, etc.
    issuer: str                  # IdP entity ID
    audience: str                # SP entity ID (GitHub)
    in_response_to: str          # request_id
    not_before: int
    not_on_or_after: int

    def to_bytes(self) -> bytes:
        return json.dumps({
            "subject": self.subject,
            "attributes": self.attributes,
            "issuer": self.issuer,
            "audience": self.audience,
            "in_response_to": self.in_response_to,
            "not_before": self.not_before,
            "not_on_or_after": self.not_on_or_after,
        }, sort_keys=True).encode("utf-8")


@dataclass
class SAMLResponse:
    assertion_b64: str
    signature: str  # mock "XML signature" via HMAC over assertion bytes

    def to_wire(self) -> str:
        return b64e(json.dumps({
            "assertion_b64": self.assertion_b64,
            "signature": self.signature,
        }).encode("utf-8"))

    @staticmethod
    def from_wire(wire: str) -> "SAMLResponse":
        data = json.loads(b64d(wire))
        return SAMLResponse(**data)


# ----------------------------
# Parties
# ----------------------------

class MockGitHubSP:
    """
    Represents GitHub as a SAML Service Provider for one org.
    """
    def __init__(self, entity_id: str, acs_url: str, idp_signing_secret: bytes):
        self.entity_id = entity_id
        self.acs_url = acs_url
        self.idp_signing_secret = idp_signing_secret

        # For demo: store SSO-authorized sessions by user
        self.sso_authorized_users = set()

    def start_sso(self, relay_state: str) -> Dict[str, str]:
        # Build an AuthnRequest (real SAML has many more fields)
        req = AuthnRequest(
            issuer=self.entity_id,
            acs_url=self.acs_url,
            audience=self.entity_id,
            request_id=f"REQ-{now()}",
            relay_state=relay_state,
            issue_instant=now(),
        )
        # SP redirects browser to IdP with SAMLRequest + RelayState
        return {
            "redirect_to_idp": "https://idp.example.com/sso",
            "SAMLRequest": req.to_wire(),
            "RelayState": req.relay_state,
        }

    def consume_acs_post(self, saml_response_wire: str, relay_state: str) -> str:
        """
        This simulates GitHub's ACS endpoint receiving an HTTP POST with:
          - SAMLResponse
          - RelayState
        """
        resp = SAMLResponse.from_wire(saml_response_wire)
        assertion_bytes = b64d(resp.assertion_b64)

        # 1) Verify signature (real GitHub verifies XMLSig with IdP cert)
        if not verify_hmac(assertion_bytes, resp.signature, self.idp_signing_secret):
            raise ValueError("Invalid SAML signature")

        # 2) Parse assertion
        assertion_dict = json.loads(assertion_bytes.decode("utf-8"))

        # 3) Validate core conditions (audience + time window)
        if assertion_dict["audience"] != self.entity_id:
            raise ValueError("Invalid audience (not intended for this SP)")

        t = now()
        if t < assertion_dict["not_before"]:
            raise ValueError("Assertion not yet valid")
        if t >= assertion_dict["not_on_or_after"]:
            raise ValueError("Assertion expired")

        # 4) Create org SSO authorization
        user = assertion_dict["subject"]
        self.sso_authorized_users.add(user)

        # 5) Redirect user back to relay_state target
        return f"SSO success for {user}. Redirecting to: {relay_state}"


class MockIdP:
    """
    Represents your company's SAML Identity Provider.
    """
    def __init__(self, entity_id: str, signing_secret: bytes):
        self.entity_id = entity_id
        self.signing_secret = signing_secret

    def handle_redirect(self, saml_request_wire: str, relay_state: str, username: str) -> Dict[str, str]:
        """
        Browser arrives at IdP with SAMLRequest + RelayState.
        IdP authenticates user and returns a POST to SP ACS with SAMLResponse.
        """
        req = AuthnRequest.from_wire(saml_request_wire)

        # (Pretend) user authenticated here: password + MFA + policy checks

        # Build assertion with validity window
        assertion = SAMLAssertion(
            subject=username,
            attributes={
                "email": f"{username}@example.com",
                "groups": ["dev", "github-users"],
            },
            issuer=self.entity_id,
            audience=req.audience,
            in_response_to=req.request_id,
            not_before=now() - 5,
            not_on_or_after=now() + 300,  # 5 minutes
        )

        assertion_bytes = assertion.to_bytes()
        saml_response = SAMLResponse(
            assertion_b64=b64e(assertion_bytes),
            signature=sign_hmac(assertion_bytes, self.signing_secret),
        )

        # IdP returns an auto-submitted HTML form POST to ACS in real life.
        return {
            "post_to_acs": req.acs_url,
            "SAMLResponse": saml_response.to_wire(),
            "RelayState": relay_state,
        }


# ----------------------------
# Demo "browser" run
# ----------------------------

if __name__ == "__main__":
    # Shared secret here stands in for "IdP signing cert" that GitHub trusts.
    IDP_SIGNING_SECRET = b"super-secret-signing-key"

    github_sp = MockGitHubSP(
        entity_id="https://github.com/orgs/ACME",
        acs_url="https://github.com/orgs/ACME/saml/consume",
        idp_signing_secret=IDP_SIGNING_SECRET,
    )
    idp = MockIdP(
        entity_id="https://idp.example.com/metadata",
        signing_secret=IDP_SIGNING_SECRET,
    )

    # 1) User tries to access a protected resource in GitHub org
    sp_redirect = github_sp.start_sso(relay_state="https://github.com/ACME/private-repo")

    # 2) Browser follows redirect to IdP
    idp_post = idp.handle_redirect(
        saml_request_wire=sp_redirect["SAMLRequest"],
        relay_state=sp_redirect["RelayState"],
        username="karthick",
    )

    # 3) Browser posts SAMLResponse back to GitHub ACS
    result = github_sp.consume_acs_post(
        saml_response_wire=idp_post["SAMLResponse"],
        relay_state=idp_post["RelayState"],
    )

    print(result)
    print("SSO-authorized users:", github_sp.sso_authorized_users)
