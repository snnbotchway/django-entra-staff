"""A software WebAuthn authenticator: fido2's own client and server code run
unmocked against an in-memory CTAP2 device, the way a browser and a security
key would drive allauth's endpoints."""

try:
    import fido2.features

    fido2.features.webauthn_json_mapping.enabled = True
except AttributeError:
    pass

import hashlib
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor
from fido2.client import DefaultClientDataCollector, Fido2Client
from fido2.cose import ES256
from fido2.ctap import CtapDevice, CtapError
from fido2.ctap2 import Ctap2
from fido2.hid import CAPABILITY
from fido2.webauthn import AttestedCredentialData, AuthenticatorData

ORIGIN = "https://testserver"


class _SoftCtapDevice(CtapDevice):
    """The CTAP2 half of an authenticator holding its credentials in memory."""

    capabilities = CAPABILITY.CBOR

    def __init__(self):
        self.credentials = {}
        self.counter = 0

    @classmethod
    def list_devices(cls):
        return iter(())

    def call(self, cmd, data=b"", event=None, on_keepalive=None):
        params = cbor.decode(data[1:]) if len(data) > 1 else {}
        match data[0]:
            case Ctap2.CMD.GET_INFO:
                info = {1: ["FIDO_2_0"], 3: bytes(16), 4: {"up": True}, 5: 1024}
                return b"\x00" + cbor.encode(info)
            case Ctap2.CMD.MAKE_CREDENTIAL:
                return b"\x00" + cbor.encode(self._make_credential(params))
            case Ctap2.CMD.GET_ASSERTION:
                return b"\x00" + cbor.encode(self._get_assertion(params))
            case _:
                raise CtapError(CtapError.ERR.INVALID_COMMAND)

    def _make_credential(self, params):
        rp, user = params[2], params[3]
        for excluded in params.get(5) or []:
            if excluded["id"] in self.credentials:
                raise CtapError(CtapError.ERR.CREDENTIAL_EXCLUDED)
        key = ec.generate_private_key(ec.SECP256R1())
        credential_id = os.urandom(32)
        self.credentials[credential_id] = (key, rp["id"], user["id"])
        self.counter += 1
        credential_data = AttestedCredentialData.create(
            bytes(16), credential_id, ES256.from_cryptography_key(key.public_key())
        )
        auth_data = AuthenticatorData.create(
            hashlib.sha256(rp["id"].encode()).digest(),
            AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT,
            self.counter,
            credential_data,
        )
        return {1: "none", 2: auth_data, 3: {}}

    def _get_assertion(self, params):
        rp_id, client_data_hash, allow_list, options = (
            params[1],
            params[2],
            params.get(3),
            params.get(5) or {},
        )
        matches = [
            (credential_id, secret)
            for credential_id, secret in self.credentials.items()
            if secret[1] == rp_id
            and (allow_list is None or any(c["id"] == credential_id for c in allow_list))
        ]
        if not matches:
            raise CtapError(CtapError.ERR.NO_CREDENTIALS)
        credential_id, (key, _, user_handle) = matches[0]
        self.counter += 1
        flags = AuthenticatorData.FLAG.UP if options.get("up", True) else 0
        if options.get("uv"):
            flags |= AuthenticatorData.FLAG.UV
        auth_data = AuthenticatorData.create(
            hashlib.sha256(rp_id.encode()).digest(), flags, self.counter
        )
        signature = key.sign(auth_data + client_data_hash, ec.ECDSA(hashes.SHA256()))
        return {
            1: {"id": credential_id, "type": "public-key"},
            2: auth_data,
            3: signature,
            4: {"id": user_handle},
        }


class SoftwareAuthenticator:
    """One physical authenticator. A second passkey needs a second instance,
    the way a second registration needs a second device."""

    def __init__(self):
        self._client = Fido2Client(_SoftCtapDevice(), DefaultClientDataCollector(ORIGIN))

    def create_credential(self, creation_options):
        """What the browser's navigator.credentials.create() hands back."""
        response = self._client.make_credential(creation_options["publicKey"])
        return dict(response)

    def sign(self, request_options):
        """What the browser's navigator.credentials.get() hands back."""
        assertion = self._client.get_assertion(request_options["publicKey"])
        return dict(assertion.get_response(0))
