"""Tests for preserving the device identity supplied by the local Anisette API."""

from __future__ import annotations

import asyncio
import base64
import plistlib
import unittest
from typing import Any
from types import SimpleNamespace
from unittest.mock import patch

from findmy import AsyncAppleAccount, LoginState
from findmy.reports.account import _normalize_2fa_status
from findmy.reports import anisette as anisette_report
from findmy.reports.anisette import LocalAnisetteProvider
from findmy.util.http import HttpResponse

_USER_ID = "mac26-local-user"
_DEVICE_ID = "12345678-1234-5678-1234-567812345678"
_PLATFORM = "<MacBookPro16,2> <macOS;26.0;25A354>"
_CLIENT_INFO = f"{_PLATFORM} <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
_USER_AGENT = "akd/1.0 CFNetwork/3860.100.1 Darwin/25.0.0"
_MAC_HEADERS = {
    "X-Apple-I-Client-Time": "2026-10-18T10:00:00Z",
    "X-Apple-I-MD": "mac26-otp",
    "X-Apple-I-MD-LU": base64.b64encode(_USER_ID.encode()).decode(),
    "X-Apple-I-MD-M": "mac26-machine",
    "X-Apple-I-MD-RINFO": "17106176",
    "X-Apple-I-SRL-NO": "mac26-serial",
    "X-Apple-I-TimeZone": "UTC",
    "X-Apple-Locale": "en_US",
    "X-MMe-Client-Info": _CLIENT_INFO,
    "X-Mme-Device-Id": _DEVICE_ID,
}


class _FakeAnisette:
    device = SimpleNamespace(user_agent=_USER_AGENT)

    def get_data(self) -> dict[str, str]:
        return _MAC_HEADERS


class _ImmediateLoop:
    """Run the provider's blocking call inline so tests do not start worker threads."""

    def run_in_executor(self, executor: object, function: Any, *args: Any) -> asyncio.Future:
        future = asyncio.get_running_loop().create_future()
        try:
            future.set_result(function(*args))
        except Exception as error:
            future.set_exception(error)
        return future


class _ImmediateAsyncio:
    @staticmethod
    def get_running_loop() -> _ImmediateLoop:
        return _ImmediateLoop()


class _FakeResponse:
    ok = True

    def plist(self) -> dict[str, dict[str, Any]]:
        return {"Response": {}}


class LocalAnisetteIdentityTest(unittest.TestCase):
    def test_apple_409_without_au_is_a_trusted_device_challenge(self) -> None:
        status: dict[str, Any] = {"hsc": 409}

        _normalize_2fa_status(status)

        self.assertEqual(status["au"], "trustedDeviceSecondaryAuth")

    def test_other_auth_statuses_are_unchanged(self) -> None:
        status: dict[str, Any] = {"hsc": 200, "au": "secondaryAuth"}

        _normalize_2fa_status(status)

        self.assertEqual(status, {"hsc": 200, "au": "secondaryAuth"})

    def test_local_provider_preserves_device_headers(self) -> None:
        """Forward the machine identity and client string from the Anisette API."""
        provider = LocalAnisetteProvider()

        async def fake_get_ani() -> _FakeAnisette:
            return _FakeAnisette()

        with (
            patch.object(provider, "_get_ani", fake_get_ani),
            patch.object(
                anisette_report,
                "asyncio",
                _ImmediateAsyncio,
            ),
        ):
            headers = asyncio.run(
                provider.get_headers("random-user", "random-device", with_client_info=True),
            )

        for name, value in _MAC_HEADERS.items():
            if name.lower() != "x-mme-client-info":
                self.assertEqual(headers[name], value)
        self.assertEqual(
            [value for name, value in headers.items() if name.lower() == "x-mme-client-info"],
            [f"{_PLATFORM} <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>"],
        )
        self.assertEqual(provider.client, _CLIENT_INFO)

    def test_gsa_request_uses_local_anisette_identity(self) -> None:
        """Keep account state and the request identity aligned with the Anisette machine."""
        provider = LocalAnisetteProvider()

        async def fake_get_ani() -> _FakeAnisette:
            return _FakeAnisette()

        account = AsyncAppleAccount(provider)
        sent: dict[str, Any] = {}

        async def fake_post(url: str, *, headers: dict[str, str], data: bytes) -> _FakeResponse:
            sent["headers"] = headers
            sent["request"] = plistlib.loads(data)["Request"]
            return _FakeResponse()

        with (
            patch.object(provider, "_get_ani", fake_get_ani),
            patch.object(
                anisette_report,
                "asyncio",
                _ImmediateAsyncio,
            ),
            patch.object(
                account._http,
                "post",
                fake_post,
            ),
        ):

            async def run() -> None:
                await account._gsa_request({"o": "init"})
                await account.close()

            asyncio.run(run())

        self.assertEqual(account._uid, _USER_ID)
        self.assertEqual(account._devid, _DEVICE_ID)
        cpd = sent["request"]["cpd"]
        self.assertEqual(cpd["X-Apple-I-MD-LU"], _MAC_HEADERS["X-Apple-I-MD-LU"])
        self.assertEqual(cpd["X-Mme-Device-Id"], _DEVICE_ID)
        self.assertEqual(sent["headers"]["X-MMe-Client-Info"], _CLIENT_INFO)
        self.assertFalse(any(name.lower() == "x-mme-client-info" for name in cpd))

    def test_2fa_and_mobileme_use_one_client_info_for_the_local_mac(self) -> None:
        provider = LocalAnisetteProvider()
        provider._ani = _FakeAnisette()
        account = AsyncAppleAccount(provider)
        account._username = "offline@example.test"
        sent = []

        async def fake_request(method, url, **kwargs):
            sent.append(kwargs["headers"])
            return HttpResponse(
                200,
                plistlib.dumps(
                    {
                        "status": 0,
                        "dsid": "fixture",
                        "delegates": {"com.apple.mobileme": {"service-data": {}}},
                    }
                ),
            )

        async def run():
            try:
                await account._gsa_request({"o": "complete", "c": "fixture", "M1": b"proof"})
                account._set_login_state(
                    LoginState.REQUIRE_2FA,
                    {"adsid": "fixture", "idms_token": "fixture"},
                )
                await account._sms_2fa_request("GET", "https://example.test/auth")
                account._set_login_state(
                    LoginState.AUTHENTICATED,
                    {"adsid": "fixture", "idms_pet": "fixture"},
                )
                await account._login_mobileme()
            finally:
                await account.close()

        # GSA expects a Response envelope; the other two endpoints read the top level.
        async def fake_post(url, **kwargs):
            if url == account._ENDPOINT_GSA:
                sent.append(kwargs["headers"])
                return HttpResponse(200, plistlib.dumps({"Response": {}}))
            return await fake_request("POST", url, **kwargs)

        with (
            patch.object(anisette_report, "asyncio", _ImmediateAsyncio),
            patch.object(
                account._http,
                "request",
                fake_request,
            ),
            patch.object(account._http, "post", fake_post),
        ):
            asyncio.run(run())

        expected = [
            _CLIENT_INFO,
            f"{_PLATFORM} <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>",
            f"{_PLATFORM} <com.apple.AOSKit/282 (com.apple.accountsd/113)>",
        ]
        for headers, client_info in zip(sent, expected, strict=True):
            self.assertEqual(
                [value for name, value in headers.items() if name.lower() == "x-mme-client-info"],
                [client_info],
            )
        self.assertEqual(
            sent[-1]["User-Agent"],
            _USER_AGENT.replace("akd/1.0", "com.apple.iCloudHelper/282", 1),
        )

    def test_current_anisette_api_and_state_round_trip(self) -> None:
        class CurrentAnisette:
            closed = False

            @classmethod
            def init(cls):
                return cls()

            @classmethod
            def from_json(cls, state):
                self.assertEqual(state, {"device": "fixture", "adi_pb": "fixture"})
                return cls()

            async def get_headers(self):
                return _MAC_HEADERS.copy()

            def to_json(self):
                return {"device": "fixture", "adi_pb": "fixture"}

            async def close(self):
                self.closed = True

        async def run():
            provider = LocalAnisetteProvider()
            headers = await provider.get_headers("user", "device")
            self.assertEqual(headers["X-Apple-I-MD-LU"], _MAC_HEADERS["X-Apple-I-MD-LU"])
            mapping = provider.to_json()
            await provider.close()
            assert provider._ani is not None
            self.assertTrue(provider._ani.closed)
            restored = LocalAnisetteProvider.from_json(mapping)
            self.assertEqual(await restored.get_headers("user", "device"), headers)
            await restored.close()

        with (
            patch.object(anisette_report, "_ANISETTE_CLASS", CurrentAnisette),
            patch.object(
                anisette_report,
                "asyncio",
                _ImmediateAsyncio,
            ),
        ):
            asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
