"""Verify Grand Slam uses separate connections while other hosts retain pooling."""

import asyncio
import base64
import unittest
import warnings
from unittest.mock import patch

from aiohttp import TCPConnector, web
from aiohttp.abc import AbstractResolver

from findmy.util.http import HttpSession


class _LoopbackResolver(AbstractResolver):
    async def resolve(self, host, port=0, family=0):
        return [
            {
                "hostname": host,
                "host": "127.0.0.1",
                "port": port,
                "family": family,
                "proto": 0,
                "flags": 0,
            }
        ]

    async def close(self):
        pass


class ConnectionReuseTest(unittest.TestCase):
    def test_only_grand_slam_uses_a_new_connection_for_each_request(self):
        async def run():
            connections = []

            async def handler(request):
                expected_auth = (
                    "Basic " + base64.b64encode("fixture:pássword".encode("latin1")).decode()
                )
                self.assertEqual(request.headers.get("Authorization"), expected_auth)
                reused = any(request.transport is item for item in connections)
                connections.append(request.transport)
                return web.Response(status=429 if reused else 200)

            app = web.Application()
            app.router.add_post("/login", handler)
            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]

            def connector(**kwargs):
                return TCPConnector(resolver=_LoopbackResolver(), **kwargs)

            session = HttpSession()
            try:
                with patch("findmy.util.http.TCPConnector", connector), warnings.catch_warnings():
                    warnings.simplefilter("error", DeprecationWarning)
                    for host, expected in [
                        ("gsa.apple.com", [200, 200]),
                        ("setup.icloud.com", [200, 429]),
                    ]:
                        statuses = []
                        for _ in range(2):
                            response = await session.post(
                                f"http://{host}:{port}/login",
                                data=b"fixture",
                                auth=("fixture", "pássword"),
                            )
                            statuses.append(response.status_code)
                        self.assertEqual(statuses, expected)
                clients = (session._session, session._unpooled)
                await session.close()
                self.assertTrue(all(client.closed for client in clients))
                with self.assertRaises(RuntimeError):
                    await session._get_session("https://gsa.apple.com")
            finally:
                await session.close()
                await runner.cleanup()

        asyncio.run(run())
