import optparse
from unittest import *
from http.client import HTTPMessage
from unittest.mock import *  # MagicMock, Mock
from email.policy import Compat32
from rhnpush import rhnpush_main
from rhnpush import rhnpush_config
import sys
from optparse import OptionParser, Option


class TestUpload(TestCase):

    config = {
        "options_defaults": {
            "newest": "0",
            "usage": "0",
            "header": "0",
            "test": "0",
            "nullorg": "0",
            "source": "0",
            "stdin": "0",
            "verbose": "0",
            "force": "0",
            "nosig": "0",
            "list": "0",
            "exclude": "",
            "files": "",
            "orgid": "",
            "reldir": "",
            "count": "",
            "dir": "",
            "server": "http://rhn.redhat.com/APP",
            "channel": "",
            "cache_lifetime": "600",
            "new_cache": "0",
            "extended_test": "0",
            "no_session_caching": "0",
            "proxy": "",
            "tolerant": "0",
            "ca_chain": "/usr/share/rhn/RHN-ORG-TRUSTED-SSL-CERT",
            "timeout": None,
        },
        "settings": Mock(),
        "section": "rhnpush",
        "username": None,
        "password": None,
        "newest": True,
        "usage": None,
        "header": None,
        "test": None,
        "nullorg": None,
        "source": None,
        "stdin": None,
        "verbose": 0,
        "force": None,
        "nosig": None,
        "list": None,
        "exclude": [""],
        "files": [],
        "orgid": "",
        "reldir": "",
        "count": "",
        "dir": "/opt/mytools/",
        "server": "uyuni-srv-2206",
        "channel": ["custom-deb-tools"],
        "cache_lifetime": 600,
        "new_cache": None,
        "extended_test": None,
        "no_session_caching": None,
        "proxy": "",
        "tolerant": None,
        "ca_chain": "/etc/pki/trust/anchors/LOCAL-RHN-ORG-TRUSTED-SSL-CERT",
        "timeout": 300,
    }

    server_digest_hash = {
        "4ti2_1.6.7+ds-2build2_amd64.deb": [
            "sha256",
            "cd5b4348e7b76c2287a9476f3f3ef3911480fe8e872ac541ffb598186a9e9607",
        ],
        "cadabra_2.46-4_amd64.deb": "",
    }

    pkgs_info = {
        "4ti2_1.6.7+ds-2build2_amd64.deb": {
            "name": "4ti2",
            "version": "1.6.7+ds",
            "release": "2build2",
            "epoch": "",
            "arch": "amd64-deb",
            "checksum_type": "sha256",
            "checksum": "cd5b4348e7b76c2287a9476f3f3ef3911480fe8e872ac541ffb598186a9e9607",
        },
        "cadabra_2.46-4_amd64.deb": {
            "name": "cadabra",
            "version": "2.46",
            "release": "4",
            "epoch": "",
            "arch": "amd64-deb",
            "checksum_type": "sha256",
            "checksum": "ece4eedf7a5c65396d136b5765226e2c8b10f268c744b0ab1fa2625e35384a00",
        },
    }

    digest_hash = {
        "4ti2_1.6.7+ds-2build2_amd64.deb": (
            "sha256",
            "cd5b4348e7b76c2287a9476f3f3ef3911480fe8e872ac541ffb598186a9e9607",
        ),
        "cadabra_2.46-4_amd64.deb": (
            "sha256",
            "ece4eedf7a5c65396d136b5765226e2c8b10f268c744b0ab1fa2625e35384a00",
        ),
    }

    headerinfo = {
        "policy": Compat32(),
        "_headers": [
            ("Date", "Mon, 25 Jul 2022 10:48:01 GMT"),
            ("Server", "Apache"),
            ("X-Frame-Options", "SAMEORIGIN"),
            ("Content-Length", "0"),
            ("X-RHN-Check-Package-Exists", "1"),
            ("Cache-Control", "no-cache,no-store,must-revalidate,private"),
            ("Pragma", "no-cache"),
            ("Expires", "0"),
            (
                "Content-Security-Policy",
                "default-src 'self' https: wss: ; "
                "script-src 'self' https: 'unsafe-inline' 'unsafe-eval'; "
                "img-src 'self' https: data: ;"
                "style-src 'self' https: 'unsafe-inline' ",
            ),
            ("X-XSS-Protection", "1; mode=block"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Permitted-Cross-Domain-Policies", "master-only"),
            ("Content-Type", "text/xml"),
        ],
        "_unixfrom": None,
        "_payload": "",
        "_charset": None,
        "preamble": None,
        "epilogue": None,
        "defects": [],
        "_default_type": "text/plain",
    }
    http_headers = HTTPMessage()
    http_headers.__dict__ = headerinfo

    server = {
        "_uri": "http://uyuni-srv-2206/APP",
        "_refreshCallback": None,
        "_progressCallback": None,
        "_bufferSize": None,
        "_proxy": None,
        "_username": None,
        "_password": None,
        "_timeout": None,
        "rpc_version": "4.3.44.3.4-11",
        "_type": "http",
        "_host": "uyuni-srv-2206",
        "_handler": "/APP",
        "_allow_redirect": 1,
        "_redirected": None,
        "use_handler_path": 1,
        "_transport": {
            "_use_builtin_types": False,
            "_transport_flags": {"transfer": 1, "encoding": 1},
            "_headers": {
                "x-info": ["RPC Processor (C) Red Hat, Inc (version 4.3.44.3.4-11)"],
                "x-client-version": "1",
                "x-rhn-transport-capability": ["follow-redirects=3"],
            },
            "verbose": 0,
            "connection": None,
            "method": "POST",
            "_lang": None,
            "refreshCallback": None,
            "progressCallback": None,
            "bufferSize": 16384,
            "headers_in": headerinfo,
            "response_status": 200,
            "response_reason": "OK",
            "_redirected": None,
            "_use_datetime": None,
            "timeout": None,
        },
        "_trusted_cert_files": [
            "/etc/pki/trust/anchors/LOCAL-RHN-ORG-TRUSTED-SSL-CERT"
        ],
        "_lang": None,
        "_encoding": None,
        "_verbose": 0,
        "send_handler": None,
        "_headers": {},
    }

    def setUp(self):
        self._upload = rhnpush_main.UploadClass(None)

    def tearDown(self):
        pass

    @patch("rhnpush.rhnpush_main.UploadClass.authenticate", MagicMock())
    @patch(
        "rhnpush.rhnpush_v2.PingPackageUpload.ping",
        Mock(return_value=[200, "OK", headerinfo]),
    )
    @patch("rhnpush.rhnpush_main.UploadClass.packages", MagicMock())
    @patch(
        "rhnpush.uploadLib.listdir",
        MagicMock(return_value=["packet.rpm", "packet.deb"]),
    )
    def test_main(self):
        testargs = [
            "--ca-chain=/etc/pki/trust/anchors/LOCAL-RHN-ORG-TRUSTED-SSL-CERT",
            "-c",
            "custom-deb-tools",
            "--server",
            "uyuni-srv-2206",
            "--dir",
            "/opt/mytools/",
        ]
        with patch.object(sys, "argv", testargs), patch(
            "uploadLib.call", Mock(return_value=0)
        ):
            rhnpush_main.main()
            assert self._upload.packages.called

    @patch(
        "rhnpush.rhnpush_v2.PingPackageUpload.ping",
        Mock(return_value=[200, "OK", http_headers]),
    )
    @patch(
        "rhnpush.uploadLib.listdir",
        MagicMock(return_value=["cadabra_2.46-4_amd64.deb"]),
    )
    @patch("rhnpush.rhnpush_cache.RHNPushSession", MagicMock())
    @patch("up2date_client.rhnserver.RhnServer", MagicMock())
    @patch(
        "rhnpush.rhnpush_main.UploadClass.check_package_exists",
        Mock(return_value=(server_digest_hash, pkgs_info, digest_hash)),
    )
    def test_packages(self):
        testargs = [
            "--ca-chain=/etc/pki/trust/anchors/LOCAL-RHN-ORG-TRUSTED-SSL-CERT",
            "-c",
            "custom-deb-tools",
            "--server",
            "uyuni-srv-2206",
            "--dir",
            "/opt/mytools/",
            "--username",
            "admin",
            "--password",
            "admin",
        ]
        with patch.object(sys, "argv", testargs), patch(
            "rhnpush.uploadLib.call",
            Mock(
                side_effect=[
                    "83x09d549bd717d63cc46c3750474a4122c3508bd3c5cae8915f8275b7d9f1cd2c0",
                    0,
                ]
            ),
        ), patch(
            "rhnpush.rhnpush_main.UploadClass.package", Mock(return_value=0)
        ) as package:

            config_parser = rhnpush_config.rhnpushConfigParser()
            with (patch.dict(config_parser.__dict__, TestUpload.config)):
                self._upload.options = config_parser

                if self._upload.options.dir and not self._upload.options.stdin:
                    self._upload.directory()

                elif self._upload.options.stdin and not self._upload.options.dir:
                    self._upload.readStdin()

                elif self._upload.options.dir and self._upload.options.stdin:
                    self._upload.readStdin()
                    self._upload.directory()

                self._upload.packages()
                package.assert_called_with(
                    "cadabra_2.46-4_amd64.deb",
                    "sha256",
                    "ece4eedf7a5c65396d136b5765226e2c8b10f268c744b0ab1fa2625e35384a00",
                )
