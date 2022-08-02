import optparse
from unittest import *
from http.client import HTTPMessage
from unittest.mock import *  # MagicMock, Mock
from email.policy import Compat32
from rhnpush import rhnpush_main
import sys
from optparse import OptionParser, Option


class TestUpload(TestCase):
    server_digest_hash = {
        "4ti2_1.6.7+ds-2build2_amd64.deb": [
            "sha256",
            "cd5b4348e7b76c2287a9476f3f3ef3911480fe8e872ac541ffb598186a9e9607",
        ],
        "cadabra_2.46-4_amd64.deb": [
            "sha256",
            "ece4eedf7a5c65396d136b5765226e2c8b10f268c744b0ab1fa2625e35384a00",
        ],
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

    files = [
        "/opt/mytools/4ti2_1.6.7+ds-2build2_amd64.deb",
        "/opt/mytools/cadabra_2.46-4_amd64.deb",
    ]

    options_table = [
        Option('-v', '--verbose', action='count', help='Increase verbosity',
               default=0),
        Option('-d', '--dir', action='store',
               help='Process packages from this directory'),
        Option('-c', '--channel', action='append',
               help='Manage this channel (specified by label)'),
        Option('-n', '--count', action='store',
               help='Process this number of headers per call', type='int'),
        Option('-l', '--list', action='store_true',
               help='Only list the specified channels'),
        Option('-r', '--reldir', action='store',
               help='Relative dir to associate with the file'),
        Option('-o', '--orgid', action='store',
               help='Org ID', type='int'),
        Option('-u', '--username', action='store',
               help='Use this username to connect to RHN/Satellite'),
        Option('-p', '--password', action='store',
               help='Use this password to connect to RHN/Satellite'),
        Option('-s', '--stdin', action='store_true',
               help='Read the package names from stdin'),
        Option('-X', '--exclude', action='append',
               help='Exclude packages that match this glob expression'),
        Option('--force', action='store_true',
               help='Force the package upload (overwrites if already uploaded)'),
        Option('--nosig', action='store_true', help='Push unsigned packages'),
        Option('--newest', action='store_true',
               help='Only push the packages that are newer than the server ones'),
        Option('--nullorg', action='store_true', help='Use the null org id'),
        Option('--header', action='store_true',
               help='Upload only the header(s)'),
        Option('--source', action='store_true',
               help='Upload source package information'),
        Option('--server', action='store',
               help='Push to this server (http[s]://<hostname>/APP)'),
        Option('--proxy', action='store',
               help='Use proxy server (<server>:<port>)'),
        Option('--test', action='store_true',
               help='Only print the packages to be pushed'),
        Option('-?', '--usage', action='store_true',
               help='Briefly describe the options'),
        Option('-N', '--new-cache', action='store_true',
               help='Create a new username/password cache'),
        Option('--extended-test', action='store_true',
               help='Perform a more verbose test'),
        Option('--no-session-caching', action='store_true',
               help='Disables session-token authentication.'),
        Option('--tolerant', action='store_true',
               help='If rhnpush errors while uploading a package, continue uploading the rest of the packages.'),
        Option('--ca-chain', action='store', help='alternative SSL CA Cert'),
        Option('--timeout', action='store', type='int', metavar='SECONDS',
               help='Change default connection timeout.')
            ]

    @staticmethod
    def parse_args():
        optparser = OptionParser(option_list=TestUpload.options_table)
        testargs = [
            "--ca-chain=/etc/pki/trust/anchors/LOCAL-RHN-ORG-TRUSTED-SSL-CERT",
            "-c",
            "custom-deb-tools",
            "--server",
            "uyuni-srv-2206",
            "--dir",
            "/opt/mytools/",
        ]
        (options, args) = optparser.parse_args(testargs)
        return options, args

    def setUp(self):
        self._upload = rhnpush_main.UploadClass(None)

    @patch("rhnpush.rhnpush_main.UploadClass.authenticate", MagicMock())
    @patch(
        "rhnpush.rhnpush_v2.PingPackageUpload.ping", Mock(return_value=[200, "OK", headerinfo])
    )
    @patch(
        "rhnpush.rhnpush_main.UploadClass.packages", MagicMock()
    )
    #@patch("rhnpush.rhnpush_main.UploadClass.directory", MagicMock())
    @patch("rhnpush.uploadLib.listdir", MagicMock(return_value=['packet.rpm', 'packet.deb']))
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

    """
    @patch("rhnpush_main.UploadClass.authenticate", MagicMock)
    @patch(
        "rhnpush_v2.PingPackageUpload.ping", Mock(return_value=[200, "OK", http_headers])
    )
    @patch(
        "rhnpush_main.UploadClass.check_package_exists", Mock(return_value=(server_digest_hash, pkgs_info, digest_hash))
    )
    @patch("rhnpush_confmanager.ConfManager.get_config", TestUpload.parse_args()
    )
    def test_package(self):
        with patch(
            "uploadLib.call", Mock(return_value=0)
        ) as submit, patch('optparse.OptionParser.parse_args', Mock(return_value=TestUpload.parse_args())):
            import pdb; pdb.set_trace()
            self._upload.packages()
            assert submit.called
    """

    # @patch("rhnpush.rhnpush_main.UploadClass.authenticate", MagicMock())
    @patch(
        "rhnpush.rhnpush_v2.PingPackageUpload.ping", Mock(return_value=[200, "OK", http_headers])
    )
    @patch("rhnpush.uploadLib.listdir", MagicMock(return_value=['packet.rpm', 'packet.deb']))
    @patch("rhnpush.rhnpush_cache.RHNPushSession", MagicMock())
    @patch("up2date_client.rhnserver.RhnServer", MagicMock())
    #@patch("uyuni.common.rhn_pkg.package_from_filename", MagicMock())
    @patch(
        "rhnpush.rhnpush_main.UploadClass.check_package_exists", Mock(return_value=(server_digest_hash, pkgs_info, digest_hash))
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
            "admin"
        ]
        with patch.object(sys, "argv", testargs), patch(
                "rhnpush.uploadLib.call", Mock(side_effect=["83x09d549bd717d63cc46c3750474a4122c3508bd3c5cae8915f8275b7d9f1cd2c0",0])
        ) as submit:

            optionParser = OptionParser(option_list=TestUpload.options_table, usage="%prog [OPTION] [<package>]")
            from rhnpush import rhnpush_confmanager
            true_list = ['usage', 'test', 'source', 'header', 'nullorg', 'newest',
                         'nosig', 'force', 'list', 'stdin', 'new_cache',
                         'extended_test', 'no_session_caching', 'tolerant']
            manager = rhnpush_confmanager.ConfManager(optionParser, true_list)
            options = manager.get_config()
            #self._upload.directory()
            self._upload.options = options

            if options.usage:
                optionParser.print_usage()
                sys.exit(0)

            if options.list:
                if not options.channel:
                    self._upload.die(1, "Must specify a channel for --list to work")
                self._upload.list()
                return

            if options.dir and not options.stdin:
                self._upload.directory()

            elif options.stdin and not options.dir:
                self._upload.readStdin()

            elif options.dir and options.stdin:
                self._upload.readStdin()
                self._upload.directory()

            if options.exclude:
                self._upload.filter_excludes()

            if options.newest:
                if not options.channel:
                    self._upload.die(1, "Must specify a channel for --newest to work")

                self._upload.newest()

            if not self._upload.files:
                if self._upload.newest:
                    print("No new files to upload; exiting")
                else:
                    print("Nothing to do (try --help for more options)")
                sys.exit(0)

            if options.test:
                self._upload.test()
                return

            if options.extended_test:
                self._upload.extended_test()
                return

            if options.header:
                self._upload.uploadHeaders()
                return

            self._upload.packages()
            assert submit.called

