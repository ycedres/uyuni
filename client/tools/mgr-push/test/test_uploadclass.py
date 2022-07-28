from unittest import *
from http.client import HTTPMessage
from unittest.mock import *  # MagicMock, Mock
from email.policy import Compat32
from rhnpush.rhnpush_main import UploadClass


class Testing(TestCase):

    def setUp(self):
        self._headerinfo = {'policy': Compat32(),
                            '_headers': [('Date',
                                          'Mon, 25 Jul 2022 10:48:01 GMT'),
                                         ('Server', 'Apache'),
                                         ('X-Frame-Options', 'SAMEORIGIN'),
                                         ('Content-Length', '0'),
                                         ('X-RHN-Check-Package-Exists', '1'),
                                         ('Cache-Control', 'no-cache,no-store,must-revalidate,private'),
                                         ('Pragma', 'no-cache'),
                                         ('Expires', '0'),
                                         ('Content-Security-Policy', "default-src 'self' https: wss: ; "
                                                                     "script-src 'self' https: 'unsafe-inline' 'unsafe-eval'; "
                                                                     "img-src 'self' https: data: ;"
                                                                     "style-src 'self' https: 'unsafe-inline' "),
                                         ('X-XSS-Protection', '1; mode=block'),
                                         ('X-Content-Type-Options', 'nosniff'),
                                         ('X-Permitted-Cross-Domain-Policies', 'master-only'),
                                         ('Content-Type', 'text/xml')],
                            '_unixfrom': None,
                            '_payload': '',
                            '_charset': None,
                            'preamble': None,
                            'epilogue': None,
                            'defects': [],
                            '_default_type': 'text/plain'}
        #self.options.channel = ['test-channel']
        self.server.__dict__ = {'_uri': 'http://uyuni-srv-2206/APP', '_refreshCallback': None,
                                '_progressCallback': None, '_bufferSize': None, '_proxy': None, '_username': None,
                                '_password': None, '_timeout': None, 'rpc_version': '4.3.44.3.4-11', '_type': 'http',
                                '_host': 'uyuni-srv-2206', '_handler': '/APP', '_allow_redirect': 1,
                                '_redirected': None, 'use_handler_path': 1,
                                '_transport': {'_use_builtin_types': False,
                                               '_transport_flags': {
                                                   'transfer': 1,
                                                   'encoding': 1},
                                               '_headers': {'x-info': [
                                                   'RPC Processor (C) Red Hat, Inc (version 4.3.44.3.4-11)'],
                                                   'x-client-version': '1',
                                                   'x-rhn-transport-capability': [
                                                       'follow-redirects=3']},
                                               'verbose': 0,
                                               'connection': None,
                                               'method': 'POST',
                                               '_lang': None,
                                               'refreshCallback': None,
                                               'progressCallback': None,
                                               'bufferSize': 16384,
                                               'headers_in': self._headerinfo,
                                               'response_status': 200,
                                               'response_reason': 'OK',
                                               '_redirected': None,
                                               '_use_datetime': None,
                                               'timeout': None},
                                '_trusted_cert_files': ['/etc/pki/trust/anchors/LOCAL-RHN-ORG-TRUSTED-SSL-CERT'],
                                '_lang': None, '_encoding': None, '_verbose': 0, 'send_handler': None, '_headers': {}}
        self.files = ['/opt/mytools/4ti2_1.6.7+ds-2build2_amd64.deb', '/opt/mytools/cadabra_2.46-4_amd64.deb']
        self._upload = UploadClass(None)

    @patch('UploadClass.authenticate', MagicMock)
    @patch('rhnpush_v2.PingPackageUpload', MagicMock)
    def test_package(self):
        patch('rhnpush_v2.PingPackageUpload.ping', Mock(return_value=[200, 'OK', self._headerinfo]))
        patch()
        server_digest_hash = {'4ti2_1.6.7+ds-2build2_amd64.deb': ['sha256', 'cd5b4348e7b76c2287a9476f3f3ef3911480fe8e872ac541ffb598186a9e9607'], 'cadabra_2.46-4_amd64.deb': ['sha256', 'ece4eedf7a5c65396d136b5765226e2c8b10f268c744b0ab1fa2625e35384a00']}
        pkgs_info = {'4ti2_1.6.7+ds-2build2_amd64.deb': {'name': '4ti2', 'version': '1.6.7+ds', 'release': '2build2', 'epoch': '', 'arch': 'amd64-deb', 'checksum_type': 'sha256', 'checksum': 'cd5b4348e7b76c2287a9476f3f3ef3911480fe8e872ac541ffb598186a9e9607'}, 'cadabra_2.46-4_amd64.deb': {'name': 'cadabra', 'version': '2.46', 'release': '4', 'epoch': '', 'arch': 'amd64-deb', 'checksum_type': 'sha256', 'checksum': 'ece4eedf7a5c65396d136b5765226e2c8b10f268c744b0ab1fa2625e35384a00'}}
        digest_hash = {'4ti2_1.6.7+ds-2build2_amd64.deb': ('sha256', 'cd5b4348e7b76c2287a9476f3f3ef3911480fe8e872ac541ffb598186a9e9607'), 'cadabra_2.46-4_amd64.deb': ('sha256', 'ece4eedf7a5c65396d136b5765226e2c8b10f268c744b0ab1fa2625e35384a00')}
        patch('UploadClass.check_package_exists', (server_digest_hash, pkgs_info, digest_hash))
        patch('uploadLib.call', Mock(return_value=0))
        patch('rhnpush_confmanager.ConfManager.get_config', MagicMock)
        with patch('uploadLib.call', Mock(return_value=0)) as submit:
            self._upload.packages()
            assert submit.called

