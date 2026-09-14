import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INSTALL = ROOT / 'deploy/control/install.sh'
SERVICE = ROOT / 'deploy/systemd/gbf-control.service'


class ControlInstallContractTests(unittest.TestCase):
    def test_installer_exists_and_accepts_only_explicit_inputs(self):
        text = INSTALL.read_text(encoding='utf-8')
        for option in ('--binary', '--config', '--tls-cert', '--tls-key'):
            self.assertIn(option, text)
        self.assertIn('readlink -f', text)
        self.assertNotIn('192.0.2.', text)

    def test_installer_uses_dedicated_locked_down_account(self):
        text = INSTALL.read_text(encoding='utf-8')
        self.assertIn('useradd --system', text)
        self.assertIn('--shell /usr/sbin/nologin', text)
        self.assertIn('-m 0700', text)
        self.assertIn('-m 0600', text)

    def test_installer_checks_staged_config_and_preserves_state(self):
        text = INSTALL.read_text(encoding='utf-8')
        self.assertIn('check-config --config', text)
        self.assertIn('mktemp -d', text)
        self.assertNotRegex(text, r'rm\s+-[^\n]*\bstate\.json\b')

    def test_systemd_runs_as_service_user_and_has_no_tcp_admin_port(self):
        text = SERVICE.read_text(encoding='utf-8')
        self.assertIn('User=gbf-control', text)
        self.assertIn('Group=gbf-control', text)
        self.assertIn('serve --config /etc/gbf-power/control/config.json', text)
        self.assertNotIn('--admin', text)
        self.assertIn('NoNewPrivileges=true', text)


if __name__ == '__main__':
    unittest.main()
