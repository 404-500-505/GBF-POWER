import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INSTALL = ROOT / 'deploy/gateway/install.sh'
SERVICE = ROOT / 'deploy/systemd/gbf-gateway.service'
ADD_GATEWAY = ROOT / 'deploy/multinode/Add-Gateway.ps1'


class GatewayInstallContractTests(unittest.TestCase):
    def test_keys_are_generated_on_target_with_private_permissions(self):
        text = INSTALL.read_text(encoding='utf-8')
        self.assertIn('ssh-keygen', text)
        self.assertIn('/usr/sbin/nologin', text)
        self.assertIn('chmod 0600', text)
        self.assertNotIn('--private-key', text)

    def test_config_requires_control_certificate_pin_and_explicit_capacity(self):
        text = INSTALL.read_text(encoding='utf-8')
        for option in ('--node-id', '--control-url', '--control-cert-sha256', '--capacity-bps'):
            self.assertIn(option, text)
        self.assertIn('check-gateway-config --config', text)

    def test_installer_outputs_public_keys_only(self):
        text = INSTALL.read_text(encoding='utf-8')
        self.assertIn('HOST_PUBLIC_KEY=', text)
        self.assertIn('NODE_PUBLIC_KEY=', text)
        self.assertNotRegex(text, r'cat\s+[^\n]*(?:node_ed25519|ssh_host_ed25519_key)(?:\s|$)')

    def test_systemd_uses_dedicated_gateway_account(self):
        text = SERVICE.read_text(encoding='utf-8')
        self.assertIn('User=gbf-gateway', text)
        self.assertIn('Group=gbf-gateway', text)
        self.assertIn('gateway --config /etc/gbf-power/gateway/config.json', text)
        self.assertIn('NoNewPrivileges=true', text)

    def test_multinode_script_has_no_baked_in_remote_or_private_key_download(self):
        text = ADD_GATEWAY.read_text(encoding='utf-8')
        self.assertIn('ParametersFile', text)
        self.assertIn('ConvertFrom-Json', text)
        self.assertIn('HOST_PUBLIC_KEY', text)
        self.assertIn('NODE_PUBLIC_KEY', text)
        self.assertNotRegex(text, r'\b(?:scp|sftp)\b[^\n]*(?:node_ed25519|ssh_host_ed25519_key)(?!\.pub)')
        self.assertNotIn('root@', text)
        self.assertNotIn('C:\\Users\\', text)


if __name__ == '__main__':
    unittest.main()
