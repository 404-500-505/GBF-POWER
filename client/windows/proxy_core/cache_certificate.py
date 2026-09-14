"""Create a per-installation CDN-only leaf. The CA signing key is NEVER saved."""
import argparse
import csv
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import subprocess

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from asset_cache import ASSET_HOSTS


def protect_directory(directory):
    directory.mkdir(parents=True, exist_ok=True)
    if os.name == 'nt':
        flags = subprocess.CREATE_NO_WINDOW
        identity = subprocess.check_output(['whoami','/user','/fo','csv','/nh'],creationflags=flags).decode(errors='replace')
        sid = next(csv.reader(io.StringIO(identity.strip())))[1]
        subprocess.run(['icacls',str(directory),'/inheritance:r','/grant:r',f'*{sid}:(OI)(CI)F'],
                       check=True,stdout=subprocess.DEVNULL,creationflags=flags)
    else:
        directory.chmod(0o700)


def certificate_info(directory):
    ca = x509.load_pem_x509_certificate((directory/'ca.pem').read_bytes())
    leaf = x509.load_pem_x509_certificate((directory/'leaf.pem').read_bytes())
    return dict(thumbprint=ca.fingerprint(hashes.SHA1()).hex().upper(),
                sha256=ca.fingerprint(hashes.SHA256()).hex().upper(),
                expires=leaf.not_valid_after_utc.isoformat())


def prepare_certificate(directory):
    directory = Path(directory)
    protect_directory(directory)
    files = [directory/name for name in ('ca.pem','leaf.pem','leaf-key.pem')]
    if all(p.exists() for p in files):
        return certificate_info(directory)
    if any(p.exists() for p in files):
        raise RuntimeError('Incomplete cache certificate files; restore them before continuing. Nothing overwritten.')
    now = datetime.now(timezone.utc)
    expires = now+timedelta(days=365)
    ca_key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'GBF Local Asset Cache - Personal CA')])
    names = [x509.DNSName(host) for host in sorted(ASSET_HOSTS)]
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5)).not_valid_after(expires)
          .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
          .add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),critical=True)
          .add_extension(x509.NameConstraints(permitted_subtrees=names,excluded_subtrees=None),critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),critical=False)
          .sign(ca_key,hashes.SHA256()))
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'GBF Asset Cache')]))
            .issuer_name(name).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-timedelta(minutes=5)).not_valid_after(expires)
            .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
            .add_extension(x509.SubjectAlternativeName(names),critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),critical=False)
            .add_extension(x509.KeyUsage(True,False,True,False,False,False,False,False,False),critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),critical=False)
            .sign(ca_key,hashes.SHA256()))
    # Create exclusively; no CA private-key serialization at any point.
    contents = [ca.public_bytes(serialization.Encoding.PEM), leaf.public_bytes(serialization.Encoding.PEM),
                leaf_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())]
    for path, data in zip(files,contents):
        with path.open('xb') as file:
            file.write(data)
        if os.name != 'nt':
            path.chmod(0o600)
    return certificate_info(directory)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory',type=Path,default=Path(__file__).resolve().parent/'runtime/cache-tls')
    args = parser.parse_args()
    print(json.dumps(prepare_certificate(args.directory)))
