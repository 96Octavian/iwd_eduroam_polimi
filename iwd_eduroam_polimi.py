#!/usr/bin/env python3
import argparse
import getpass
import cryptography.hazmat.primitives.serialization.pkcs12 as pk
import cryptography.hazmat.primitives.serialization as ser
import sys
import os
from typing import Tuple


CERTIFICATE_FILENAME: str = "eduroam.pem"
KEY_FILENAME: str = "eduroam.key"
SYSTEM_CERTS_DIRECTORY: str = "/etc/ssl/certs"

IWD_EDUROAM_CONFIGURATION_FILENAME: str = "eduroam.8021x"
IWD_POLIMIPROTECTED_CONFIGURATION_FILENAME: str = "polimi-protected.8021x"
IWD_CONFIGURATION_DIRECTORY: str = "/var/lib/iwd"
IWD_FILE_TEMPLATE = """[Security]
EAP-Method=TLS
EAP-TLS-CACert={certfile_destination}
EAP-TLS-ClientCert={certfile_destination}
EAP-TLS-ClientKey={keyfile_destination}
EAP-Identity={username}@polimi.it

[Settings]
AutoConnect=True
"""
BAG_ATTRIBUTE_TEMPLATE = """Bag Attributes
    friendlyName: {friendlyName}
subject={subject}

issuer={issuer}

"""


def generate_iwd_configuration(certfile_destination, keyfile_destination, username):
    return IWD_FILE_TEMPLATE.format(
        certfile_destination=certfile_destination,
        keyfile_destination=keyfile_destination,
        username=username
    )


def generate_bag_attribute(subject, issuer):
    return BAG_ATTRIBUTE_TEMPLATE.format(
        friendlyName=subject,
        subject=', '.join(subject.replace('=', ' = ').split(',')[::-1]),
        issuer=', '.join(issuer.replace('=', ' = ').split(',')[::-1])
    )


def install(
    p12_certificate_path: str,
    username: str,
    password: str,
    install_system_wide: bool
) -> None:
    private_key = None
    certificate = None
    additional_certificates = None
    try:
        with open(p12_certificate_path, "rb") as certificate_file:
            private_key, cert, additional_certs = pk.load_key_and_certificates(
                certificate_file.read(),
                password.encode()
            )
    except FileNotFoundError:
        print(f"Could not find certificate file at {p12_certificate_path}")
        sys.exit(1)
    except PermissionError:
        print(
            f"Permission error trying to read file at {p12_certificate_path}")
        sys.exit(1)

    certs_destination: str = '.'
    iwdfile_destination: str = '.'
    if install_system_wide:
        if os.path.exists(os.path.join(SYSTEM_CERTS_DIRECTORY, KEY_FILENAME)):
            print(f"Key {KEY_FILENAME} already exists in "
                  f"{SYSTEM_CERTS_DIRECTORY}, files will only be created in "
                  "current directory")
        elif os.path.exists(
                os.path.join(SYSTEM_CERTS_DIRECTORY, CERTIFICATE_FILENAME)):
            print(f"Certificate {CERTIFICATE_FILENAME} already exists in "
                  f"{SYSTEM_CERTS_DIRECTORY}, files will only be created in "
                  "current directory")
        elif os.path.exists(
            os.path.join(
                IWD_CONFIGURATION_DIRECTORY,
                IWD_EDUROAM_CONFIGURATION_FILENAME
            )
        ):
            print(f"Configuration file {IWD_EDUROAM_CONFIGURATION_FILENAME} "
                  f"already exists in {IWD_CONFIGURATION_DIRECTORY}, files "
                  "will only be created in current directory")
        elif os.path.exists(
            os.path.join(
                IWD_CONFIGURATION_DIRECTORY,
                IWD_POLIMIPROTECTED_CONFIGURATION_FILENAME
            )
        ):
            print("Configuration file "
                  f"{IWD_POLIMIPROTECTED_CONFIGURATION_FILENAME} already "
                  f"exists in {IWD_CONFIGURATION_DIRECTORY}, files will only "
                  "be created in current directory")
        else:
            certs_destination = SYSTEM_CERTS_DIRECTORY
            iwdfile_destination = IWD_CONFIGURATION_DIRECTORY

        if certs_destination != SYSTEM_CERTS_DIRECTORY:
            print("Files will be generated in the current directory.")
            print(f"To install them, manually place {KEY_FILENAME} and "
                  f"{CERTIFICATE_FILENAME} in {SYSTEM_CERTS_DIRECTORY}, and "
                  f"{IWD_EDUROAM_CONFIGURATION_FILENAME} and "
                  f"{IWD_POLIMIPROTECTED_CONFIGURATION_FILENAME} in "
                  f"{IWD_CONFIGURATION_DIRECTORY}")
            print("")

    keyfile_destination = os.path.join(certs_destination, KEY_FILENAME)
    with open(keyfile_destination, "wb") as keyfile_output:
        keyfile_output.write(
            private_key.private_bytes(
                encoding=ser.Encoding.PEM,
                format=ser.PrivateFormat.PKCS8,
                encryption_algorithm=ser.NoEncryption()
            )
        )
        keyfile_output.flush()
    print(f"Key written to {keyfile_destination}")

    certfile_destination = os.path.join(
        certs_destination, CERTIFICATE_FILENAME)
    with open(certfile_destination, "wb") as certfile_output:
        certfile_output.write(certificate.public_bytes(ser.Encoding.PEM))
        for additional_certificate in additional_certificates:
            certfile_output.write(
                generate_bag_attribute(
                    additional_certificate.subject.rfc4514_string(),
                    additional_certificate.issuer.rfc4514_string()
                ).encode()
            )
            certfile_output.write(
                additional_certificate.public_bytes(ser.Encoding.PEM)
            )
        certfile_output.flush()
    print(f"Certificate written to {certfile_destination}")

    iwd_eduroam_destination = os.path.join(
        iwdfile_destination, IWD_EDUROAM_CONFIGURATION_FILENAME)
    with open(iwd_eduroam_destination, "w") as iwd_output:
        iwd_configuration = generate_iwd_configuration(
            certfile_destination, keyfile_destination, username)
        iwd_output.write(iwd_configuration)
        iwd_output.flush()
    print(f"iwd eduroam configuration written to {iwd_eduroam_destination}")

    iwd_polimiprotected_destination = os.path.join(
        iwdfile_destination, IWD_POLIMIPROTECTED_CONFIGURATION_FILENAME)
    with open(iwd_polimiprotected_destination, "w") as iwd_output:
        iwd_configuration = generate_iwd_configuration(
            certfile_destination, keyfile_destination, username)
        iwd_output.write(iwd_configuration)
        iwd_output.flush()
    print("iwd polimi-protected configuration written to "
          f"{iwd_polimiprotected_destination}")


def prepare_installer() -> Tuple[str, str, str, str]:
    username: str = str()
    p12_certificate_path: str = str()
    install_system_wide: bool = False
    parser = argparse.ArgumentParser(
        description=('Configure iwd for eduroam and polimi-protected with a '
                     'certificate.')
    )
    parser.add_argument(
        '--username',
        '-u',
        action='store',
        dest='username',
        help='polimi person code',
        required=True
    )
    parser.add_argument(
        '--certificate',
        '-c',
        action='store',
        dest='certificate_path',
        help='certificate .p12/.pfx file',
        required=True
    )
    parser.add_argument(
        '--install',
        '-i',
        default=False,
        action='store_true',
        dest='install',
        help=('install the generated files instead of just creating them in '
              'the local directory')
    )
    args = parser.parse_args()

    if args.install and not os.geteuid() == 0:
        print("To install the generated configuration and certificates in "
              "your system, run this script with sudo")
        sys.exit(1)

    username = args.username
    p12_certificate_path = args.certificate_path
    install_system_wide = args.install

    password: str = str()
    while not password:
        password = getpass.getpass("Certificate import password: ")
        if not password:
            print("Empty password not allowed.")

    return p12_certificate_path, username, password, install_system_wide


if __name__ == '__main__':
    path, user, password, system_wide = prepare_installer()
    install(path, user, password, system_wide)
