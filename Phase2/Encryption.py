import os
import base64
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import datetime, timedelta


class Encryption:

    @staticmethod
    def encrypt_file(file_path, password):
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        fernet = Fernet(key)
        with open(file_path, 'rb') as file:
            file_contents = file.read()
        encrypted_contents = fernet.encrypt(file_contents)
        with open(file_path + '.encrypted', 'wb') as encrypted_file:
            encrypted_file.write(salt + encrypted_contents)

    @staticmethod
    def decrypt_file(file_path, password):
        with open(file_path, 'rb') as encrypted_file:
            salt = encrypted_file.read(16)
            encrypted_contents = encrypted_file.read()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        fernet = Fernet(key)
        decrypted_contents = fernet.decrypt(encrypted_contents)
        with open(file_path[:-9], 'wb') as decrypted_file:
            decrypted_file.write(decrypted_contents)

    @staticmethod
    def generate_private_key(path, password):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        with open(path + '/private_key.pem', 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        Encryption.encrypt_file(path + '/private_key.pem', password)
        os.remove(path + '/private_key.pem')

        return private_key

    @staticmethod
    def generate_csr(ID, private_key):
        csr = x509.CertificateSigningRequestBuilder() \
            .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'California'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u'San Francisco'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ID),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'IT'),
            x509.NameAttribute(NameOID.COMMON_NAME, ID),
        ])) \
            .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(ID)]),
            critical=False,
        ) \
            .sign(private_key, hashes.SHA256())

        with open(ID + '/' + ID + '.pem', 'wb') as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))

        return csr

    @staticmethod
    def generate_root_certificate(private_key):
        public_key = private_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, u'US'),
            x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, u'California'),
            x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, u'San Francisco'),
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, u'My Company'),
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u'Root CA'),
        ]))
        builder = builder.issuer_name(x509.Name([
            # its issuer is itself
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, u'US'),
            x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, u'California'),
            x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, u'San Francisco'),
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, u'My Company'),
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u'Root CA'),
        ]))
        builder = builder.not_valid_before(datetime.utcnow())
        builder = builder.not_valid_after(datetime.utcnow() + timedelta(days=10 * 365))  # Valid for 10 years
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        )
        # Self-sign our certificate
        ca_certificate = builder.sign(
            private_key=private_key, algorithm=hashes.SHA256(),
            backend=default_backend()
        )

        with open('SecretFiles/CA.crt', 'wb') as f:
            f.write(ca_certificate.public_bytes(serialization.Encoding.DER))

        with open('ActiveDirectory/CA.crt', 'wb') as f:
            f.write(ca_certificate.public_bytes(serialization.Encoding.DER))

        return ca_certificate

    @staticmethod
    def sign_csr(certificate, private_key, csr, cert_path):
        # Generate the certificate signing the CSR with the CA's private key
        cert = x509.CertificateBuilder() \
            .subject_name(csr.subject) \
            .issuer_name(certificate.subject) \
            .public_key(csr.public_key()) \
            .serial_number(x509.random_serial_number()) \
            .not_valid_before(certificate.not_valid_before_utc) \
            .not_valid_after(certificate.not_valid_after_utc) \
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True) \
            .sign(private_key, hashes.SHA256(), default_backend())

        with open(cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.DER))

        return cert

    @staticmethod
    def load_csr(csr_path):
        with open(csr_path, 'rb') as file:
            csr = file.read()
            return csr

    @staticmethod
    def load_certificate(file_path):
        with open(file_path, 'rb') as file:
            cert_data = file.read()
        certificate = x509.load_der_x509_certificate(cert_data, default_backend())
        return certificate

    @staticmethod
    def load_certificate_as_byte(file_path):
        with open(file_path, 'rb') as file:
            certificate = file.read()
        return certificate

    @staticmethod
    def load_private_key(path, password):
        Encryption.decrypt_file(path + '/private_key.pem' + '.encrypted', password)
        with open(path + '/private_key.pem', 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        os.remove(path + '/private_key.pem')
        return private_key

    @staticmethod
    def sign_message(private_key, message):
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return message + b'||' + signature

    @staticmethod
    def verify_message_signature(public_key, signature, message):
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except InvalidSignature:
            print("Signature is invalid")

    @staticmethod
    def get_public_key(cert_path):
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
        cert = x509.load_der_x509_certificate(cert_data)
        public_key = cert.public_key()
        return public_key

    @staticmethod
    def encrypt_message(public_key, message):
        chunk_size = 190
        encrypted_chunks = []
        for i in range(0, len(message), chunk_size):
            chunk = message[i:i + chunk_size]
            encrypted_chunk = public_key.encrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            encrypted_chunks.append(encrypted_chunk)
        return b'||'.join(encrypted_chunks)

    @staticmethod
    def decrypt_message(private_key, encrypted_message):
        encrypted_chunks = encrypted_message.split(b'||')
        decrypted_chunks = []
        for encrypted_chunk in encrypted_chunks:
            decrypted_chunk = private_key.decrypt(
                encrypted_chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            decrypted_chunks.append(decrypted_chunk)
        return b''.join(decrypted_chunks)