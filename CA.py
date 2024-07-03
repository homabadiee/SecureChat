import threading
import socket

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding


class CA:

    def __init__(self):
        self.ID = 'CA'
        self.private_key = self.generate_private_key()
        self.certificate = self.generate_root_certificate()
        open('secret_files/group_id.txt', 'w')

    def add_group_id(self, group_id):
        with open('secret_files/group_id.txt', 'r') as file:
            for stored_group_id in file:
                if stored_group_id == group_id:
                    return False

        with open('secret_files/group_id.txt', 'a') as file:
            file.write(group_id)

        return True

    def generate_private_key(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )

        with open('secret_files/ca_private_key.pem', 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        return private_key

    def generate_root_certificate(self):
        public_key = self.private_key.public_key()
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
            private_key=self.private_key, algorithm=hashes.SHA256(),
            backend=default_backend()
        )


        with open('secret_files/CA.crt', 'wb') as f:
            f.write(ca_certificate.public_bytes(serialization.Encoding.DER))

        with open('ActiveDirectory/CA.crt', 'wb') as f:
            f.write(ca_certificate.public_bytes(serialization.Encoding.DER))

        return ca_certificate

    def sign_csr(self, csr, output_cert):
        # Generate the certificate signing the CSR with the CA's private key
        certificate = x509.CertificateBuilder() \
            .subject_name(csr.subject) \
            .issuer_name(self.certificate.subject) \
            .public_key(csr.public_key()) \
            .serial_number(x509.random_serial_number()) \
            .not_valid_before(self.certificate.not_valid_before_utc) \
            .not_valid_after(self.certificate.not_valid_after_utc) \
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True) \
            .sign(self.private_key, hashes.SHA256(), default_backend())

        with open(output_cert, 'wb') as f:
            f.write(certificate.public_bytes(serialization.Encoding.DER))

        return certificate

    def find_user_role(self, user_ID):
        with open('secret_files/database.txt', 'r') as file:
            for line in file:
                parts = line.strip().split(",")
                email, s_user_ID, salt, hashed_password, role = parts
                if s_user_ID == user_ID:
                    return role


    def send_certificate(self, client_socket, cert_path):
        try:
            with open(cert_path, 'rb') as file:
                cert = file.read()
                client_socket.send('1'.encode('utf-8'))
                client_socket.recv(3)
                client_socket.sendall(cert)
        except FileNotFoundError:
            client_socket.send('4'.encode('utf-8'))

    def load_certificate(self, file_path):
        with open(file_path, 'rb') as file:
            certificate = file.read()
        return certificate

    def load_csr(self, file_path):
        with open(file_path, 'rb') as csr_file:
            csr_data = csr_file.read()
            csr = x509.load_pem_x509_csr(csr_data, default_backend())
        return csr

    def receive_csr(self, client, file_size):
        csr = client.recv(int(file_size))
        csr = x509.load_pem_x509_csr(csr, default_backend())
        return csr

    def get_public_key(self, cert_path):
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
        cert = x509.load_der_x509_certificate(cert_data)
        public_key = cert.public_key()
        return public_key

    def sign_message(self, message):
        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return message + b'||' + signature

    def verify_message_signature(self, public_key, signature, message):
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

    def process_request(self, client):
        request = client.recv(1024)
        message, signature = request.rsplit(b'||', 1)
        flag, sender_ID, _ = request.split(b'||', 2)
        flag = flag.decode('utf-8')
        sender_ID = sender_ID.decode('utf-8')
        if flag == '0':  # certificate request
            client.send('0'.encode('utf-8'))  # waiting for CSR
            csr_size = client.recv(1024).decode('utf-8')
            csr = self.receive_csr(client, csr_size)
            cert_path = 'secret_files/' + sender_ID + '.crt'
            self.sign_csr(csr, cert_path)

        else:
            cert_path = 'secret_files/' + sender_ID + '.crt'

            try:
                public_key = self.get_public_key(cert_path)
                self.verify_message_signature(public_key, signature, message)

                if flag == '1':
                    _, _, req_ID = message.split(b'||', 2)
                    req_ID = req_ID.decode('utf-8')
                    cert_path = 'secret_files/' + req_ID + '.crt'
                    self.send_certificate(client, cert_path)

                elif flag == '2':
                    _, _, group_ID = message.split(b'||', 2)
                    group_ID = group_ID.decode('utf-8')
                    if self.add_group_id(group_ID):
                        if self.find_user_role(sender_ID) == 'superadmin':
                            port = '8000'
                            gp_info = f"{group_ID}:{port}".encode('utf-8')
                            signed_gp_info = self.sign_message(gp_info)
                            cert_path = 'secret_files/' + sender_ID + '.crt'
                            cert = self.load_certificate(cert_path)
                            client.send('1'.encode('utf-8'))
                            client.sendall(cert + b'||' + signed_gp_info)

                        else:  # not allowed creating group
                            client.send('2'.encode('utf-8'))
                    else:  # repetitive group ID
                        client.send('5'.encode('utf-8'))
            except FileNotFoundError:  # invalid sender ID
                client.send('3'.encode('utf-8'))


    def listen(self):
        IP = '127.0.0.1'
        PORT = 8001

        listenSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listenSocket.bind((IP, PORT))
        listenSocket.listen(10)

        while True:
            client, address = listenSocket.accept()
            threading.Thread(target=self.process_request, args=(client,)).start()

def main():
    ca = CA()
    ca.listen()


if __name__ == "__main__":
    main()







