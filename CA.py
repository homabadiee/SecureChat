import threading
import socket
from Group import Group
from SystemHandler import SystemHandler
from Encryption import Encryption
from cryptography.hazmat.backends import default_backend
from cryptography import x509



class CA:

    def __init__(self):
        self.ID = 'CA'
        self.private_key = Encryption.generate_private_key('SecretFiles/')
        self.certificate = Encryption.generate_root_certificate(self.private_key)
        open('SecretFiles/group_id.txt', 'w')

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
            cert_path = 'SecretFiles/' + sender_ID + '.crt'
            Encryption.sign_csr(self.certificate, self.private_key, csr, cert_path)

        else:
            cert_path = 'SecretFiles/' + sender_ID + '.crt'

            try:
                public_key = Encryption.get_public_key(cert_path)
                Encryption.verify_message_signature(public_key, signature, message)

                if flag == '1':
                    _, _, req_ID = message.split(b'||', 2)
                    req_ID = req_ID.decode('utf-8')
                    cert_path = 'SecretFiles/' + req_ID + '.crt'
                    self.send_certificate(client, cert_path)

                elif flag == '2':
                    _, _, group_ID = message.split(b'||', 2)
                    group_ID = group_ID.decode('utf-8')
                    if Group.add_group_id_file(group_ID):
                        if SystemHandler.find_user_role(sender_ID) == 'superadmin':
                            port = '8000'
                            gp_info = f"{group_ID}:{port}".encode('utf-8')
                            signed_gp_info = Encryption.sign_message(self.private_key, gp_info)
                            cert_path = 'SecretFiles/' + sender_ID + '.crt'
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
