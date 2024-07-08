from Encryption import Encryption
import threading
import socket
import os


class User:

    def __init__(self, ID):
        result = self.make_dir(ID)
        self.ID = ID
        self.state = {'active': False, 'end': True, 'stop': False}
        self.recipient_ID = None
        self.group_ID_port = {}
        self.group_cred = None
        self.group_member = 'None'
        self.msg_flag = None
        

        self.init()
        if result:
            self.private_key = Encryption.generate_private_key(self.ID)
            Encryption.generate_csr(self.ID, self.private_key)

    def init(self):
        self.state['inputCondition'] = threading.Condition()
        self.state['sendMessageLock'] = threading.Lock()

    def make_dir(self, path):
        if not os.path.exists(path):
            os.mkdir(path)
            return True
        return False

    def activate_user(self):
        self.state['active'] = True

    def set_recipient_id(self, recipient_ID):
        self.recipient_ID = recipient_ID

    def set_msg_flag(self, flag):
        self.msg_flag = flag

    def get_activity(self):
        return self.state['active']

    def restart_chat(self):
        self.state['end'] = False
        self.state['active'] = False
        self.recipient_ID = None

    def get_chat_status(self):
        return self.state['end']

    def end_status(self):
        self.state['end'] = True

    def create_group(self):
        IP = '127.0.0.1'
        PORT = 5000
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((IP, PORT))
        client_socket.send(self.ID.encode('utf-8'))  # Send client ID
        client_socket.recv(3)
        msg = 'None'.encode('utf-8')

        self.msg_flag = 4
        client_socket.send(str(self.msg_flag).encode('utf-8') + b'||'
                           + self.ID.encode('utf-8') + b'||' + self.recipient_ID.encode('utf-8')
                           + b'||' + self.ID.encode('utf-8') + b'||' + msg)

        client_socket.close()
        self.state['end'] = True

    def send_csr(self):
        try:
            IP = '127.0.0.1'
            PORT = 8001
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((IP, PORT))
            message = '0'.encode('utf-8') + b'||' + self.ID.encode('utf-8')
            signed_message = Encryption.sign_message(Encryption.load_private_key(self.ID), message)
            server_socket.send(signed_message)
            response = server_socket.recv(1024)
            self.CA_response(server_socket, 0, response)
            server_socket.close()

        except Exception as e:
            print(f"An error occurred: {e}")

    def chat_request(self, request):
        try:
            IP = '127.0.0.1'
            PORT = 8001
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((IP, PORT))
            message = None

            if request == 1:  # private chat
                self.msg_flag = 0

                if self.recipient_ID is None:
                    self.recipient_ID = input('Enter the ID you want to chat with : ')
                message = str(request).encode('utf-8') + b'||' + self.ID.encode(
                    'utf-8') + b'||' + self.recipient_ID.encode('utf-8')

            elif request == 2:  # group chat
                self.msg_flag = 1

                group_ID = input('Enter Group ID : ')
                message = str(request).encode('utf-8') + b'||' + self.ID.encode('utf-8') + b'||' + group_ID.encode(
                    'utf-8')

            signed_message = Encryption.sign_message(Encryption.load_private_key(self.ID), message)
            server_socket.send(signed_message)
            response = server_socket.recv(1024)
            self.CA_response(server_socket, request, response)


        except Exception as e:
            print(f"An error occurred in chat_request: {e}")

    def CA_response(self, server_socket, request, response):
        flag = response
        flag = int(flag.decode('utf-8'))
        if flag == 0 and request == 0:  # waiting for CSR
            csr_path = self.ID + '/' + self.ID + '.pem'
            csr = Encryption.load_csr(csr_path)
            server_socket.send(str(len(csr)).encode('utf-8'))
            server_socket.sendall(csr)
        elif flag == 1 and request == 1:  # success response for private chat request
            server_socket.send(b'ACK')
            cert_path = self.ID + '/' + self.recipient_ID + '.crt'
            cert = server_socket.recv(4096)
            with open(cert_path, 'wb') as file:
                file.write(cert)

        elif flag == 1 and request == 2:  # success response for group chat request
            self.group_cred = server_socket.recv(4096)
            cert, gp_info, signature = self.group_cred.rsplit(b'||', 2)
            CA_cert_path = 'ActiveDirectory/CA.crt'
            CA_cert = Encryption.load_certificate(CA_cert_path)
            public_key = CA_cert.public_key()
            Encryption.verify_message_signature(public_key, signature, gp_info)
            group_ID, port = gp_info.decode('utf-8').split(':', 1)
            self.group_ID_port[group_ID] = port
            self.recipient_ID = group_ID
            self.create_group()
            print(f'group id = {group_ID} on port = {port}')

        elif flag == 2:  # not super admin
            print('You are not allowed creating group :( ')

        elif flag == 3:
            print('Invalid sender ID')

        elif flag == 4:
            print('Recipient ID not found')

        elif flag == 5:
            print('Repetitive Group ID')

        server_socket.close()

        if flag > 1:
            self.end_status()


    def get_message(self):
        while True:
            if self.state['active']:
                self.state['sendMessageLock'].acquire()
                self.state['userInput'] = input()
                if self.state['userInput'] != '':
                    print(f"{self.ID} (you) : {self.state['userInput']}")
                self.state['sendMessageLock'].release()
                with self.state['inputCondition']:
                    self.state['inputCondition'].notify()

                if self.state['userInput'] == 'end':
                    self.state['stop'] = True
                    break

            if self.state['stop']:
                self.state['userInput'] = None
                with self.state['inputCondition']:
                    self.state['inputCondition'].notify()
                break

    def send_message(self, client_socket):
        while True:
            with self.state['inputCondition']:
                self.state['inputCondition'].wait()

            if self.state['stop'] and self.state['userInput'] != 'end':  # stop threads
                self.state['stop'] = False
                client_socket.close()
                self.state['end'] = True
                break

            if self.state['userInput'] != '':
                message = self.state['userInput'].encode('utf-8')
                message = Encryption.sign_message(Encryption.load_private_key(self.ID), message)
                if self.msg_flag == 0:  # private message
                    cert_path = self.ID + '/' + self.recipient_ID + '.crt'
                    public_key = Encryption.get_public_key(cert_path)
                    message = Encryption.encrypt_message(public_key, message)

                client_socket.send(str(self.msg_flag).encode('utf-8') + b'||'
                                   + self.group_member.encode('utf-8') + b'||' + self.recipient_ID.encode('utf-8')
                                   + b'||' + self.ID.encode('utf-8') + b'||' + message)

            if self.state['stop']:  # end conversation
                self.state['stop'] = False
                client_socket.close()
                self.state['end'] = True
                break

    def receive_message(self, client_socket):
        while True:
            try:
                message = client_socket.recv(4096)
            except ConnectionAbortedError:
                break

            if message:
                flag, sender_ID, en_message = message.split(b'||', 2)
                flag = int(flag.decode('utf-8'))
                if flag == 2:
                    cert, gp_info, signature = en_message.rsplit(b'||', 2)
                    CA_cert_path = 'ActiveDirectory/CA.crt'
                    CA_cert = Encryption.load_certificate(CA_cert_path)
                    public_key = CA_cert.public_key()
                    Encryption.verify_message_signature(public_key, signature, gp_info)
                    group_ID, port = gp_info.decode('utf-8').split(':', 1)
                    self.group_ID_port[group_ID] = port
                    print(f'added to group id = {group_ID} on port = {port}')
                    self.state['stop'] = True
                    client_socket.close()
                    break

                elif flag == 3:
                    rem_group_id = en_message.decode('utf-8')
                    del self.group_ID_port[rem_group_id]
                    self.state['stop'] = True
                    client_socket.close()
                    print(f'removed from group id = {rem_group_id}')
                    break
                else:
                    sender_ID = sender_ID.decode('utf-8')
                    if not self.state['active']:
                        if flag == 0:
                            self.recipient_ID = sender_ID
                            self.chat_request(1)
                        self.state['active'] = True

                    cert_path = None
                    decrypted_message = None
                    if flag == 0:
                        decrypted_message = Encryption.decrypt_message(Encryption.load_private_key(self.ID), en_message)
                        cert_path = self.ID + '/' + sender_ID + '.crt'
                    elif flag == 1:
                        decrypted_message = en_message
                        cert_path = self.recipient_ID + '/' + sender_ID + '.crt'

                    message, signature = decrypted_message.rsplit(b'||', 1)
                    public_key = Encryption.get_public_key(cert_path)
                    Encryption.verify_message_signature(public_key, signature, message)

                    try:
                        message = message.decode('utf-8')
                    except UnicodeDecodeError as e:
                        print(f"Decryption error: {e}")
                        continue

                    print(f'{sender_ID} : {message}')

                    if message == 'end':
                        self.state['stop'] = True
                        self.state['active'] = False
                        client_socket.close()
                        break

            if self.state['end'] or self.state['stop']:  # Check for exit message
                self.state['active'] = False
                client_socket.close()
                break

    def listen_server(self, client_socket):
        receive_thread = threading.Thread(target=self.receive_message, args=(client_socket,))
        send_thread = threading.Thread(target=self.send_message, args=(client_socket,))
        get_thread = threading.Thread(target=self.get_message)
        receive_thread.start()
        get_thread.start()
        send_thread.start()

    def server_conn(self):
        IP = '127.0.0.1'
        PORT = 5000
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((IP, PORT))
        client_socket.send(self.ID.encode('utf-8'))  # Send client ID
        client_socket.recv(3)

        self.listen_server(client_socket)

    def handle_group_member(self, member):
        msg = None
        self.group_member = member

        if self.msg_flag == 2:  # add user
            msg = self.group_cred

        elif self.msg_flag == 3 or self.msg_flag == 5:
            msg = self.recipient_ID.encode('utf-8')

        IP = '127.0.0.1'
        PORT = 5000
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((IP, PORT))
        client_socket.send(self.ID.encode('utf-8'))  # Send client ID
        client_socket.recv(3)

        client_socket.send(str(self.msg_flag).encode('utf-8') + b'||'
                           + self.group_member.encode('utf-8') + b'||' + self.recipient_ID.encode('utf-8')
                           + b'||' + self.ID.encode('utf-8') + b'||' + msg)

        client_socket.close()
        self.state['end'] = True
