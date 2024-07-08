import os

from Encryption import Encryption
import threading
import socket


class User:

    def __init__(self, ID, password):
        result = self.make_dir(ID)
        self.ID = ID
        self.password = password
        self.state = {'active': False, 'end': True, 'stop': False}
        self.recipient_ID = None
        self.group_ID_port = {}
        self.group_ID_admin = {}
        self.group_cred = None
        self.group_member = 'NONE'
        self.msg_flag = None
        self.voting = False
        self.poll = False
        self.voting_option = 1
        self.poll_options = {}
        self.waitVotingACK = []

        self.init()
        if result:
            self.private_key = Encryption.generate_private_key(self.ID, self.password)
            Encryption.generate_csr(self.ID, self.private_key)

    def make_dir(self, path):
        if not os.path.exists(path):
            os.mkdir(path)
            return True
        return False


    def init(self):
        self.state['inputCondition'] = threading.Condition()
        self.state['sendMessageLock'] = threading.Lock()

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
            signed_message = Encryption.sign_message(Encryption.load_private_key(self.ID, self.password), message)
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

            signed_message = Encryption.sign_message(Encryption.load_private_key(self.ID, self.password), message)
            server_socket.send(signed_message)
            response = server_socket.recv(1024)
            self.CA_response(server_socket, request, response)


        except Exception as e:
            print(f"An error occurred: {e}")

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

                # todo check
                elif self.state['userInput'].lower().startswith('voting') and self.msg_flag == 1:
                    if not 'ack' in self.state['userInput'].lower():
                        self.msg_flag = 6

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
                message = None

                if self.state['userInput'].replace(' ', '').startswith('vote=') and self.voting_option == 2:  # confidential voting
                    self.msg_flag = 8
                    message = self.state['userInput'].encode('utf-8')
                    message = Encryption.sign_message(Encryption.load_private_key(self.ID, self.password), message)
                    cert_path = self.recipient_ID + '/' + self.group_ID_admin[self.recipient_ID] + '.crt'
                    public_key = Encryption.get_public_key(cert_path)
                    message = Encryption.encrypt_message(public_key, message)

                elif not self.state['userInput'].startswith('poll'):  # ordinary msg
                    if self.state['userInput'] == 'end poll':
                        self.poll = False
                        message = ','.join(f'{key}:{value}' for key, value in self.poll_options.items())
                        print(message)
                        message = message.encode('utf-8')
                    else:
                        message = self.state['userInput'].encode('utf-8')

                    message = Encryption.sign_message(Encryption.load_private_key(self.ID, self.password), message)

                    if self.msg_flag == 0:  # private message
                        cert_path = self.ID + '/' + self.recipient_ID + '.crt'
                        public_key = Encryption.get_public_key(cert_path)
                        message = Encryption.encrypt_message(public_key, message)

                elif self.state['userInput'].replace(' ', '').startswith('poll=') and self.poll is True:  # poll
                    self.msg_flag = 7
                    self.poll_options = {key: 0
                                         for key in self.state['userInput'].replace(' ', '')[5:].split(':')}
                    cert = Encryption.load_certificate_as_byte(self.recipient_ID + '/' + self.ID + '.crt')
                    message = self.state['userInput'].encode('utf-8')
                    message = Encryption.sign_message(Encryption.load_private_key(self.ID, self.password), message)
                    message = cert + b'||' + message


                client_socket.send(str(self.msg_flag).encode('utf-8') + b'||'
                                   + self.group_member.encode('utf-8') + b'||' + self.recipient_ID.encode('utf-8')
                                   + b'||' + self.ID.encode('utf-8') + b'||' + message)



                if self.msg_flag == 7 or self.msg_flag == 8:
                    self.msg_flag = 1

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
                sender_ID = sender_ID.decode('utf-8')
                if flag == 2:
                    cert, gp_info, signature = en_message.rsplit(b'||', 2)
                    CA_cert_path = 'ActiveDirectory/CA.crt'
                    CA_cert = Encryption.load_certificate(CA_cert_path)
                    public_key = CA_cert.public_key()
                    Encryption.verify_message_signature(public_key, signature, gp_info)
                    group_ID, port = gp_info.decode('utf-8').split(':', 1)
                    self.group_ID_port[group_ID] = port
                    print(f'added to group id = {group_ID} on port = {port}')
                    self.group_ID_admin[group_ID] = sender_ID
                    self.state['stop'] = True
                    client_socket.close()
                    break

                elif flag == 3:
                    rem_group_id = en_message.decode('utf-8')
                    del self.group_ID_port[rem_group_id]
                    del self.group_ID_admin[rem_group_id]
                    self.state['stop'] = True
                    client_socket.close()
                    break
                elif flag == 6 and sender_ID == 'Server':
                    en_message = en_message.decode('utf-8')
                    if en_message != 'Failed':
                        self.voting = True
                        self.waitVotingACK = en_message.split(',')
                        self.waitVotingACK.remove(self.ID)
                        self.msg_flag = 1

                    else:
                        print('You are not allowed to start voting!')

                else:
                    if not self.state['active']:
                        if flag == 0:
                            self.recipient_ID = sender_ID
                            self.chat_request(1)
                        self.state['active'] = True

                    cert_path = None
                    decrypted_message = None
                    if flag == 0 or (flag == 8 and self.poll is True):  # private chat and confidential voting
                        decrypted_message = Encryption.decrypt_message(
                            Encryption.load_private_key(self.ID, self.password), en_message)
                        if flag == 0:
                            cert_path = self.ID + '/' + sender_ID + '.crt'
                        elif flag == 8:
                            cert_path = self.recipient_ID + '/' + sender_ID + '.crt'

                    elif flag == 1 or flag == 6 or flag == 7:  # group chat
                        if flag == 7:
                            cert, decrypted_message = en_message.split(b'||', 1)
                            admin_cert = Encryption.load_certificate_as_byte(self.recipient_ID + '/' +
                                                                     self.group_ID_admin[self.recipient_ID] + '.crt')
                            if admin_cert == cert:
                                print('This poll is sent from admin !')
                            else:
                                print('This poll is not sent from admin !')
                        else:
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

                    elif message.lower() == 'voting ack' and self.voting is True:
                        if sender_ID in self.waitVotingACK:
                            self.waitVotingACK.remove(sender_ID)
                            if not self.waitVotingACK:  # list is empty
                                self.voting = False
                                self.poll = True
                                print('All group members sent ACK !')

                    elif message.startswith('vote=') and self.poll is True:
                        self.poll_options[message[5:]] += 1

                    if flag == 6 and ':' in message:
                        _, self.voting_option = message.split(':')
                        self.voting_option = int(self.voting_option)

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
            msg = 'None'.encode('utf-8')

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
