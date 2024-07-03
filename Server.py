import os
import socket
import threading
from Group import Group
import shutil

class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(10)
        self.clients = {}
        self.groups = {}

    def handle_client(self, client_socket):
        while True:
            message = client_socket.recv(4096)
            if message:
                eflag, group_member, recipient_id, sid_and_msg = message.split(b'||', 3)
                recipient_id = recipient_id.decode('utf-8')
                flag = int(eflag.decode('utf-8'))
                group_member = group_member.decode('utf-8')
                if flag == 0:  # private chat
                    if recipient_id in self.clients:
                        self.clients[recipient_id].sendall(eflag + b'||' + sid_and_msg)
                    else:
                        print(f"Unknown client ID: {recipient_id}")
                elif flag == 1:  # group msg
                    sender_id = sid_and_msg.split(b'||', 1)[0].decode('utf-8')
                    if self.groups[recipient_id].find_member(sender_id):
                        members = self.groups[recipient_id].get_members()
                        for member in members:  # broadcast message
                            if member != sender_id:
                                self.clients[member].sendall(eflag + b'||' + sid_and_msg)
                                print('Group chat msg sent')
                    else:
                        print(f'{sender_id} is not member of this group :(')
                elif flag == 2:
                    print(f'{group_member} added')
                    self.groups[recipient_id].add_member(group_member)
                    self.add_group_member(recipient_id, group_member)
                    shutil.copy('secret_files/' + group_member + '.crt', recipient_id + '/')
                    self.clients[group_member].sendall(eflag + b'||' + sid_and_msg)
                elif flag == 3 or flag == 5:
                    self.groups[recipient_id].remove_member(group_member)
                    self.remove_group_member(recipient_id, group_member)
                    os.remove(recipient_id + '/' + group_member + '.crt')
                    if flag == 3:
                        self.clients[group_member].sendall(eflag + b'||' + sid_and_msg)
                elif flag == 4:  # create group
                    self.groups[recipient_id] = Group(group_member, recipient_id)
                    self.add_group_member(recipient_id, group_member)
                    print(f'group with id = {recipient_id} with admin = {group_member} created')

            else:
                break
        client_socket.close()

    def add_group_member(self, group_id, member_name):
        with open('secret_files/group_id.txt', 'r') as file:
            lines = file.readlines()
        updated_lines = []
        for line in lines:
            if line.startswith(group_id):
                parts = line.strip().split(',')
                if member_name not in parts[1:]:
                    parts.append(member_name)
                line = ','.join(parts) + '\n'
            updated_lines.append(line)

        with open('secret_files/group_id.txt', 'w') as file:
            file.writelines(updated_lines)

    def remove_group_member(self, group_id, member_name):
        with open('secret_files/group_id.txt', 'r') as file:
            lines = file.readlines()
        updated_lines = []
        for line in lines:
            if line.startswith(group_id):
                parts = line.strip().split(',')
                if member_name in parts[1:]:
                    parts.remove(member_name)
                line = ','.join(parts) + '\n' if len(parts) > 1 else group_id + '\n'
            updated_lines.append(line)

        with open('secret_files/group_id.txt', 'w') as file:
            file.writelines(updated_lines)

    def start(self):
        print(f"Server started on {self.host}:{self.port}")
        while True:
            client_socket, client_address = self.server_socket.accept()
            print(f"Connected by {client_address}")
            client_id = client_socket.recv(1024).decode('utf-8')
            print(f'{client_id} connected')
            self.clients[client_id] = client_socket
            client_socket.send(b'ACK')
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()

if __name__ == "__main__":
    server = Server('localhost', 5000)
    server.start()
