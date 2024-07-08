import os
import socket
import threading
import shutil
from Group import Group


class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(10)
        self.clients = {}
        self.groups = {}
        self.load_groups()

    def load_groups(self):
        with open('SecretFiles/group_id.txt', 'r') as file:
            lines = file.readlines()

        for line in lines:
            if line is not None:
                contents = line.split(',')
                self.groups[contents[0]] = Group(contents[1], contents[0])
                contents[len(contents) - 1] = contents[len(contents) - 1].replace('\n', '')
                for i in range(2, len(contents)):
                    self.groups[contents[0]].add_member(contents[i])

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
                elif flag == 1 or flag == 7:  # ordinary group msg or poll
                    sender_id = sid_and_msg.split(b'||', 1)[0].decode('utf-8')
                    if self.groups[recipient_id].find_member(sender_id):
                        members = self.groups[recipient_id].get_members()
                        for member in members:  # broadcast message
                            if member != sender_id:
                                try:
                                    self.clients[member].sendall(eflag + b'||' + sid_and_msg)
                                    print(f'message in group {recipient_id} forwarded to {member}')
                                except Exception:
                                    print(f'{member} is offline')
                    else:
                        print(f'{sender_id} is not member of this group :(')
                elif flag == 2:
                    print(f'{group_member} added')
                    self.groups[recipient_id].add_member(group_member)
                    Group.add_group_member_file(recipient_id, group_member)
                    shutil.copy('SecretFiles/' + group_member + '.crt', recipient_id + '/')
                    self.clients[group_member].sendall(eflag + b'||' + sid_and_msg)
                elif flag == 3 or flag == 5:
                    self.groups[recipient_id].remove_member(group_member)
                    Group.remove_group_member_file(recipient_id, group_member)
                    os.remove(recipient_id + '/' + group_member + '.crt')
                    if flag == 3:
                        self.clients[group_member].sendall(eflag + b'||' + sid_and_msg)
                elif flag == 4:  # create group
                    self.groups[recipient_id] = Group(group_member, recipient_id)
                    Group.add_group_member_file(recipient_id, group_member)
                    print(f'group with id = {recipient_id} with admin = {group_member} created')
                elif flag == 6:
                    client_id = sid_and_msg.split(b'||', 1)[0].decode('utf-8')
                    sender_id = 'Server'
                    if self.groups[recipient_id].get_admin() == client_id:
                        members = self.groups[recipient_id].get_members()
                        self.clients[client_id].sendall(eflag + b'||' + sender_id.encode('utf-8')
                                                        + b'||' + ','.join(members).encode('utf-8'))
                        for member in members:  # broadcast voting message
                            if member != client_id:
                                try:
                                    self.clients[member].sendall(eflag + b'||' + sid_and_msg)
                                    print(f'message in group {recipient_id} forwarded to {member}')
                                except Exception:
                                    print(f'{member} is offline')

                    else:  # sender is not admin of group
                        self.clients[client_id].sendall(eflag + b'||' + sender_id.encode('utf-8')
                                                        + b'||' + 'Failed'.encode('utf-8'))

                elif flag == 8:  # send confidential vote to admin
                    print('confidential vote')
                    self.clients[self.groups[recipient_id].get_admin()].sendall(eflag + b'||' + sid_and_msg)
            else:
                break
        client_socket.close()

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
