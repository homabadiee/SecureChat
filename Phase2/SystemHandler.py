import re
import bcrypt
import os
from Group import Group
from User import User
from Encryption import Encryption

class SystemHandler:
    def __init__(self, password):
        self.password = password
        SystemHandler.make_dir('SecretFiles/')
        SystemHandler.make_dir('ActiveDirectory/')
        self.create_users_database()
        self.create_group_id_file()

    def create_group_id_file(self):
        if not os.path.exists('SecretFiles/group_id.txt'):
            open('SecretFiles/group_id.txt', 'w')

    @staticmethod
    def make_dir(path):
        if not os.path.exists(path):
            os.mkdir(path)
            return True
        return False

    def create_users_database(self):
        if not os.path.exists('SecretFiles/database.txt.encrypted'):
            open('SecretFiles/database.txt', 'w')

            Encryption.encrypt_file('SecretFiles/database.txt', self.password)
            os.remove('SecretFiles/database.txt')

    @staticmethod
    def find_user_role(user_ID):
        Encryption.decrypt_file('SecretFiles/database.txt.encrypted', SystemHandler.password)
        user_role = None
        with open('SecretFiles/database.txt', 'r') as file:
            for line in file:
                parts = line.strip().split(",")
                email, s_user_ID, salt, hashed_password, role = parts
                if s_user_ID == user_ID:
                    user_role = role
        os.remove('SecretFiles/database.txt')
        return user_role

    def is_valid_email(self, email):
        regex = r'^[A-Za-z0-9._%+-]+@[a-z]+'
        return re.match(regex, email) and email.endswith('.com')

    def is_username_taken(self, username):
        Encryption.decrypt_file('SecretFiles/database.txt.encrypted', self.password)
        result = False
        try:
            with open('SecretFiles/database.txt', 'r') as file:
                for line in file:
                    stored_username = line.split(",")[1]
                    if stored_username == username:
                        result = True
        except FileNotFoundError:
            result = False

        os.remove('SecretFiles/database.txt')
        return result

    def get_user_details(self):
        email = input("Enter your email: ")
        while not self.is_valid_email(email):
            print("Invalid email format! Please try again.")
            email = input("Enter your email: ")

        username = input("Enter your username: ")
        while self.is_username_taken(username):
            print("Taken username! Please try again.")
            username = input("Enter your username: ")

        password = input("Enter your password: ")
        confirm_password = input("Confirm your password: ")

        while password != confirm_password:
            print("Passwords do not match! Please try again.")
            password = input("Enter your password: ")
            confirm_password = input("Confirm your password: ")

        return email, username, password

    def verify_password(self, salt, hashed_password, password):
        return bcrypt.hashpw(password.encode('utf-8'), salt.encode('utf-8')) == hashed_password.encode('utf-8')

    def find_user(self, username, password):
        Encryption.decrypt_file('SecretFiles/database.txt.encrypted', self.password)
        result = False
        with open('SecretFiles/database.txt', 'r') as file:
            for line in file:
                parts = line.strip().split(",")

                email, s_username, salt, hashed_password, role = parts
                if s_username == username and self.verify_password(salt, hashed_password, password):
                    result = True

        os.remove('SecretFiles/database.txt')
        return result


    def grant_superadmin_role(self, username):
        Encryption.decrypt_file('SecretFiles/database.txt.encrypted', self.password)
        os.remove('SecretFiles/database.txt.encrypted')
        result = False
        lines = []
        user_found = False

        with open('SecretFiles/database.txt', 'r') as file:
            for line in file:
                parts = line.strip().split(",")

                if parts[1] == username:
                    parts[-1] = 'superadmin'
                    user_found = True

                lines.append(",".join(parts) + "\n")

        if user_found:
            with open('SecretFiles/database.txt', 'w') as file:
                file.writelines(lines)
            result = True

        Encryption.encrypt_file('SecretFiles/database.txt', self.password)
        os.remove('SecretFiles/database.txt')
        return result

    def login(self):
        username = input("Enter your username: ")
        password = input("Enter your password: ")

        if self.find_user(username, password):
            print("Login successful!")
            return username, password
        else:
            raise Exception

    def hash_password(self, password):
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        return salt, hashed_password

    def store_user_details(self, email, username, salt, hashed_password):
        Encryption.decrypt_file('SecretFiles/database.txt.encrypted', self.password)
        os.remove('SecretFiles/database.txt.encrypted')
        with open('SecretFiles/database.txt', 'a') as file:
            file.write(f"{email},{username},{salt.decode('utf-8')},{hashed_password.decode('utf-8')},user\n")
        print("User details stored successfully!")
        Encryption.encrypt_file('SecretFiles/database.txt', self.password)
        os.remove('SecretFiles/database.txt')

    def register_user(self, email, username, password):
        salt, hashed_password = self.hash_password(password)
        self.store_user_details(email, username, salt, hashed_password)



SystemHandler = SystemHandler('systemhandler')
users = {}
choice = None
is_login = False

def chat_options(chat_type, user_ID):
    print('1. Send Message')
    print('2. Receive Message')

    choice = input('Enter your choice : ')
    if choice == '1':
        users[user_ID].activate_user()
        if chat_type == '1':  # private chat
            users[user_ID].chat_request(1)

    users[user_ID].server_conn()


def login_options(user_ID):
    global is_login
    while True:
        if users[user_ID].get_chat_status():
            users[user_ID].restart_chat()
            print('1. Private Chat')
            print('2. Create Group Chat (super admin)')
            print('3. Join Group Chat')
            print('4. Add member (super admin)')
            print('5. Remove member (super admin)')
            print('6. Grant user (super admin)')
            print('7. Exit')
            choice = input('Enter your choice : ')
            if choice == '1':
                users[user_ID].set_msg_flag(0)
                chat_options(choice, user_ID)

            elif choice == '2':
                if SystemHandler.find_user_role(user_ID) == 'superadmin':
                    users[user_ID].chat_request(2)

                else:
                    print('You are not super admin :( ')
                    users[user_ID].end_status()

            elif choice == '3':
                group_ID = input('Enter group ID you want to join : ')
                if Group.find_group_id(group_ID):
                    users[user_ID].set_recipient_id(group_ID)
                    if Group.find_group_member(group_ID, user_ID):
                        users[user_ID].set_msg_flag(1)
                        chat_options(choice, user_ID)
                    else:
                        print('You are not member of this group :( ')
                        users[user_ID].end_status()
                else:
                    print('This group does not exist ! ')
                    users[user_ID].end_status()

            elif choice == '4':  # add member
                if SystemHandler.find_user_role(user_ID) == 'superadmin':
                    group_ID = input('Enter group ID you want to add member to it : ')
                    if Group.find_group_id(group_ID):
                        users[user_ID].set_recipient_id(group_ID)
                        users[user_ID].set_msg_flag(2)
                        member_ID = input('Enter member ID you want to add : ')
                        try:
                            users[user_ID].handle_group_member(member_ID)
                        except Exception:
                            print(f'Not able to add {user_ID}')
                    else:
                        print('This group does not exist ! ')
                else:
                    print('You are not super admin :( ')

                users[user_ID].end_status()


            elif choice == '5':  # remove member
                if SystemHandler.find_user_role(user_ID) == 'superadmin':
                    group_ID = input('Enter group ID you want to remove member from : ')
                    if Group.find_group_id(group_ID):
                        users[user_ID].set_recipient_id(group_ID)
                        member_ID = input('Enter member ID you want to remove : ')
                        rem_type = input('Do you want to notify removed member? (yes/no) ')
                        if rem_type == 'yes':
                            users[user_ID].set_msg_flag(3)
                        else:
                            users[user_ID].set_msg_flag(5)

                        users[user_ID].handle_group_member(member_ID)

                    else:
                        print('This group does not exist ! ')

                else:
                    print('You are not super admin :( ')

                users[user_ID].end_status()

            elif choice == '6':
                if SystemHandler.find_user_role(user_ID) == 'superadmin':
                    ID = input('Enter user ID you want to grant super admin access to : ')
                    SystemHandler.grant_superadmin_role(ID)
                    users[user_ID].end_status()
                else:
                    print('You are not super admin :( ')
                    users[user_ID].end_status()

            elif choice == '7':  # Exit
                users[user_ID].end_status()
                break

    is_login = False


def main():
    global choice
    global is_login

    if not SystemHandler.find_user('systemadmin', 'systemadmin'):
        print('Creating System Admin ...')
        SystemHandler.register_user('sysadmin@gmail.com', 'systemadmin', 'systemadmin')
        users['systemadmin'] = User('systemadmin', 'systemadmin')
        SystemHandler.grant_superadmin_role('systemadmin')

    while True:
        if not is_login:
            print('1. Register')
            print('2. Login')
            print('3. Exit')
            choice = input('Enter your choice: ')
            try:
                if choice == '1':  # register
                    email, user_ID, password = SystemHandler.get_user_details()
                    SystemHandler.register_user(email, user_ID, password)
                    users[user_ID] = User(user_ID, password)
                    users[user_ID].send_csr()
                elif choice == '2':  # login
                    is_login = True
                    user_ID, password = SystemHandler.login()
                    if not user_ID in users:
                        users[user_ID] = User(user_ID, password)

                    login_options(user_ID)
                elif choice == '3':
                    print('Exiting the program.')
                    break
                else:
                    print('Invalid choice! Please try again.')
            except Exception as e:
                is_login = False
                print(e)
                print("Invalid username or password!")


if __name__ == "__main__":
    main()

