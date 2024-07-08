from User import User
from SystemHandler import SystemHandler

SystemHandler = SystemHandler()
users = {}


def login_options(user_ID):
    while True:
        print('1. Private Chat')
        print('2. Group Chat')
        print('3. Exit')
        choice = input('Enter your choice : ')
        if choice == '1':
            users[user_ID].set_flag(1)
            users[user_ID].client_conn()
            # req_ID, rec_cert = users[user_ID].server_conn(choice)
            # users[user_ID].sender_conn(rec_cert)
            break
        elif choice == '2':
            break

        elif choice == '3':  # Exit
            break


def main():
    while True:
        print('1. Register')
        print('2. Login')
        print('3. Exit')
        choice = input('Enter your choice: ')

        if choice == '1':
            user_ID = SystemHandler.register_user()
            users[user_ID] = User(user_ID)
            users[user_ID].set_flag(0)  # receive certificate
            users[user_ID].client_conn()

        elif choice == '2':
            user_ID = SystemHandler.login()
            if not user_ID in users:
                users[user_ID] = User(user_ID)

                # users[user_ID].start_receiver_conn()
            user_choice = input('Do you want to see chat options? (yes/no)')
            if user_choice == 'yes':
                login_options(user_ID)
            else:
                users[user_ID].set_flag(10)  # listen mode
                users[user_ID].client_conn()


        elif choice == '3':
            print('Exiting the program.')
            break
        else:
            print('Invalid choice! Please try again.')


if __name__ == "__main__":
    main()
