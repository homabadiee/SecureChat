import os
import shutil

class Group:

    def __init__(self, admin, group_id):
        self.admin = admin
        self.group_id = group_id
        self.members = [admin]
        self.make_dir(group_id)
        shutil.copy('SecretFiles/' + admin + '.crt', group_id + '/')

    def get_admin(self):
        return self.admin

    def make_dir(self, path):
        if not os.path.exists(path):
            os.mkdir(path)

    def add_member(self, member):
        self.members.append(member)

    def remove_member(self, member):
        self.members.remove(member)

    def find_member(self, member):
        if member in self.members:
            return True
        return False

    def get_members(self):
        return self.members

    @staticmethod
    def add_group_member_file(group_id, member_name):
        with open('SecretFiles/group_id.txt', 'r') as file:
            lines = file.readlines()
        updated_lines = []
        for line in lines:
            if line.startswith(group_id):
                parts = line.strip().split(',')
                if member_name not in parts[1:]:
                    parts.append(member_name)
                line = ','.join(parts) + '\n'
            updated_lines.append(line)

        with open('SecretFiles/group_id.txt', 'w') as file:
            file.writelines(updated_lines)

    @staticmethod
    def remove_group_member_file(group_id, member_name):
        with open('SecretFiles/group_id.txt', 'r') as file:
            lines = file.readlines()
        updated_lines = []
        for line in lines:
            if line.startswith(group_id):
                parts = line.strip().split(',')
                if member_name in parts[1:]:
                    parts.remove(member_name)
                line = ','.join(parts) + '\n' if len(parts) > 1 else group_id + '\n'
            updated_lines.append(line)

        with open('SecretFiles/group_id.txt', 'w') as file:
            file.writelines(updated_lines)

    @staticmethod
    def find_group_id(group_id):
        with open('SecretFiles/group_id.txt', 'r') as file:
            lines = file.readlines()

        for line in lines:
            if line.startswith(group_id):
                return True

        return False

    @staticmethod
    def find_group_member(group_id, member_name):
        with open('SecretFiles/group_id.txt', 'r') as file:
            for line in file:
                if line.startswith(group_id):
                    members = line.strip().split(',')[1:]
                    return member_name in members
        return False

    @staticmethod
    def add_group_id_file(group_id):
        if Group.find_group_id(group_id):
            return False

        with open('SecretFiles/group_id.txt', 'a') as file:
            file.write(group_id)

        return True