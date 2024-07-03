import os
import shutil

class Group:
    groups = {}  # Static dictionary to store all group objects

    def __init__(self, admin, group_id):
        self.admin = admin
        self.group_id = group_id
        self.members = [admin]
        self.make_dir(group_id)
        shutil.copy('secret_files/' + admin + '.crt', group_id + '/')
        Group.groups[group_id] = self  # Add the group to the global dictionary

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