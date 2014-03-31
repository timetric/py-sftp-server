from ConfigParser import RawConfigParser


def read_permissions_file(filename):
    """
    Reads permissions from an INI file and returns a dict mapping
    paths to sets of groups. Example file:

    [permissions]
    / = superusers
    Data/Special Data = special_people, other_special_people
    """
    parser = RawConfigParser()
    # This forces parser to preseve case
    parser.optionxform=str
    parser.read([filename])
    permissions = {}
    for path, group_string in parser.items('permissions'):
        path = path.strip().strip('/')
        groups = set([group.strip() for group in group_string.split(',')])
        permissions[path] = groups
    return permissions
