#!usr/bin/python
# -*- coding: utf-8 -*-
"""
    MIT License

    Copyright (c) 2018 Antonia Stevens

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
"""

__version__ = "0.0.1"

import errno
import grp
import logging
import multiprocessing
import os
import pwd
import shutil
import stat
import sys


class PermError(Exception):
    """ Raised if a specified provisioning environment is considered unsafe """
    pass


# Create a pseudo logger
try:
    from logging import NullHandler
except ImportError:
    from logging import Handler

    class NullHandler(Handler):  # NOQA
        def emit(self, record):
            pass

logger = logging.getLogger(__name__)
logger.addHandler(NullHandler())


def import_by_path(name, path_list):
    """ Import a module using library path(s) """
    try:
        # Handle submodules and additional paths
        path_index = len(sys.path)
        sys.path.extend(path_list)
        # Attempt the actual import
        return __import__(name)
    finally:
        # Safely remove paths
        for path in path_list:
            if sys.path.pop(path_index) != path:
                raise ImportError('Returned path entry from sys.path does not match appended path')

# Import selinux if available
try:
    import selinux
except ImportError:
    try:
        selinux = import_by_path('selinux', ['/usr/lib64/python2.6/site-packages/', '/usr/lib/python2.6/site-packages/'])  # NOQA
        logger.debug('Importing selinux from system python path')
    except ImportError:
        logger.debug('Failed to import selinux, continuing ...')
        pass


def requires_selinux(func):
    """
    Allows objects to define that they depend on selinux being installed and
    enabled, handles exceptions/errors and selinux disabled/missing.
    """

    def inner(*args, **kwargs):
        try:
            if bool(selinux.is_selinux_enabled()):
                return func(*args, **kwargs)
            else:
                logger.debug('SELinux is disabled, skipping action')
        except NameError:
            logger.debug('No selinux library available, failed to get selinux context')
        except OSError as exc:
            if exc.errno == errno.ENODATA:
                logger.debug('SELinux is disabled or not returning any data')

    return inner


@requires_selinux
def get_selinux_context(path):
    """ Returns selinux context, False on error and None if selinux is not available """
    ret_code, context = selinux.lgetfilecon(path)
    if ret_code != -1:
        return context.split(':', 3)
    else:
        return False


@requires_selinux
def set_selinux_context(path, context):
    """ Sets selinux context, returns False on error and None if selinux is not available """
    if context == get_selinux_context(path):
        return True
    else:
        return not bool(selinux.lsetfilecon(path, ':'.join(context)))


def umasker(func):
    """ A decorator to change the umask while performing IO operations"""
    def inner(*args, **kwargs):
        orig_umask = os.umask(0o0002)
        try:
            retval = func(*args, **kwargs)
        finally:
            os.umask(orig_umask)
        return retval
    return inner


def set_home(func):
    """ Set environment variable HOME to match effective user home"""
    def inner(*args, **kwargs):
        init_home = os.environ['HOME']
        os.environ['HOME'] = pwd.getpwuid(os.geteuid()).pw_dir
        try:
            retval = func(*args, **kwargs)
        finally:
            os.environ['HOME'] = init_home
        return retval
    return inner


def is_superuser():
    """ Tests if a user has superuser privileges"""
    if sys.version > "2.7":
        for uid in os.getresuid():
            if uid == 0:
                return True
    else:
        if os.getuid() == 0 or os.getegid() == 0:
            return True
    return False


def elevate_priv_if_needed(func):
    """
    A decorator to elevate privileges to superuser/root if a permission error
    is encountered.
    """
    def inner(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except OSError as e:
            logger.debug('Elevating privileges due to receiving permission errror')
            logger.debug(e)
            return run_as_root(func)(*args, **kwargs)

    return inner


def set_file_owner_perm(path, permission, user, group):
    """
    Set a single file or directory to the provided permissions

    :param permission: Octal value of desired permissions
    :param user: Username string to set as owner
    :param group: Group string to set as owner
    """
    uid = pwd.getpwnam(user).pw_uid
    gid = grp.getgrnam(group).gr_gid

    current_perm = get_permissions(path)
    try:
        logger.debug('Current permission: {0}, changing to {1}'.format(current_perm, oct(permission)))
        os.chmod(path, permission)
        os.chown(path, uid, gid)
    except Exception as e:
        logger.warning('Unable to change permissions on {0}: {1}'.format(path, e))


@requires_selinux
@elevate_priv_if_needed
def match_selinux_context(dest_path, source_path):
    """ Matches selinux context of one fs object to that of another """
    return set_selinux_context(dest_path, get_selinux_context(source_path))


@elevate_priv_if_needed
def match_owner_group(dest_path, source_path):
    """ Matches owner/group from one filesystem object to another """
    source_stat = os.stat(source_path)
    return os.chown(dest_path, source_stat[stat.ST_UID], source_stat[stat.ST_GID])


@elevate_priv_if_needed
def match_stat(dest_path, source_path):
    """ Matches stats of one fs object to that of another, see shutil.copystat """
    return shutil.copystat(source_path, dest_path)


def run_as_root(func):
    """
    A decorator to run a code block as the root user, assumes that user has
    permissions to switch to root (see euid, ruid, suid)
    """
    def inner(*args, **kwargs):
        current_proc = multiprocessing.current_process()
        logger.debug("Changing permissions for process: {0} with PID: {1!s}".format(current_proc.name, current_proc.pid))
        if sys.version > "2.7":
            ruid, euid, suid = os.getresuid()
            rgid, egid, sgid = os.getresgid()

            logger.debug("UIDs before are: (ruid) {0}, (euid) {1}, (suid) {2}".format(ruid, euid, suid))
            logger.debug("GIDs before are: (rgid) {0}, (egid) {1}, (sgid) {2}".format(rgid, egid, sgid))
            logger.debug("Setting all UIDs/GIDs to 0")
            # Make the actual permissions changes
            os.setresuid(0, 0, 0)
            os.setresgid(0, 0, 0)

            try:
                retval = func(*args, **kwargs)
            finally:
                # Restore original permissions
                os.setresgid(rgid, egid, sgid)
                os.setresuid(ruid, euid, suid)
        else:
            ruid = os.getuid()
            euid = os.geteuid()
            rgid = os.getgid()
            egid = os.getegid()
            logger.debug("UIDs before are: (ruid) {0}, (euid) {1}".format(ruid, euid))
            logger.debug("GIDs before are: (rgid) {0}, (egid) {1}".format(rgid, egid))
            logger.debug("Setting all UIDs/GIDs to 0")
            # Make the actual permissions changes
            os.setreuid(0, 0)
            os.setregid(0, 0)
            try:
                logger.debug("Setting all UIDs/GIDs to 0")
                retval = func(*args, **kwargs)
            finally:
                # Restore original permissions
                os.setregid(rgid, egid)
                os.setreuid(ruid, euid)

        return retval
    return inner


def run_with_egid(group_name):
    def run_with_egid_decorator(func):
        """
        A decorator to set the effective gid to that of the group_name for the duration of the process.
        """
        def set_egid_as_root(negid):
            current_proc = multiprocessing.current_process()
            logger.debug("Temporarily changing EUID for process: {0} with PID: {1!s}".format(current_proc.name, current_proc.pid))

            # Get the effective UID
            euid = os.geteuid()
            logger.debug("EUID before is: (euid) {0}".format(euid))

            logger.debug("Setting EUID to: (euid) 0")
            os.seteuid(0)

            logger.debug("Setting EGID to: (egid) {0}".format(negid))
            os.setegid(negid)

            logger.debug("Restoring EUID to: (euid) {0}".format(euid))
            os.seteuid(euid)

        def inner(*args, **kwargs):
            current_proc = multiprocessing.current_process()
            logger.debug("Changing EGID for process: {0} with PID: {1!s}".format(current_proc.name, current_proc.pid))

            # Get the effective GID
            egid = os.getegid()
            logger.debug("EGID before is: (egid) {0}".format(egid))

            # Set the gid to the one of the provided group
            groupinfo = grp.getgrnam(group_name)
            negid = groupinfo.gr_gid

            # Make the actual permission changes
            # This requires the EUID to be root, even if the actual UID is
            set_egid_as_root(negid)

            try:
                # Run the code
                retval = func(*args, **kwargs)
            finally:
                # Restore original EGID
                logger.debug("Restoring EGID to: (egid) {0}".format(egid))
                set_egid_as_root(egid)

            return retval

        return inner

    return run_with_egid_decorator


def set_uid_gid(set_rguid_to_eguid=False, set_eguid_to_rguid=False, restore_ids=True):
    """
    A decorator to set/swap real/effective UID/GID for the duration of an operation

    EUID: Effective user ID, this is what is used to check permissions
    RUID: Real user ID, this is used to determine who the original user is
          when escalating priv. to determine the original user
    SUID: Saved user ID, this is used to store original user ID when a process
          needs to temporarily deescalate it's priv but is used to re-escalate.
    """
    def set_uid_gid_decorator(func):
        def inner(*args, **kwargs):
            current_proc = multiprocessing.current_process()
            logger.debug("Changing permissions for process: {0} with PID: {1!s}".format(current_proc.name, current_proc.pid))
            if sys.version > "2.7":
                ruid, euid, suid = os.getresuid()
                rgid, egid, sgid = os.getresgid()
                logger.debug("UIDs before are: (ruid) {0}, (euid) {1}, (suid) {2}".format(ruid, euid, suid))
                logger.debug("GIDs before are: (rgid) {0}, (egid) {1}, (sgid) {2}".format(rgid, egid, sgid))
                # Store superuser if available
                if 0 in (ruid, euid, suid):
                    tmp_stored_uid = 0
                else:
                    tmp_stored_uid = suid
                if 0 in (rgid, egid, rgid):
                    tmp_stored_gid = 0
                else:
                    tmp_stored_gid = sgid

                # Swap UID/GID's around as needed
                if set_eguid_to_rguid is True:
                    neuid = ruid
                    negid = rgid
                else:
                    neuid = euid
                    negid = egid

                if set_rguid_to_eguid is True:
                    nruid = euid
                    nrgid = egid
                else:
                    nruid = ruid
                    nrgid = rgid

                # Make the actual permission changes
                logger.debug("Setting UIDs to: (ruid) {0}, (euid) {1}, (suid) {2}".format(nruid, neuid, tmp_stored_uid))
                logger.debug("Setting GIDs to: (rgid) {0}, (egid) {1}, (sgid) {2}".format(nrgid, negid, tmp_stored_gid))
                os.setresuid(nruid, neuid, tmp_stored_uid)
                os.setresgid(nrgid, negid, tmp_stored_gid)

                try:
                    # Run the code
                    retval = func(*args, **kwargs)
                finally:
                    if restore_ids is True:
                        # Restore original permissions
                        logger.debug("Restoring UIDs to: (ruid) {0}, (euid) {1}, (suid) {2}".format(ruid, euid, suid))
                        logger.debug("Restoring GIDs to: (rgid) {0}, (egid) {1}, (sgid) {2}".format(rgid, egid, sgid))
                        os.setresgid(rgid, egid, sgid)
                        os.setresuid(ruid, euid, suid)

            else:
                # We can't check stored user ID, so we hope and try our best
                ruid = os.getuid()
                euid = os.geteuid()
                rgid = os.getgid()
                egid = os.getegid()
                logger.debug("UIDs before are: (ruid) {0}, (euid) {1}".format(ruid, euid))
                logger.debug("GIDs before are: (rgid) {0}, (egid) {1}".format(rgid, egid))
                # Store superuser if available
                if 0 in (ruid, euid):
                    #  Set all UIDs to 0 (call twice for ruid -> euid -> suid)
                    os.setuid(0)
                    os.setuid(0)
                elif 0 in (rgid, egid):
                    #  Set all GIDs to 0 (call twice for rgid -> egid -> sgid)
                    os.setgid(0)
                    os.setgid(0)

                # Swap UID/GID's around as needed
                if set_eguid_to_rguid is True:
                    neuid = ruid
                    negid = rgid
                else:
                    neuid = euid
                    negid = egid

                if set_rguid_to_eguid is True:
                    nruid = euid
                    nrgid = egid
                else:
                    nruid = ruid
                    nrgid = rgid

                # Make the actual permission changes
                if nruid != 0 and neuid != 0:
                    logger.debug("Setting both Real and Effective UIDs to non-zero!")
                logger.debug("Setting UIDs to: (ruid) {0}, (euid) {1}".format(nruid, neuid))
                logger.debug("Setting GIDs to: (rgid) {0}, (egid) {1}".format(nrgid, negid))
                os.setreuid(nruid, neuid)
                os.setregid(nrgid, negid)

                try:
                    # Run the code
                    retval = func(*args, **kwargs)
                finally:
                    if restore_ids is True:
                        # Restore original permissions
                        logger.debug("Restoring UIDs to: (ruid) {0}, (euid) {1}".format(ruid, euid))
                        logger.debug("Restoring GIDs to: (rgid) {0}, (egid) {1}".format(rgid, egid))
                        os.setregid(rgid, egid)
                        os.setreuid(ruid, euid)

            return retval
        if set_rguid_to_eguid is True or set_eguid_to_rguid is True:
            return inner
        else:
            return func
    return set_uid_gid_decorator


def get_permissions(filepath):
    """
    Returns file or directory permissions as octal integer
    """
    return oct(stat.S_IMODE(os.lstat(filepath).st_mode))


def check_permission(perm_mode, flags=stat.S_IWOTH):
    """
    Check if a bit is is set in an integer, very useful for checking if
    a particular permission is set of a file by comparing os.stat.st.mode

    Multiple modes can be combined by using by using the bitwise OR operator
     e.g.
    check_permission(0o754, stat.S_IROTH | stat.S_IWGRP)
    -> True

    Valid modes from stat:

        S_ISUID = 04000
        S_ISGID = 02000
        S_ENFMT = S_ISGID
        S_ISVTX = 01000
        S_IREAD = 00400
        S_IWRITE = 00200
        S_IEXEC = 00100
        S_IRWXU = 00700
        S_IRUSR = 00400
        S_IWUSR = 00200
        S_IXUSR = 00100
        S_IRWXG = 00070
        S_IRGRP = 00040
        S_IWGRP = 00020
        S_IXGRP = 00010
        S_IRWXO = 00007
        S_IROTH = 00004
        S_IWOTH = 00002
        S_IXOTH = 00001
    """
    return bool(perm_mode & flags)


def check_dir_perms(path, dir_perm=stat.S_IWOTH, file_perm=stat.S_IWOTH, users=('root',), groups=('root',), recurse=True):
    """
    Check dir structure and verify only specified users/groups have access
    and confirm check if they violate permission restriction.

    If any directories have the dir_perm bits set we'll raise an error and the
    same goes for files matching file_perm bits.

    See check_permission for more info on how permission bit checking works.
    """
    directories = ((path, (), ()),) if not recurse else os.walk(path)
    for dir_name, sub_dirs, files in directories:
        attrib = os.stat(dir_name)
        if attrib.st_uid not in [pwd.getpwnam(user).pw_uid for user in users]:
            err_msg = 'Directory: "{0}" is owned by {1} which is not in the list of allowed users: "{2!s}"'
            raise PermError(err_msg.format(dir_name, pwd.getpwuid(attrib.st_uid).pw_name, users))

        if attrib.st_gid not in [grp.getgrnam(group).gr_gid for group in groups]:
            err_msg = 'The group for directory: "{0}" is {1} which is not in the list of allowed groups: "{2!s}"'
            raise PermError(err_msg.format(dir_name, grp.getgrgid(attrib.st_gid).gr_name, groups))

        if check_permission(attrib.st_mode, dir_perm):
            # Could add strmode for python one day and make nice human errors
            err_msg = 'The permissions on directory: "{0}" are "{1!s}" and violate restriction "{2!s}"'
            raise PermError(err_msg.format(dir_name, oct(attrib.st_mode), oct(dir_perm)))

        for f in files:
            file_attrib = os.stat(os.path.join(dir_name, f))
            if check_permission(file_attrib.st_mode, file_perm):
                # Could add strmode for python one day and make nice human errors
                err_msg = 'The permissions on file: "{0}" are "{1!s}" and violate restriction "{2!s}"'
                raise PermError(err_msg.format(os.path.join(dir_name, f), oct(file_attrib.st_mode), oct(file_perm)))
