import fcntl
import paramiko
import socket
import struct
import subprocess
import time
import traceback

from gcutils.cli import exec_local_cmd

from gcutils.const import TIMEOUT_s, SHORT_s, SCRIPT_EXECUTE_TIMEOUT_s, RETRY, LOCALS, DNS


def remote_exec(cmd, ip, username, passkey=None, pkey=None, port=22, no_err=True, timeout=TIMEOUT_s, short_wait=SHORT_s, retry=RETRY, omit_str=None, platform='linux'):
    resd = {'res': [], 'err': []}
    rt = 0
    if ('' != cmd):
        if ('linux' == platform):
            while (('err' in resd.keys()) and (rt <= retry)):
                resd.pop('err')
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    ssh.load_system_host_keys()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    try:
                        ssh.connect(hostname=ip, port=port, username=username, password=passkey)
                    except:
                        pkey=paramiko.RSAKey.from_private_key_file(passkey)
                        ssh.connect(ip, username=username, pkey=pkey)
                    finally:
                        pass
                    if (cmd.split(';')[-1].replace('&', '').split('-')[0].strip() in (
                    'reboot', 'shutdown', 'poweroff')):
                        ssh.exec_command(cmd, timeout=timeout)
                    else:
                        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
                        resd['res'] = stdout.readlines()
                        resd['err'] = stderr.readlines()
                        if ((0 == len(resd['err'])) or ((not no_err) and (0 < len(resd['res'])))):
                            resd.pop('err')
                        else:
                            rt = rt + 1
                except Exception as err:
                    resd['err'] = [str(err), traceback.format_exc()]
                    rt = rt + 1
                    time.sleep(short_wait)
                    raise Exception(__name__, err)
                finally:
                    ssh.close()
            if (not 'err' in resd):
                resd['err'] = []
        elif('windows' == platform):
            while (('err' in resd.keys()) and (rt <= retry)):
                resd.pop('err')
                try:
                    ret = winrm.Session('http://' + ip + ':' + str(port) + '/wsman', auth=(username, passkey)).run_cmd(cmd)
                    resd['res'], resd['err'] = ret.std_out, ret.std_err
                except Exception as err:
                    resd['err'] = [str(err), traceback.format_exc()]
                    rt = rt + 1
                    time.sleep(short_wait)
                    raise Exception(__name__, err)
                finally:
                    pass
    return resd


def exec_cmd(cmd, machine='localhost', username=None, passkey=None, port=22, no_err=True, omit_str=None, platform='linux', timeout=TIMEOUT_s, debug=False):
    rtcode = -1
    resl = []
    if (machine in LOCALS):
        rtcode, resl = exec_local_cmd(cmd)
    else:
        if passkey is None:
            passkey = '/home/' + username + '/.ssh/id_rsa'
        resd = remote_exec(cmd, machine, username, passkey, port, no_err=no_err, timeout=timeout, short_wait=SHORT_s, retry=RETRY, omit_str=omit_str, platform=platform)
        resl = resd['res']
        if (resd.get('err')) and no_err and ((omit_str is None) or (not (omit_str in resd['res'][0]))):
            resl = resd['err']
        else:
            rtcode = 0
    if debug:
        print(rtcode)
        print(resl)
    return rtcode, resl

def get_ip_by_if(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', ifname.encode('ascii')[:15]))[20:24])

def get_local_ip(port=80):
    ip = None
    i = 0
    while (ip is None) and (i < len(DNS)):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((DNS[i], port))
            ip = s.getsockname()[0]
        except Exception as err:  
            raise Exception(__name__, err)
        finally:
            i = i + 1
            s.close()
    return ip


def get_local_hostname():
    return socket.gethostname() or None


def remote_cp(src, tgt):
    # username:password@ip:port@path
    (local, remote) = (src, tgt) if ('@' in tgt) else (tgt, src)
    auth, sock, remote_path = remote.split('@')
    username, password = auth.split(':')
    if not(':' in sock):
        sock = sock + ':22'
    t = paramiko.Transport(sock)
    t.connect(username=username, password=password)
    sftp = paramiko.SFTPClient.from_transport(t)
    res = None
    try:
        src_root = ''
        tgt_root = ''
        local = os.path.abspath(local)
        if (local == src):
            tgt_path = remote_path
            if os.path.isdir(src):
                src_files = deep_scan(src)
                if src.endswith(os.sep):
                    src_root = src.split(os.sep)[-2]
                else:
                    src_root = src.split(os.sep)[-1]
                while tgt_path.endswith(os.sep):
                    tgt_path = tgt_path[:-1]
                tgt_path = os.sep.join([tgt_path, src_root, ''])
            else:
                src_files = [src]
                if is_dir(sftp=sftp, path=tgt_path):
                    pass
            for fullpath in src_files:
                rel_path = ''
                if is_dir(src):
                    fplist = fullpath.replace(src, '').split(os.sep)
                    rel_path = os.sep.join(fplist[:-1])
                    filename = fplist[-1]
                else:
                    filename = fullpath.split(os.sep)[-1]
                while rel_path.startswith(os.sep):
                    rel_path = rel_path[1:]
                if (not tgt_path.endswith(os.sep)):
                    tgt_path = tgt_path + os.sep
                remotepath = tgt_path + rel_path
                if not(remotepath.endswith(os.sep)):
                    remotepath = remotepath + os.sep
                if not(is_dir(sftp=sftp, path=remotepath)):
                    sftp.mkdir(remotepath)
                if not(is_dir(path=fullpath)):
                    sftp.put(fullpath, remotepath + filename)
        elif(remote == src):
            src_root = ''
            src_path = remote_path
            if is_dir(sftp=sftp, path=src_path):
                src_files = deep_scan_remote(sftp, src_path)
                if src_path.endswith(os.sep):
                    src_root = src_path.split(os.sep)[-2]
                else:
                    src_root = src_path.split(os.sep)[-1]
            else:
                src_files = [src_path]
                src_path = os.sep.join(src_path.split(os.sep)[:-1])
            for fullpath in src_files:
                fplist = fullpath.replace(src_path, '').split(os.sep)
                rel_path = os.sep.join(fplist[:-1])
                filename = fplist[-1]
                if rel_path.startswith(os.sep):
                    rel_path = rel_path[1:]
                if (not local.endswith(os.sep)):
                    local = local + os.sep
                localpath = local + src_root + os.sep + rel_path
                if not(localpath.endswith(os.sep)):
                    localpath = localpath + os.sep
                if not(os.path.exists(localpath)):
                    os.mkdir(localpath)
                if not(is_dir(sftp=sftp, path=fullpath)):
                    sftp.get(fullpath, localpath + filename)
        res = tgt + os.sep + src_root
    except Exception as err:
        raise Exception(__name__, err)
    finally:
        t.close()
    return res


def remote_mkdir(sftp, path):
    path_split = path.split(os.sep)
    paths = []
    i = 0
    remote_path = os.sep.join(path_split[:len(path_split) - i])
    while (i < len(path_split)) and (not(is_dir(sftp=sftp, path=remote_path))):
#        print(remote_path, is_dir(sftp=sftp, path=remote_path))
        paths.append(remote_path)
        i = i + 1
        remote_path = os.sep.join(path_split[:len(path_split) - i])
    while (0 < len(paths)):
        sftp.mkdir(paths.pop())


if ('__main__' == __name__):
    print(get_local_ip())
