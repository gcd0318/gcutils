import paramiko
import socket
import subprocess
import time
import traceback

from misc import exec_local_cmd

from const import TIMEOUT_s, SHORT_s, SCRIPT_EXECUTE_TIMEOUT_s, RETRY, LOCALS


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
