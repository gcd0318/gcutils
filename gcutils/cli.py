from const import SCRIPT_EXECUTE_TIMEOUT_s, TIMEOUT_s, SHORT_s, RETRY

def run_shell_cmd(cmd):
    try:
        rc = subprocess.call(cmd, shell=True)
        if rc != 0:
            raise Exception(__name__, "Fail to run %s , rc: %s" % (cmd, rc))
    except OSError as err:
        raise Exception(__name__, err)
    return rc


def exec_local_cmd(args, shell=True, with_blank=False):
    resl = []
    try:
        process = subprocess.Popen(args, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        rtcode = process.returncode
        output = stdout + stderr
        process.poll()
        if (0 != rtcode):
            output = stderr
    except OSError as e:
        rtcode = e.errno
        output = "Fail to run command: %s" % e
    for l in output.decode('utf-8').split('\n'):
        if ((0 < len(l)) or with_blank):
            resl.append(l)
    return rtcode, resl


def run_shell_script(args, shell=False, timeout=SCRIPT_EXECUTE_TIMEOUT_s, return_output=False):
    command = Command(args)
    return command.run(shell=shell, timeout=timeout, return_output=return_output)


class Command(object):
    def __init__(self, cmd):
        self.cmd = cmd
        self.process = None
        self.error_message = None

    def run(self, shell=False, timeout=SCRIPT_EXECUTE_TIMEOUT_s, return_output=False):
        try:
            def kill_process():
                if self.process.poll() is None:
                    self.process.kill()
                    self.error_message = "shell process killed by timeout, timeout=%s" % timeout

            self.process = subprocess.Popen(self.cmd, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                            close_fds=True)
            # start timer
            t = threading.Timer(timeout, kill_process)
            t.start()

            # wrap self.process.stdout with a NonBlockingStreamReader object:
            nbsr = NonBlockingStreamReader(self.process.stdout)

            shell_output = ""

            # print the output in real-time
            while self.process.poll() is None:
                line = nbsr.readline(0.1)  # 0.1 secs to let the shell output the result
                if line:
                    shell_output += line

            # When the subprocess terminates there might be unconsumed output that still needs to be processed.
            content = nbsr.readline(1)
            if content:
                shell_output += content

            # cancel timer
            t.cancel()
            if return_output:
                output = shell_output if self.process.returncode == 0 else self.error_message
                return self.process.returncode, output
            else:
                return self.process.returncode, self.error_message
        except OSError as e:
            error_message = "Fail to run command: %s" % e
            return e.errno, error_message



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

