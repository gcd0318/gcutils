import paramiko
import socket
import subprocess
import time
import traceback

TIMEOUT_s = 60
SHORT_s = 10
SCRIPT_EXECUTE_TIMEOUT_s = 60

RETRY = 10
LOCALS = ('localhost', '127.0.0.1')

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


class NonBlockingStreamReader:
    def __init__(self, stream):
        '''
        stream: the stream to read from.
                Usually a process' stdout or stderr.
        '''

        self._s = stream
        self._q = Queue()

        def _populateQueue(stream, queue):
            '''
            Collect lines from 'stream' and put them in 'quque'.
            '''

            while True:
                line = stream.readline()
                if line:
                    queue.put(line)
                else:
                    break
                    # raise UnexpectedEndOfStream

        self._t = threading.Thread(target=_populateQueue,
                                   args=(self._s, self._q))
        self._t.daemon = True
        self._t.start()  # start collecting lines from the stream

    def readline(self, timeout=None):
        try:
            return self._q.get(block=timeout is not None,
                               timeout=timeout)
        except Exception as err:
            return None


def execute(command, *args, **kwargs):
    """
    Execute an command then return its return code.
    :type command: str or unicode
    :param timeout: timeout of this command
    :type timeout: int
    :rtype: (int, str, str)
    """

    timeout = kwargs.pop("timeout", None)
    command_list = [command, ]
    command_list.extend(args)

    ref = {
        "process": None,
        "stdout": None,
        "stderr": None,
    }

    def target():
        ref['process'] = subprocess.Popen(
            " ".join(command_list),
            shell=True,
            close_fds=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        ref['stdout'], ref['stderr'] = ref['process'].communicate()

    thread = Thread(target=target)
    thread.start()
    thread.join(timeout=timeout)
    if thread.is_alive():
        if ref['process'] is not None:
            ref['process'].terminate()
            ref['process'].wait()
        thread.join()

    return ref['process'].returncode, ref['stdout'], ref['stderr']

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
