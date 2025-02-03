import configparser
import datetime
import os
import random
import string
import threading
import time


def get_func(f):
    def _wrapper(*argc, **kwargs):
        logger.info('running ' + f.__name__)
        while True:
            try:
                f(*argc, **kwargs)
            except Exception as err:
                import traceback
                logger.error(f.__name__)
                logger.error(str(err))
                logger.error(traceback.format_exc())
            time.sleep(PERIOD_s)
    return _wrapper


def idle(msg, mark='y', case_match=False):
    msg = msg.strip() + ' '
    c = ''
    if not case_match:
        mark = mark.lower()
    while not(c == mark):
        c = input(msg)
        if not case_match:
            c = c.lower()


def randstr(length=4):
    return ''.join(random.sample(string.ascii_letters + string.digits, length))


def weekday(t=None):
    if t is None:
        t = datetime.date.today()
    d = datetime.date.weekday(t)
    if 6 == d:
        res = '日'
    else:
        res = str(d + 1)
    return res


def comp_list(l1, l2, order=False):
    res = (len(l1) == len(l2))
    i = 0
    if order:
        while res and (i < len(l1)):
            res = (l1[i] == l2[i])
            i = i + 1
    else:
        while res and (i < len(l1)):
            res = (l1[i] in l2)
            i = i + 1
    return res


def value2dict(value):
    res = []
#    value = value.replace('\n', ',').replace(',,', ',')
    for line in value.split('\n'):
        line = line.strip()
        if ':' in line:
            k, v = line.split(':')
            res.append('"' + k.strip() + '": "' + v.strip() + '"')
    return eval('{' + ', '.join(res) + '}')


def value2list(value):
    value = value.strip()
    return [p.strip() for p in value[1:-1].split(',')]


def timestamp(t=None, fmt='%Y%m%d_%H%M%S.%f'):
    res = None
    if t is None:
        t = datetime.datetime.now()
    if isinstance(t, time.struct_time):
        if fmt.endswith('.%f'):
            fmt = fmt[:-3]
        res = time.strftime(fmt, t)
    elif isinstance(t, datetime.datetime):
        res = t.strftime(fmt)
    return res


def read_config(paramfile, include_default=True, allow_empty=True):
    resd = {}
    if os.path.isfile(paramfile):
        config = configparser.ConfigParser()
        config.read(paramfile)
        for sect in config:
            if (include_default or ('DEFAULT' != sect)):
                params = {}
                section = config[sect]
                for key in section:
                    params[key] = section[key]
                if (allow_empty or (0 < len(params))):
                    resd[sect] = params
    return resd


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
            Collect lines from 'stream' and put them in 'queue'.
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

    thread = threading.Thread(target=target)
    thread.start()
    thread.join(timeout=timeout)
    if thread.is_alive():
        if ref['process'] is not None:
            ref['process'].terminate()
            ref['process'].wait()
        thread.join()

    return ref['process'].returncode, ref['stdout'], ref['stderr']

MAX_BLOCK = 1024 * 1024

def encrypt(data, encrypt='sha512', bsize=MAX_BLOCK):
    res = None
    from hashlib import sha512 as encrypt_func
    if('md5' == encrypt):
        from hashlib import md5 as encrypt_func
    if('sha256' == encrypt):
        from hashlib import sha256 as encrypt_func
    m = encrypt_func()
    i = 0
    blk = data[i: i + bsize]
    while blk:
        b = blk.encode('ascii')
        m.update(b)
        i = i + bsize
        blk = data[i: i + bsize]

    res = m.hexdigest()

    return res


