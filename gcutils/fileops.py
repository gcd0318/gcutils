import glob
import os
import paramiko
import shutil
import stat

UTF8 = 'utf-8'

def file_count(path):
    res = 0
    for _, _, filenames in os.walk(os.path.abspath(path)):
        for filename in filenames:
            if os.path.isfile(filename):
                res = res + 1
    return res

def latest(path):
    latest_mtime = -1
    latest_filename = None
    for _, _, filenames in os.walk(os.path.abspath(path)):
        for filename in filenames:
            if os.path.isfile(filename):
                mtime = os.path.getmtime(filename)
                if(latest_mtime < mtime):
                    latest_mtime = mtime
                    latest_filename = filename
    return latest_filename, latest_mtime

def is_same(src, tgt):
    src = pathize(os.path.abspath(src))
    tgt = pathize(os.path.abspath(tgt))
    res = True
    if os.path.isdir(src):
        if os.path.isdir(tgt):
            fps = scan(src)
            i = 0
            while(res and (i < len(fps))):
                fp = fps[i]
                tail = fp.replace(src, '')
                if('' != res):
                    res = res and is_same(fp, tgt+tail)
                i = i + 1
        else:
            res = False
            if not res:
                print(src, tgt)
    else:
        if os.path.isdir(tgt):
            res = (get_encrypt(src) == get_encrypt(tgt + src.split(os.sep)[-1]))
            if not res:
                print(src, tgt)
        else:
            res = (get_encrypt(src) == get_encrypt(tgt))
            if not res:
                print(src, tgt)
    return res

def local_cp(src, tgt):
    src = pathize(os.path.abspath(src))
    tgt = pathize(os.path.abspath(tgt))
    if os.path.isdir(src):
        if os.path.isdir(tgt):
            for fp in scan(src):
                tgt_fp = tgt + fp.replace(src, '')
                if os.path.isdir(fp):
                    if not os.path.exists(tgt_fp):
                        os.mkdir(tgt_fp)
                local_cp(fp, tgt_fp)
        else:
            tgt = None
    else:
        if os.path.isdir(tgt):
            tgt = tgt + src.split(os.sep)[-1]
        else:
            if os.path.exists(tgt):
                os.remove(tgt)
        tgt = shutil.copy2(src, tgt)
    return tgt


def get_disk_usage(path='/'):
    st = os.statvfs(path)
    free = (st.f_bavail * st.f_frsize)
    total = (st.f_blocks * st.f_frsize)
    used = (st.f_blocks - st.f_bfree) * st.f_frsize
    return total, used, free

def get_path_size(path):
# todo: why 1024?
    import math

    size = 0
    if(os.path.isdir(path)):
        for root, dirs, files in os.walk(path):
            size = size + sum([math.ceil(os.path.getsize(os.path.join(root, name)) / 1024) * 1024 for name in files])
    elif(os.path.isfile(path)):
        # use ceil for larger estimation
        size = math.ceil(os.path.getsize(path) / 1024) * 1024
    return size

def scan(root='.', key='', skip=''):
    resl = []
    root = os.path.abspath(root)
    if os.path.isdir(root):
        root = pathize(root)
        for filepath in glob.glob(root + '*'):
            if os.path.isdir(filepath):
                if not (filepath.endswith(os.sep)):
                    filepath = filepath + os.sep
            if (key in filepath) and ((not skip) or (skip not in filepath)):
                resl.append(filepath)
    else:
        resl.append(root)
    return resl

def rooty(name, root):
    if not root.endswith('/'):
        root = root + '/'
    if not name.startswith('/'):
        name = root + name
    return name


def pathize(filepath, force=False):
    if os.path.isdir(filepath) or force:
        tmp = filepath.replace(os.sep+os.sep, os.sep)
        while(tmp != filepath):
            filepath, tmp = tmp, filepath.replace(os.sep+os.sep, os.sep)
        if not (filepath.endswith(os.sep)):
            filepath = filepath + os.sep
    return filepath


def deep_scan(root='.', key = '', skip=''):
    resl = []
    root = os.path.abspath(root)
    if os.path.isdir(root):
        root = pathize(root)
        for dirpath, dirnames, filenames in os.walk(root):
            if ([] == filenames):
                filenames.append('')
            for filepath in filenames:
                filename = os.path.join(dirpath, filepath)
                if (key in filename) and ((not skip) or (skip not in filename)):
                    resl.append(filename)
    else:
        resl.append(root)
    return resl


def is_dir(path, sock=None, sftp=None):
    res = False
    if (sock is None) and (sftp is None) and (not '@' in path):
        res = os.path.isdir(path)
    else:
        username = None
        password = None
        try:
            if ('@' in path):
                auth, sock, remote_path = path.split('@')
                username, password = auth.split(':')
                if not (':' in sock):
                    sock = sock + ':22'
            else:
                remote_path = path
            if sock is not None:
                t = paramiko.Transport(sock)
                t.connect(username=username, password=password)
                sftp = paramiko.SFTPClient.from_transport(t)
            res = stat.S_ISDIR(sftp.lstat(remote_path).st_mode)
        except Exception as err:
            raise Exception(__name__, err)
    return res

def makedirs(path):
    tgt_path = os.path.realpath.expanduser(path)
    if not os.path.exists(tgt_path):
        os.makedirs(path)

def get_encrypt(filepath, encrypt='sha512', enblock_size=1024*1024):
    res = None
    from hashlib import sha512 as encrypt_func
    if('md5' == encrypt):
        from hashlib import md5 as encrypt_func
    if('sha256' == encrypt):
        from hashlib import sha256 as encrypt_func
    absfp = os.path.abspath(filepath)
    if os.path.isfile(absfp):
        m = encrypt_func()
#        m.update(absfp.encode(UTF8))
        with open(absfp, 'rb') as f:
            b = f.read(enblock_size)
            while(b):
                m.update(b)
                b = f.read(enblock_size)
            res = m.hexdigest()
    elif os.path.isdir(absfp):
        absfp = pathize(absfp)
        pathencrypt = encrypt_func()
        pathencrypt.update(absfp.encode(UTF8))
        tmp_path = os.path.abspath('/tmp')
        makedirs(tmp_path)
        path_encrypt = tmp_path + os.sep + pathencrypt.hexdigest()
        with open(path_encrypt, 'w') as tmpf:
            encrypt_d = {}
            for filename in deep_scan(absfp):
                if(filename != absfp):
                    encrypt_d[filename.replace(absfp, '')] = get_encrypt(filename, encrypt=encrypt)
            for k, v in sorted(encrypt_d.items(), key=lambda item:item[0]):
                print(k, v, file=tmpf)
        res = get_encrypt(path_encrypt, encrypt=encrypt)
        os.remove(path_encrypt)
    return res

def deep_scan_remote(sftp, path):
    res = []
    if is_dir(path=path, sftp=sftp):
        if (not path.endswith(os.sep)):
            path = path + os.sep
        for fobj in sftp.listdir_attr(path):
            filepath = path + fobj.filename
            if stat.S_ISDIR(fobj.st_mode):
                res = res + deep_scan_remote(sftp, filepath)
            else:
                res.append(filepath)
    if ([] == res):
        res = [path]
    return res
