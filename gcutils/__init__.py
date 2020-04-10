import configparser
import datetime
import glob
import os
import shutil
import time

def read_config(paramfile):
    resd = {}
    if os.path.isfile(paramfile):
        config = configparser.ConfigParser()
        config.read(paramfile)
        for sect in config:
            params = {}
            section = config[sect]
            for key in section:
                params[key] = section[key]
            resd[sect] = params
    return resd

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

if ('__main__' == __name__):
    val = '''
    {
{attributeID}: {value}
includefield: {includefield}
fuzzymatch: {fuzzymatch}
limit: {limit}
offset: {offset}
}'''
    v2d = value2dict(val)
    print(v2d)
    print(type(v2d))
#    print(scan('.', 'case', 'pycache'))
#    print(deep_scan('.', 'case', 'pycache'))
#    print(read_config('/Users/guochen/work/prod/cars/dicomapi/cases/query_all_studies.cases'))
    val = '[1,2,3,4,5]'
    print(value2list(val))
