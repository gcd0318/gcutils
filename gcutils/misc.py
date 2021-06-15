import datetime
import os
import random
import string
import time

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
