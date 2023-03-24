import logging
import logging.handlers

def mk_log(logfilename, when="D", interval=1, backup_count=10, level=logging.DEBUG):
    logger = logging.getLogger()
    fh = logging.handlers.TimedRotatingFileHandler(logfilename, when, interval, backup_count)
    fh.setFormatter(logging.Formatter('%(asctime)s %(filename)s_%(lineno)d: [%(levelname)s] %(message)s', '%Y-%m-%d %H:%M:%S'))
    logger.addHandler(fh)
    logger.setLevel(level)
    return logger
