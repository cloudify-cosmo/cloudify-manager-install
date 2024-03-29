from __future__ import absolute_import

import sys
from os import geteuid, getegid
from os.path import join, isdir, expanduser
from subprocess import check_output

import logging

from .constants import BASE_LOG_DIR
from .utils import subprocess_preexec

BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = list(range(30, 38))

# The background is set with 40 plus the number of the color,
# and the foreground with 30

# These are the sequences need to get colored ouput
RESET_SEQ = "\033[0m"
COLOR_SEQ = "\033[0;%dm"
BOLD_SEQ = "\033[1;%dm"


LEVEL_COLORS = {
    'WARNING': BOLD_SEQ % YELLOW,
    'INFO': BOLD_SEQ % WHITE,
    'NOTICE': BOLD_SEQ % GREEN,
    'DEBUG': BOLD_SEQ % BLUE,
    'CRITICAL': BOLD_SEQ % YELLOW,
    'ERROR': BOLD_SEQ % RED
}

MSG_LEVEL_COLORS = {
    'WARNING': COLOR_SEQ % YELLOW,
    'INFO': COLOR_SEQ % WHITE,
    'NOTICE': COLOR_SEQ % GREEN,
    'DEBUG': COLOR_SEQ % BLUE,
    'CRITICAL': COLOR_SEQ % YELLOW,
    'ERROR': COLOR_SEQ % RED
}

FORMAT_MESSAGE = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'


# region notice log level

# Custom code that adds another log level (notice) in a green color
NOTICE_LOG_LEVEL = 25
logging.addLevelName(NOTICE_LOG_LEVEL, 'NOTICE')


def notice(self, message, *args, **kws):
    if self.isEnabledFor(NOTICE_LOG_LEVEL):
        self._log(NOTICE_LOG_LEVEL, message, args, **kws)


logging.Logger.notice = notice

# endregion


class ColoredFormatter(logging.Formatter):
    def format(self, record):
        level_color = LEVEL_COLORS[record.levelname]
        msg_color = MSG_LEVEL_COLORS[record.levelname]
        record.levelname = level_color + record.levelname + RESET_SEQ
        record.name = BOLD_SEQ % BLUE + record.name + RESET_SEQ
        record.msg = msg_color + record.msg + RESET_SEQ
        return logging.Formatter.format(self, record)


def get_file_handlers_level():
    # the handlers in the function name is actually handler's
    # because i assume there is only one file handler
    # and function gets the first and only one
    handlers = logging.getLogger().handlers[:]
    for handler in handlers:
        if isinstance(handler, logging.FileHandler):
            return handler.level


def set_file_handlers_level(level):
    # see comment on function above
    handlers = logging.getLogger().handlers[:]
    for handler in handlers:
        if isinstance(handler, logging.FileHandler):
            handler.setLevel(level)


def _setup_logger():
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    _setup_file_logger(logger)


logging_initialized = False


def setup_console_logger(verbose=False):
    # it is enough to init the logger only once for cfy_manager execution
    global logging_initialized
    if logging_initialized:
        return
    _setup_logger()
    # Requests is fairly verbose at INFO level; make it verbose only when
    # requested
    logging.getLogger('requests').setLevel(
        logging.DEBUG if verbose else logging.ERROR
    )
    logger = logging.getLogger()
    log_level = logging.DEBUG if verbose else logging.INFO
    out_sh = logging.StreamHandler(sys.stdout)
    out_sh.setLevel(log_level)
    out_sh.setFormatter(ColoredFormatter(FORMAT_MESSAGE))

    err_sh = logging.StreamHandler(sys.stderr)
    err_sh.setLevel(logging.ERROR)
    logger.addHandler(out_sh)
    logger.addHandler(err_sh)
    logging_initialized = True


def _create_log_dir():
    if geteuid() == 0:
        base_log_dir = BASE_LOG_DIR
    else:
        # Non sudo-requiring commands will be logged to the user's home
        # directory's cloudify area to avoid permissions issues.
        base_log_dir = expanduser('~/.cloudify')
    log_dir = join(base_log_dir, 'manager')
    if not isdir(log_dir):
        # Need to call subprocess directly, because utils.common depends on the
        # logger, and we'd get a cyclical import
        check_output(['mkdir', '-p', log_dir],
                     preexec_fn=subprocess_preexec)
        check_output(['chown', '-R',
                      '{0}:{1}'.format(geteuid(), getegid()),
                      log_dir], preexec_fn=subprocess_preexec)
    return log_dir


def _setup_file_logger(logger):
    log_dir = _create_log_dir()

    # The handler that outputs to file always outputs DEBUG
    fh = logging.FileHandler(join(log_dir, 'cfy_manager.log'))
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(FORMAT_MESSAGE))
    logger.addHandler(fh)


def get_logger(logger_name):
    return logging.getLogger('[{0}]'.format(logger_name.upper()))
