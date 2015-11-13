import os
import src.lib.irc as _irc
from src.config.config import *
import socket

def channels():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    irc = _irc.irc(config)
    sock.send('/list -yes' + '\r\n')
