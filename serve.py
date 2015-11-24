#!/usr/bin/env python2.7

from sys import argv
from src.bot import *
from src.config.config import *
from src.config.crons import *
import datetime

bot = Roboraj(config, crons).run()
