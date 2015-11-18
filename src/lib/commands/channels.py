import json
import requests
import socket

slack_token = ""


def initial_channels(token=None):
    url = "https://slack.com/api/channels.list?token={0}".format(token)
    resp = requests.get(url)
    data = json.loads(resp.content)
    channels = ["#" + x["name"] for x in data["channels"]]
    print channels
    return channels


def channels():
    channels = initial_channels(slack_token)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    print "joined {0}".format(channels)


def cron(a=None):
    pass
