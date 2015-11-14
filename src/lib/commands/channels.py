import json
import requests


def channels(token):
    url = "https://slack.com/api/channels.list?token={0}".format(token)
    resp = requests.get(url)
    data = json.loads(resp.content)
    channels = ["#" + x["name"] for x in data["channels"]]
    return channels
