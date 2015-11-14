from src.config.config import slack_token
import requests
import json

def emojis():
    url = "https://slack.com/api/emoji.list?token={0}".format(slack_token)
    resp = requests.get(url)
    data = json.loads(resp.content)
    emoji_list = [x for x in data["emoji"].iterkeys()]
    return data, emoji_list
