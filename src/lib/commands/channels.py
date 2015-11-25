import json
import requests

slack_token = ""


def initial_channels(token=None):
    url = "https://slack.com/api/channels.list?token={0}".format(token)
    resp = requests.get(url)
    data = json.loads(resp.content)
    channels = ["#" + x["name"] for x in data["channels"]]
    print channels
    return channels


def cron(a=None):
    import time
    import requests
    import json
    channels_url = "https://slack.com/api/channels.list?token={0}".format(
        slack_token)
    channels_resp = requests.get(channels_url)
    channels_data = json.loads(channels_resp.content)
    channels = ["#" + x["name"] for x in channels_data["channels"]]
    with open("src/config/channels.json", "r") as f:
        channels_joined_dict = json.loads(f.read())
        channels_joined = channels_joined_dict["channels"]
    if set(channels) != set(channels_joined):
        channels_to_join = list(set(channels) - set(channels_joined))
        for channel in channels_to_join:
            join_url = "https://slack.com/api/channels.join?token={0}&name={1}".format(slack_token, channel.lstrip("#"))
            join_resp = requests.get(join_url)
            join_data = join_resp.content
            print "joined {0}".format(channel)
            time.sleep(1)
        channel_dict = {"channels": channels_joined + channels_to_join}
        with open("src/config/channels.json", "w") as f:
            f.write(json.dumps(channel_dict))
    return
