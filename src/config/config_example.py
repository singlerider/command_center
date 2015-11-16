from src.lib.commands.channels import channels
import src.lib.save_to_drive as save_to_drive
global config


"""
Head over to
YOURSLACKCHANNEL.slack.com/admin/settings
to enable IRC gateways, then head to
YOURSLACKCHANNEL.slack.com/account/gateways
"""

slack_token = ""
# Slack Token obtained from https://api.slack.com/web#basics
channels_to_join = channels(slack_token)

for channel in channels_to_join:
    channel = channel.lstrip("#")

config = {
    # details required to login to Slack IRC server
    "server": "YOURSLACKCHANNEL.irc.slack.com",
    "port": 6667,
    "username": "YOURUSERNAME",
    "password": "YOURPASSWORD-novoice",

    "debug": True,
    "log_messages": True,

    "channels": channels_to_join,

    # Cron jobs.
    "cron": {
        "#general": [
            (10, True, save_to_drive.cron)
        ],
    },
}
