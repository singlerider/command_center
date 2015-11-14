import src.lib.save_to_drive as save_to_drive
import time
global config

previous_date = time.strftime("%Y_%m_%d", time.gmtime())

"""
Head over to
YOURSLACKCHANNEL.slack.com/admin/settings
to enable IRC gateways, then head to
YOURSLACKCHANNEL.slack.com/account/gateways
"""

channels_to_join = ["#general", "#random"]

for channel in channels_to_join:
    channel = channel.lstrip("#")

config = {
    # details required to login to twitch IRC server
    "server": "YOURSLACKCHANNEL.irc.slack.com",
    "port": 6667,
    "username": "YOURUSERNAME",
    "password": "YOURPASSWORD,

    "google_api": "",  # API Key
    "google_client": "",  # Client ID
    "google_secret": "",  # Client Secret

    "debug": True,
    "log_messages": True,

    "channels": channels_to_join,

    # Cron jobs.
    "cron": {
        "#general": [
            (60, True, save_to_drive.cron)  # run cron job every 60 seconds
        ],
    },
}
