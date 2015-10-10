global config

"""
Head over to
YOURSLACKCHANNEL.slack.com/admin/settings
to enable IRC gateways, then head to
YOURSLACKCHANNEL.slack.com/account/gateways
"""

channels_to_join = ['#general', '#random']

for channel in channels_to_join:
    channel = channel.lstrip('#')

config = {
    # details required to login to twitch IRC server
    'server': 'YOURSLACKCHANNEL.irc.slack.com',
    'port': 6667,
    'username': 'YOURREGISTEREDSLACKUSERNAME',
    # get this from http://twitchapps.com/tmi/
    'password': 'YOURSLACKCHANNEL.passwordhash72h349242hndas',

    'debug': True,
    'log_messages': True,

    'channels': channels_to_join,

    # Cron jobs.
    'cron': {
        '#example_channel': [

        ],
    },
}
