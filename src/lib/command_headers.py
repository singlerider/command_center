commands = {
    '!report': {
        'limit': 200,
        'argc': 1,
        'return': 'command',
        'space_case': True,
        'ul': 'mod',
        'usage': "!report [insert bug report text here]"
    },
    '!help': {
        'limit': 15,
        'return': 'There is a super useful README for lorenzo at http://www.twitch.tv/lorenzotherobot',
        'usage': '!help'
    },
    '!channels': {
        'limit': 0,
        'return': 'command',
        'usage': '!channels',
    },
    '!save_to_drive': {
        'limit': 0,
        'return': 'command',
        'usage': '!save_to_drive'
    }

}


def initalizeCommands(config):
    for channel in config['channels']:
        for command in commands:
            commands[command][channel] = {}
            commands[command][channel]['last_used'] = 0
