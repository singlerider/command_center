commands = {
    "!report": {
        "limit": 200,
        "argc": 1,
        "return": "command",
        "space_case": True,
        "ul": "mod",
        "usage": "!report [insert bug report text here]"
    },
    "!help": {
        "limit": 15,
        "return": """There is a super useful README for command_center at \
https://www.github.com/singlerider/command_center""",
        "usage": "!help"
    },
    "!channels": {
        "limit": 0,
        "return": "command",
        "usage": "!channels",
    },
}


def initalizeCommands(config):
    for channel in config["channels"]:
        for command in commands:
            commands[command][channel] = {}
            commands[command][channel]["last_used"] = 0
