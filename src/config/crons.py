import src.lib.commands.channels as channels
import src.lib.save_to_drive as save_to_drive
# Cron jobs.
crons = {
    "cron": {
        "#general": [
            (60, True, save_to_drive.cron),
            (300, True, channels.cron)
        ],
    }
}
