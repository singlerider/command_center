import src.lib.commands.channels as channels
import src.lib.save_to_drive as save_to_drive
import src.bot as bot
# Cron jobs.
crons = {
    "cron": {
        "#general": [
            (60, True, save_to_drive.cron),
            (1, True, bot.join_cron)
        ],
    }
}
