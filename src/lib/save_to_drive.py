#! /usr/bin/python2.7
# -*- coding: utf-8 -*-

# channel/channel_year_month_day.txt

from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive
from apiclient.discovery import build
from oauth2client.client import SignedJwtAssertionCredentials
import time
import os


def get_log_files(previous_date):
    log_files = []
    folder = "src/logs/{0}/".format(previous_date)
    for log in os.listdir(folder):
        if log.endswith(".txt"):
            log_files.append("{0}{1}".format(folder, log))
    print log_files
    return folder, log_files


def save_file_to_drive(log, channel, data):  # log = filename to save as, data
    # = the content (messages to save)
    """Gets valid user credentials from storage.
    If nothing has been stored, or if the stored credentials are invalid,
    the OAuth2 flow is completed to obtain the new credentials.
    Returns:
    Credentials, the obtained credential.
    """

    # from google API console - convert private key to base64 or load from file
    gauth = GoogleAuth()
    # Try to load saved client credentials
    gauth.LoadCredentialsFile("credentials.txt")
    if gauth.credentials is None:
        print "No creds file"
        # Authenticate if they're not there
        gauth.CommandLineAuth()
    elif gauth.access_token_expired:
        # Refresh them if expired
        gauth.Refresh()
    else:
        # Initialize the saved creds
        gauth.Authorize()
    # Save the current credentials to a file
    gauth.SaveCredentialsFile("credentials.txt")

    drive = GoogleDrive(gauth)

    title = "{0}_{1}.txt".format(channel, time.strftime("%Y_%m_%d"))
    log = drive.CreateFile({"title": title})
    log.SetContentString("Temporary")
    log.Upload(param={"convert": True})  # Files.insert()
    log["title"] = title  # Change title of the file
    log.Upload(param={"convert": True})  # Files.patch()

    content = log.GetContentString()  # "Hello"
    log.SetContentString(data)
    log.Upload(param={"convert": True})  # Files.update()


def save_logs_to_drive(previous_date):
    folder, log_files = get_log_files(previous_date)
    for log in log_files:
        channel = log.rstrip(".txt").split("/")[3]
        filename = channel + ".txt"
        print channel
        with open("{0}{1}".format(folder, filename), "r") as f:
            data = f.read()
            save_file_to_drive(log, channel, data)


def cron(channel):  # todo remove this arg requirement.
    try:
        from src.config.config import previous_date  # gets assigned as program
        # is first run
        print previous_date
        current_date = time.strftime("%Y_%m_%d", time.gmtime())
        if current_date != previous_date:
            date_to_log = previous_date  # reassign this to a new variable
            previous_date = current_date  # reset this here just in case cron
            # job takes more than one minute
            print "Date Not Matched"
            print "Saving files (by channel):"
            save_logs_to_drive(date_to_log)  # save all logs to drive
            return
        else:
            print (
                "previous_date:", previous_date, "current_date:", current_date,
                "@", time.strftime("%H:%M:%SZ", time.gmtime())
                )
    except Exception as error:
        print str(error)


if __name__ == "__main__":
    save_file_to_drive("TESTFILE.txt", "#fakechannel", "TESTDATA")
