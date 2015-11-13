#!/usr/bin/python
# -*- coding: utf-8 -*-

#channel/channel_year_month_day.txt

from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive
from apiclient.discovery import build
from oauth2client.client import SignedJwtAssertionCredentials
import time
import os

def save_file_to_drive(log, channel, data): # log = filename to save as, data = the content (messages to save)
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
        gauth.LocalWebserverAuth()
    elif gauth.access_token_expired:
        # Refresh them if expired
        gauth.Refresh()
    else:
        # Initialize the saved creds
        gauth.Authorize()
    # Save the current credentials to a file
    gauth.SaveCredentialsFile("credentials.txt")

    drive = GoogleDrive(gauth)

    title = '{}_{}.txt'.format(channel, time.strftime('%Y_%m_%d'))
    log = drive.CreateFile({'title': title})
    log.SetContentString('Temporary')
    log.Upload(param={'convert': True}) # Files.insert()

    log['title'] = title  # Change title of the file
    log.Upload(param={'convert': True}) # Files.patch()

    content = log.GetContentString()  # 'Hello'
    log.SetContentString(data)
    log.Upload(param={'convert': True}) # Files.update()


def get_log_contents(folder, date, log_files):
    for log in log_files:
    #for log in os.listdir(folder):
        channel = log.rstrip(".txt").split("/")[3]
        filename = channel + ".txt"
        print channel
        with open("{}{}".format(folder, filename), 'r') as f:
            data = f.read()
            save_file_to_drive(log, channel, data)


def get_log_files():
    log_files = []
    date = time.strftime('%Y_%m_%d', time.gmtime())
    folder = 'src/logs/{}/'.format(date)
    for log in os.listdir(folder):
        if log.endswith(".txt"):
            log_files.append("{}{}".format(folder, log))
    print log_files
    get_log_contents(folder, date, log_files)

def cron(channel):  # todo remove this arg requirement.
    from config import previous_date
    current_date = time.strftime('%Y_%m_%d', time.gmtime())
    if current_date != previous_date:
        previous_date = current_date
        print "Saving files (by channel):"
        return get_log_files()