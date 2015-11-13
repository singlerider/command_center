#channel/channel_year_month_day.txt

from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive
import time

from apiclient.discovery import build
from oauth2client.client import SignedJwtAssertionCredentials


def save_file(channel, data): # filename to save as, data is the content (messages to save)
    """Gets valid user credentials from storage.

    If nothing has been stored, or if the stored credentials are invalid,
    the OAuth2 flow is completed to obtain the new credentials.

    Returns:
        Credentials, the obtained credential.
    """

    # from google API console - convert private key to base64 or load from file
    gauth = GoogleAuth()
    # Try to load saved client credentials
    gauth.LoadCredentialsFile("mycreds.txt")
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
    gauth.SaveCredentialsFile("mycreds.txt")

    drive = GoogleDrive(gauth)

    title = '{}_{}.txt'.format(channel.lstrip("#"), time.strftime('%Y_%m_%d'))
    log = drive.CreateFile({'title': title})
    log.SetContentString('Temporary')
    log.Upload(param={'convert': True}) # Files.insert()

    log['title'] = title  # Change title of the file
    log.Upload(param={'convert': True}) # Files.patch()

    content = log.GetContentString()  # 'Hello'
    log.SetContentString(data)  # 'Hello World!'
    log.Upload(param={'convert': True}) # Files.update()

    """
    # Auto-iterate through all files that matches this query
    file_list = drive.ListFile({'q': "'root' in parents"}).GetList()
    for log in file_list:
      print 'title: %s, id: %s' % (log['title'], log['id'])

    # Paginate file lists by specifying number of max results
    for file_list in drive.ListFile({'maxResults': 10}):
      print 'Received %s files from Files.list()' % len(file_list) # <= 10
      for log in file_list:
        print 'title: %s, id: %s' % (log['title'], log['id'])
    """

save_file("#general", "FAKE message")
