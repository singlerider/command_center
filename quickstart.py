from __future__ import print_function
import httplib2
import os

from apiclient import discovery
import oauth2client
from oauth2client import client
from oauth2client import tools
from config import config
from apiclient import errors
from apiclient.http import MediaFileUpload
# ...

try:
    import argparse
    flags = argparse.ArgumentParser(parents=[tools.argparser]).parse_args()
except ImportError:
    flags = None

SCOPES = 'https://www.googleapis.com/auth/drive'
CLIENT_SECRET_FILE = 'client_secret_385215132261-l215r6mnaavg5r7vn6r9s5m7t69jbi0u.apps.googleusercontent.com.json'
APPLICATION_NAME = 'cloudbot'


def get_credentials():
    """Gets valid user credentials from storage.

    If nothing has been stored, or if the stored credentials are invalid,
    the OAuth2 flow is completed to obtain the new credentials.

    Returns:
        Credentials, the obtained credential.
    """
    home_dir = os.path.expanduser('~')
    credential_dir = os.path.join(home_dir, '.credentials')
    if not os.path.exists(credential_dir):
        os.makedirs(credential_dir)
    credential_path = os.path.join(credential_dir,
                                   'drive-python-quickstart.json')

    store = oauth2client.file.Storage(credential_path)
    credentials = store.get()
    if not credentials or credentials.invalid:
        flow = client.flow_from_clientsecrets(CLIENT_SECRET_FILE, SCOPES)
        flow.user_agent = APPLICATION_NAME
        if flags:
            credentials = tools.run_flow(flow, store, flags)
        else: # Needed only for compatibility with Python 2.6
            credentials = tools.run(flow, store)
        print('Storing credentials to ' + credential_path)
    return credentials

def insert_file(service, title, description, parent_id, mime_type, filename):
  """Insert new file.

  Args:
    service: Drive API service instance.
    title: Title of the file to insert, including the extension.
    description: Description of the file to insert.
    parent_id: Parent folder's ID.
    mime_type: MIME type of the file to insert.
    filename: Filename of the file to insert.
  Returns:
    Inserted file metadata if successful, None otherwise.
  """
  media_body = MediaFileUpload(filename, mimetype=mime_type, resumable=True)
  body = {
    'title': title,
    'description': description,
    'mimeType': mime_type
  }
  # Set the parent folder.
  if parent_id:
      body['parents'] = [{'id': parent_id}]

  try:
      file = service.files().insert(
        body=body,
        media_body=media_body).execute()

    # Uncomment the following line to print the File ID
    # print 'File ID: %s' % file['id']

      return file
  except errors.HttpError as error:
    print(error)
    return None

def upload():
    import requests
    home_dir = os.path.expanduser('~')
    url = "https://www.googleapis.com/upload/drive/v2/files?uploadType=media?convert=true"
    headers = {
        "Host": "www.googleapis.com",
        "Content-Type": "text/plain",
        "Content-Length": "number_of_bytes_in_file",
        "Authorization": "Bearer {}".format(config["google_api"])
    }
    resp = requests.post(url=url, headers=headers)
    data = resp.content
    print data

def main():
    """Shows basic usage of the Google Drive API.

    Creates a Google Drive API service object and outputs the names and IDs
    for up to 10 files.
    """
    credentials = get_credentials()
    http = credentials.authorize(httplib2.Http())
    service = discovery.build('drive', 'v2', http=http)

    results = service.files().list(maxResults=10).execute()
    items = results.get('items', [])

    insert_file(service, "word_freq_1447229808", "log", "bsiufkV0ZVF1M2FEZHNaN1VoekZfQk9iQktZNGVGMFhOWWxaSmcxc2dHMjlnRHM", "text/plain", "word_freq_1447229808.txt")

    if not items:
        print('No files found.')
    else:
        print('Files:')
        for item in items:
            print('{0} ({1})'.format(item['title'], item['id']))



if __name__ == '__main__':
    main()
