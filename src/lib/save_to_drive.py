#channel/channel_year_month_day.txt

from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive
import time

def save_file(title, channel, data): # filename to save as, data is the content (messages to save)
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


    gauth = GoogleAuth()
    gauth.LocalWebserverAuth()

    drive = GoogleDrive(gauth)

    log = drive.CreateFile({'title': '{}_{}.txt'.format(channel, time.strftime('%Y_%m_%d'))})
    log.SetContentString('Temporary')
    log.Upload(param={'convert': True}) # Files.insert()

    log['title'] = 'testlog.txt'  # Change title of the file
    log.Upload(param={'convert': True}) # Files.patch()

    content = log.GetContentString()  # 'Hello'
    log.SetContentString(f)  # 'Hello World!'
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
