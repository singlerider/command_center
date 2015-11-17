# command_center

An automated notification and communications system for software service
emergencies.

Right now it's mostly a message logger for Slack messages to Google Drive,
though.

## Installation

### Important

This project was made using Python 2.7.x

Due to the type of string formatting employed, this will not work prior to 2.7.

It is possible to set up an environment with 2.7, even if your server's primary
env is 2.6 or earlier. With your favorite package manager, install `python2.7`
using one of the various online guides. Once that's done, install the
dependencies as outlined below, with the exception of replacing `pip` with
`pip-2.7`.

### Pre-game

First, you'll need a config file. From your project directory, run:

`cp src/config/config_example.py src/config/config.py`

Head over to

https://YOURSLACKCHANNEL.slack.com/admin/settings

and enable IRC gateways, then go to

https://YOURSLACKCHANNEL.slack.com/account/gateways

and get your gateway, username, and IRC-specific password and plug them into
your brand new config file.

### Google API

#### Python Quickstart

Use the wizard at:

https://console.developers.google.com/flows/enableapi?apiid=drive

to get started creating your application and managing your auth flow.

Once the Google Drive API is enabled, go the the "Credentials" tab in the
Developer's Console.

#### Add Credentials

Click "Add Credentials" and generate an API Key (Server Key) and an OAuth
2.0 Client ID (Other)

Download your generated clien_secret json file and rename it to
"client_secrets.json" then place it in your project's root directory - PyDrive
looks for this specific file in this specific place.

### Virtual Environment

I would recommend running this in a virtual environment to keep your
dependencies in check. If you'd like to do that, run:

`sudo pip install virtualenv`

Followed by:

`virtualenv venv`

This will create an empty virtualenv in your project directory in a folder
called "venv." To enable it, run:

`source venv/bin/activate`

and your console window will be in that virtualenv state. To deactivate, run:

`deactivate`

### Dependencies

To install all dependencies locally (preferably inside your activated
virtualenv), run:

`pip install -r requirements.txt`

## To Run

From the project's root directory, run:

`./serve`

The first time you run this, a message in the console will ask you to paste a
link into a browser's address bar and authorize the application to modify
your Google Drive files. After you accept, you will see a code that should be
pasted back into the console. After this initial authorization, the app
will be connected to your GDrive account.

## TODO

Fix errors for foreign character encoding
