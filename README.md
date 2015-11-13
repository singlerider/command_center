# command_center

An automated notification and communications system for software service
emergencies.

Right now it's mostly a message logger for Slack messages to Google Drive,
though.

## Installation
Copy the config_example.py file in src/config to src/config/config.py

### Pre-game

First, you'll need a config file. From your project directory, run:

`cp src/config/config_example.py src/config/config.py`

Head over to

https://YOURSLACKCHANNEL.slack.com/admin/settings

and enable IRC gateways, then go to

https://YOURSLACKCHANNEL.slack.com/account/gateways

and get your gateway, username, and IRC-specific password and plug them into
your brand new config file.

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

From the project's root directory, run

`./serve`

## TODO

Fix errors for foreign character encoding
Integrate folder structure for GDrive uploads
