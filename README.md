# command_center
An automated notification and communications system for software service emergencies.

## Installation
Copy the config_example.py file in src/config to src/config/config.py

Head over to
YOURSLACKCHANNEL.slack.com/admin/settings
and enable IRC gateways, then go to
YOURSLACKCHANNEL.slack.com/account/gateways
and get your gateway, username, and IRC-specific password and replace the contents of config.py.

### Dependencies

https://developers.google.com/gdata/articles/python_client_lib?hl=en#macintosh

https://github.com/google/gdata-python-client

## To Run
From the project's root directory, simply run ./serve
