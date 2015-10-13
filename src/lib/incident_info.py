import lib.irc as irc_

class IndividualInfo(object):
    def __init__(self, config):
        self.irc = irc_.irc(config)
        self.contact_info = {}
        contact_info = self.contact_info

    def contact(name, team, email, phone_number):
        contact_info["first_name"] = name[0]
        contact_info["last_name"] = name[1]
        contact_info["team"] = team
        contact_info["email"] = email
        contact_info["phone_number"] = phone_number

        return contact_info
