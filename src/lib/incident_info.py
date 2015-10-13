import src.bot
import lib.irc as irc_
from threading import Thread

class IndividualInfo(object, channel, Thread):

    def __init__(self, config, irc, channel, user):
        self.contact_info = {}
        self.irc = irc
        self.channel = channel
        self.user = user
        self.commander = ""
        contact_info = self.contact_info


    def make_commander(user):
        self.commander = user
        resp = "Attention! {} has reported an issue! Route all communication \
        through them. Stand by for more info!".format(self.commander)
        self.irc.send_message(channel, resp)


    def contact(name, team, email, phone_number):
        contact_info["first_name"] = name[0]
        contact_info["last_name"] = name[1]
        contact_info["team"] = team
        contact_info["email"] = email
        contact_info["phone_number"] = phone_number
        return contact_info


    def question(name=None, topic):
        resp = ""
        if name != None:
            resp = "What is {}'s {}?".format(name, topic)
        else:
            resp = "What is this person's name?"
        self.irc.send_message(channel, resp)


    def ask_questions():
        if "first_name" not in contact_info:
            question("name", "first name")
            #contact_info[topic.replace(" ", "_")] = ""
        first_name = contact_info["first_name"]
        if "last_name" not in contact_info:
            question(first_name, "last name")
        if "team" not in contact_info:
            question(first_name, "team")
        if "email" not in contact_info:
            question(first_name, "email")
        if "phone_number" not in contact_info:
            question(first_name, "phone number")
        return
