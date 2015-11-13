

def new_day_tasks(channel, log_files):

    get_log_files(channel)

    for log in log_files:
        with open("{}.txt".format(log), "r") as myfile:
            data = myfile.read()
        save_file_to_drive(channel, data)
