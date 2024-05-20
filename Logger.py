import time

class Logger:
    def __init__(self, class_):
        self.class_name = str(class_)
        self.logs = []
        self.print_logs = False

    def log(self, message):
        log = f"{time.strftime('%H:%M:%S')} {self.class_name}: {message}"
        self.logs.append(log)
        if self.print_logs:
            print(log)
