import time

class Logger:
    def __init__(self, class_):
        self.class_name = class_.__class__.__name__
        self.logs = []

    def log(self, message):
        log = f"{time.strftime('%H:%M:%S')} {self.class_name}: {message}"
        self.logs.append(log)
        print(log)
