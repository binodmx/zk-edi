import time

class Logger:
    def __init__(self, class_):
        self.class_name = str(class_)
        self.logs = []
        self.print_logs = True

    def log(self, message):
        log = f"{time.strftime('%H:%M:%S')} {self.class_name}: {message}"
        self.logs.append(log)
        if self.print_logs:
            print(log)

    def write(self, key, message):
        with open("logs.txt", "a") as f:
            l = (80-len(key)) // 2
            r = 80 - len(key) - l
            f.write("-"*l + key + "-"*r + "\n")
            f.write(message + "\n")
            f.write("-"*80 + "\n")
