from Logger import Logger

class AppVendor:
    def __init__(self):
        self.logger = Logger(self)

    def __str__(self):
        return f"AppVendor"
    
    def run(self):
        self.logger.log("Running...")
