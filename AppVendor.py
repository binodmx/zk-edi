from Logger import Logger

class AppVendor:
    def __init__(self):
        self.logger = Logger(self)

    def __str__(self):
        return f"AppVendor"
    
    def run(self):
        self.logger.log("Running...")

    def getdata():
        # 1. listen to the data from the edge servers until a certain timeout
        # 2. choose the longest array from received data and create a matrix
        # 3. fill the missing values with -1 to indicate failures (missing data)
        # 4. now replace negative values according to the similarity. however, 
        # outliers cannot be cluster heads.
        pass
