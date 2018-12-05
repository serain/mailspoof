class SPFRecurse(Exception):
    def __init__(self, message, recursive_domain):
        super(SPFRecurse, self).__init__(message)
        self.recursive_domain = recursive_domain

class WHOAPIException(Exception):
    pass
