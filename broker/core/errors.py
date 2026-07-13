class ProviderError(Exception):
    def __init__(self, reason, message=None, status=400):
        super().__init__(message or reason)
        self.reason = reason
        self.message = message or reason
        self.status = status
