class ProviderError(Exception):
    def __init__(self, reason, message=None, status=400, audit_context=None):
        super().__init__(message or reason)
        self.reason = reason
        self.message = message or reason
        self.status = status
        self.audit_context = audit_context or {}
