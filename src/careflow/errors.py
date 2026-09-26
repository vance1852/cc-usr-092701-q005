"""稳定的领域异常及其 HTTP 表达。"""


class CareflowError(Exception):
    code = "careflow_error"
    status = 400

    def __init__(self, message: str, *, details: dict | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ValidationError(CareflowError):
    code = "invalid_request"
    status = 422


class NotFound(CareflowError):
    code = "not_found"
    status = 404


class Conflict(CareflowError):
    code = "conflict"
    status = 409


class Forbidden(CareflowError):
    code = "forbidden"
    status = 403


class Unauthorized(CareflowError):
    code = "unauthorized"
    status = 401


class StorageFailure(CareflowError):
    code = "storage_failure"
    status = 503
