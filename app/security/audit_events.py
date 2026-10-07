# ==========================================================
# AUTHENTICATION
# ==========================================================

USER_REGISTERED = "USER_REGISTERED"

LOGIN_SUCCESS = "LOGIN_SUCCESS"
LOGIN_FAILED = "LOGIN_FAILED"
LOGOUT = "LOGOUT"


# ==========================================================
# ACCOUNT MANAGEMENT
# ==========================================================

ACCOUNT_APPROVED = "ACCOUNT_APPROVED"
ACCOUNT_REJECTED = "ACCOUNT_REJECTED"
ACCOUNT_SUSPENDED = "ACCOUNT_SUSPENDED"

USER_CREATED = "USER_CREATED"
USER_DELETED = "USER_DELETED"

ROLE_CHANGED = "ROLE_CHANGED"


# ==========================================================
# PASSWORD
# ==========================================================

PASSWORD_CHANGED = "PASSWORD_CHANGED"
PASSWORD_CHANGE_FAILED = "PASSWORD_CHANGE_FAILED"


# ==========================================================
# SESSION
# ==========================================================

SESSION_CREATED = "SESSION_CREATED"
SESSION_EXPIRED = "SESSION_EXPIRED"
SESSION_INVALID = "SESSION_INVALID"


# ==========================================================
# AUTHORIZATION
# ==========================================================

ACCESS_GRANTED = "ACCESS_GRANTED"
ACCESS_DENIED = "ACCESS_DENIED"
UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS"


# ==========================================================
# CSRF / INPUT SECURITY
# ==========================================================

CSRF_REJECTED = "CSRF_REJECTED"


# ==========================================================
# MFA
# ==========================================================

MFA_SETUP_STARTED = "MFA_SETUP_STARTED"
MFA_SETUP_SUCCESS = "MFA_SETUP_SUCCESS"
MFA_SETUP_FAILED = "MFA_SETUP_FAILED"

MFA_LOGIN_REQUIRED = "MFA_LOGIN_REQUIRED"
MFA_LOGIN_SUCCESS = "MFA_LOGIN_SUCCESS"
MFA_LOGIN_FAILED = "MFA_LOGIN_FAILED"

MFA_RECOVERY_USED = "MFA_RECOVERY_USED"


# ==========================================================
# SECURITY / DETECTION
# ==========================================================

BRUTE_FORCE = "BRUTE_FORCE"
SUSPICIOUS_ACTIVITY = "SUSPICIOUS_ACTIVITY"
PRIVILEGE_CHANGE = "PRIVILEGE_CHANGE"
SESSION_HIJACK = "SESSION_HIJACK"
LOG_TAMPERING = "LOG_TAMPERING"


# ==========================================================
# CONTRACT EVENTS
# Reserved for teammate / contract module
# ==========================================================

CONTRACT_CREATED = "CONTRACT_CREATED"
CONTRACT_SHARED = "CONTRACT_SHARED"
CONTRACT_VIEWED = "CONTRACT_VIEWED"
CONTRACT_DOWNLOADED = "CONTRACT_DOWNLOADED"
CONTRACT_VALIDATED = "CONTRACT_VALIDATED"
CONTRACT_SIGNED = "CONTRACT_SIGNED"
CONTRACT_MODIFIED = "CONTRACT_MODIFIED"

INTEGRITY_FAILURE = "INTEGRITY_FAILURE"