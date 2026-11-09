import os

DEBUG = True  # VULN: MISCONFIG
ALLOWED_HOSTS = ["*"]  # VULN: MISCONFIG
TEMPLATE_DEBUG = os.environ.get("TEMPLATE_DEBUG") == "1"
CSRF_TRUSTED_ORIGINS = ["https://app.example.com"]
