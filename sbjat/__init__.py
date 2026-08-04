"""SenderBase Jira Automation Tool package."""

import warnings

# macOS system Python 3.9 links against LibreSSL. urllib3 2.x reports this at
# import time, but the automation intentionally supports that existing runtime.
warnings.filterwarnings(
    "ignore",
    message=r"urllib3 v2 only supports OpenSSL 1\.1\.1\+.*",
    category=Warning,
    module=r"urllib3(?:\..*)?",
)
