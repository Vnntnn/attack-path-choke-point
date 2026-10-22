"""Runs the normal `cartography` CLI, minus one call LocalStack community can
never answer: IAM Access Advisor's GenerateServiceLastAccessedDetails always
501s there, `iam.sync()` calls it unconditionally with no CLI flag to skip
it, and it runs before s3/ec2 in RESOURCE_FUNCTIONS order, so the whole aws
stage stalls before any real resource loads.

Deliberately minimal: no-ops one Cartography call for the LocalStack-community
gap above (real AWS gets it back for free). Upgrade path: revisit if this
repo's lab ever points at real AWS/LocalStack Pro, or upstream implements the
API.
"""

import sys

from cartography.intel.aws import iam

iam.sync_service_last_accessed_details = lambda *a, **kw: None

from cartography.cli import main  # noqa: E402  (must import after the patch above)

if __name__ == "__main__":
    sys.exit(main())
