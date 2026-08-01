import re

from sqlalchemy import select

from trustsoc.config import get_settings
from trustsoc.database import SessionLocal
from trustsoc.models import DetectionRule, Organization, User, UserRole
from trustsoc.security import hash_password


def slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


async def bootstrap() -> None:
    settings = get_settings()
    async with SessionLocal() as db:
        org = await db.scalar(
            select(Organization).where(Organization.name == settings.bootstrap_org_name)
        )
        if org is None:
            org = Organization(
                name=settings.bootstrap_org_name, slug=slugify(settings.bootstrap_org_name)
            )
            db.add(org)
            await db.flush()
        user = await db.scalar(
            select(User).where(User.email == str(settings.bootstrap_admin_email).lower())
        )
        if user is None:
            db.add(
                User(
                    organization_id=org.id,
                    email=str(settings.bootstrap_admin_email).lower(),
                    password_hash=hash_password(settings.bootstrap_admin_password),
                    role=UserRole.platform_admin,
                )
            )
        if not await db.scalar(
            select(DetectionRule).where(DetectionRule.organization_id == org.id).limit(1)
        ):
            db.add_all(
                [
                    DetectionRule(
                        organization_id=org.id,
                        external_id="TSOC-SIGMA-001",
                        name="Suspicious PowerShell",
                        severity="high",
                        source_types=["sysmon", "windows_event", "wazuh"],
                        required_fields=["process_name", "command_line", "user"],
                        mitre_techniques=["T1059.001"],
                        protected_asset_types=["endpoint", "domain_controller"],
                    ),
                    DetectionRule(
                        organization_id=org.id,
                        external_id="TSOC-AUTH-001",
                        name="Repeated Failed Logon",
                        severity="medium",
                        source_types=["windows_event", "auditd", "wazuh"],
                        required_fields=["user", "source_ip", "outcome"],
                        mitre_techniques=["T1110"],
                        protected_asset_types=["endpoint", "domain_controller", "server"],
                    ),
                    DetectionRule(
                        organization_id=org.id,
                        external_id="TSOC-LOG-001",
                        name="Security Log Cleared",
                        severity="critical",
                        source_types=["windows_event", "wazuh"],
                        required_fields=["event_id", "user", "timestamp"],
                        mitre_techniques=["T1070.001"],
                        protected_asset_types=["endpoint", "domain_controller", "server"],
                    ),
                ]
            )
        await db.commit()
