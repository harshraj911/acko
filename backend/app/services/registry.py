from pathlib import Path

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import ActivityLog, Service


def infer_ecosystem(root: Path) -> str:
    if (root / "package.json").exists():
        return "npm"
    if any(root.glob("requirements*.txt")) or (root / "requirements.lock").exists():
        return "PyPI"
    return "unknown"


def register_kit_services(db: Session, kit_path: Path | None = None) -> int:
    services_dir = (kit_path or settings.kit_path) / "services"
    if not services_dir.is_dir():
        raise FileNotFoundError(f"Services directory not found: {services_dir}")
    created = 0
    for descriptor in sorted(services_dir.glob("*/service.yaml")):
        data = yaml.safe_load(descriptor.read_text(encoding="utf-8")) or {}
        name = data.get("name")
        if not name:
            continue
        current = db.scalar(select(Service).where(Service.name == name))
        if current:
            current.owner = data.get("owner", current.owner)
            current.tier = int(data.get("tier", current.tier))
            current.internet_facing = bool(data.get("internet_facing", current.internet_facing))
            current.description = data.get("description", current.description)
            current.root_path = str(descriptor.parent.resolve())
            current.ecosystem = infer_ecosystem(descriptor.parent)
        else:
            db.add(Service(
                name=name,
                owner=data.get("owner", "Unknown"),
                tier=int(data.get("tier", 3)),
                internet_facing=bool(data.get("internet_facing", False)),
                description=data.get("description", ""),
                root_path=str(descriptor.parent.resolve()),
                ecosystem=infer_ecosystem(descriptor.parent),
            ))
            created += 1
            db.flush()
            db.add(ActivityLog(
                entity_type="service", entity_id=name, event_type="service.registered",
                service_id=db.scalar(select(Service.id).where(Service.name == name)),
                details_json="{}",
            ))
    db.commit()
    return created
