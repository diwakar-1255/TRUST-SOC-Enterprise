import json
from pathlib import Path


def load_state(path: Path) -> dict:
    if not path.exists():
        return {"sequence": 0, "last_hash": None}
    return json.loads(path.read_text())


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state))
    tmp.replace(path)
