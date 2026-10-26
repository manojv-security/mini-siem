"""Shared pytest fixtures."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from siem import create_app, db  # noqa: E402
from siem.detection import default_config  # noqa: E402
from siem.samples import generate_samples  # noqa: E402


@pytest.fixture
def conn():
    connection = db.connect(":memory:")
    yield connection
    connection.close()


@pytest.fixture
def config():
    return default_config()


@pytest.fixture
def app(tmp_path):
    application = create_app({
        "TESTING": True,
        "DATABASE": str(tmp_path / "test.db"),
        "RULES_PATH": str(tmp_path / "rules.json"),
        "SAMPLE_DIR": str(tmp_path / "samples"),
        "SECRET_KEY": "test-secret",
        "CSRF_ENABLED": False,
    })
    yield application


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture(scope="session")
def sample_dir(tmp_path_factory):
    directory = tmp_path_factory.mktemp("samples")
    generate_samples(directory)
    return directory
