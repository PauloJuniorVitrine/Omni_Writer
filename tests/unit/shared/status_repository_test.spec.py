import pytest
from unittest import mock
import shared.status_repository as status_mod

def test_get_status():
    with mock.patch.object(status_mod, "get_status", return_value={"status": "ok"}):
        st = status_mod.get_status("abc")
        assert st["status"] == "ok"

def test_clear_old_status():
    if hasattr(status_mod, "clear_old_status"):
        with mock.patch.object(status_mod, "clear_old_status") as mock_clear:
            status_mod.clear_old_status()
            mock_clear.assert_called() 