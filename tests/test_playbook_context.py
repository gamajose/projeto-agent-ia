from app.services import playbooks


def _book(identifier: str, priority: int = 1):
    return playbooks.Playbook(
        id=identifier,
        title=identifier,
        priority=priority,
        profiles=("any",),
        patterns=("erro",),
        steps=(),
        allowed_corrections=(),
        validation_tools=(),
        source=f"{identifier}.yml",
    )


def test_manual_and_none_playbook_selection(monkeypatch):
    monkeypatch.setattr(playbooks, "load_playbooks", lambda: (_book("one"), _book("two", 2)))

    with playbooks.use_playbook("manual", "one"):
        assert playbooks.select_playbook("qualquer texto", "linux_generic").id == "one"

    with playbooks.use_playbook("none"):
        assert playbooks.select_playbook("erro", "linux_generic") is None

    assert playbooks.select_playbook("erro", "linux_generic").id == "two"
