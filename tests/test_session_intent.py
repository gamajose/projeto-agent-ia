from app.services.session_intent import detect_local_intent


def test_exit_variants_are_recognized():
    assert detect_local_intent("exit").name == "exit"
    assert detect_local_intent("sair").name == "exit"
    assert detect_local_intent("desconectar servidor").name == "exit"


def test_switch_target_extracts_ip():
    intent = detect_local_intent("conecte no servidor 10.45.1.24")
    assert intent.name == "switch_target"
    assert intent.target == "10.45.1.24"


def test_arrume_uses_existing_proposal():
    assert detect_local_intent("arrume").name == "execute_proposal"


def test_service_restart_is_proposed_before_execution():
    intent = detect_local_intent("reinicie o serviço automation-helper")
    assert intent.name == "propose_specific_action"
