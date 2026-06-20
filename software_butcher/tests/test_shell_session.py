"""Tests for shell session management."""

from software_butcher.state.session_state import ShellSession, ShellSessionStore, SessionStore
from software_butcher.shelves.hexstrike.adapter import HexstrikeAdapter
from software_butcher.brain.context import build_brain_context
from software_butcher.state.engagement import EngagementState, phase_hypotheses
from software_butcher.state.schema import Finding
import tempfile
import json


def test_shell_session_creation():
    """Test basic ShellSession creation and serialization."""
    session = ShellSession(
        session_id="msf_1",
        session_type="metasploit",
        host="10.10.11.5",
        port=4444,
        user="www-data",
        cwd="/var/www/html",
    )
    
    assert session.session_id == "msf_1"
    assert session.session_type == "metasploit"
    assert session.host == "10.10.11.5"
    assert session.port == 4444
    assert session.user == "www-data"
    assert session.cwd == "/var/www/html"
    assert session.active is True
    
    # Test serialization
    data = session.to_dict()
    assert data["session_id"] == "msf_1"
    assert data["session_type"] == "metasploit"
    
    # Test deserialization
    restored = ShellSession.from_dict(data)
    assert restored.session_id == session.session_id
    assert restored.session_type == session.session_type
    assert restored.host == session.host


def test_shell_session_update():
    """Test updating session usage."""
    session = ShellSession(
        session_id="msf_1",
        session_type="metasploit",
        host="10.10.11.5",
    )
    
    initial_last_used = session.last_used
    session.update_usage("id", "uid=33(www-data) gid=33(www-data)")
    
    assert session.last_command == "id"
    assert session.last_output == "uid=33(www-data) gid=33(www-data)"
    assert session.last_used != initial_last_used


def test_shell_session_store():
    """Test ShellSessionStore operations."""
    store = ShellSessionStore()
    
    session1 = ShellSession(
        session_id="msf_1",
        session_type="metasploit",
        host="10.10.11.5",
        port=4444,
        user="www-data",
    )
    
    session2 = ShellSession(
        session_id="sliver_abc",
        session_type="sliver",
        host="10.10.11.5",
        port=8888,
        user="root",
    )
    
    # Add sessions
    store.add_session(session1)
    store.add_session(session2)
    
    # Test retrieval
    assert store.get_session("msf_1") == session1
    assert store.get_session("sliver_abc") == session2
    assert store.get_session("nonexistent") is None
    
    # Test target indexing
    sessions_for_target = store.get_sessions_for_target("10.10.11.5")
    assert len(sessions_for_target) == 2
    
    sessions_with_port = store.get_sessions_for_target("10.10.11.5", 4444)
    assert len(sessions_with_port) == 1
    assert sessions_with_port[0].session_id == "msf_1"
    
    # Test best session selection
    best = store.get_best_session_for_target("10.10.11.5")
    assert best is not None
    assert best.session_id in ["msf_1", "sliver_abc"]
    
    # Test session update
    store.update_session("msf_1", "whoami", "www-data", "/home/www-data")
    updated = store.get_session("msf_1")
    assert updated.last_command == "whoami"
    assert updated.cwd == "/home/www-data"
    
    # Test deactivation
    assert store.deactivate_session("msf_1") is True
    assert store.get_session("msf_1").active is False
    assert store.deactivate_session("nonexistent") is False


def test_shell_session_store_persistence():
    """Test ShellSessionStore save/load."""
    store = ShellSessionStore()
    
    session = ShellSession(
        session_id="msf_1",
        session_type="metasploit",
        host="10.10.11.5",
        user="www-data",
    )
    
    store.add_session(session)
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name
    
    try:
        store.save(temp_path)
        
        loaded_store = ShellSessionStore.load(temp_path)
        assert len(loaded_store.sessions) == 1
        assert loaded_store.get_session("msf_1") is not None
        assert loaded_store.get_session("msf_1").host == "10.10.11.5"
    finally:
        import os
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def test_session_store_integration():
    """Test SessionStore with shell sessions."""
    store = SessionStore()
    
    # Test HTTP cookie storage (existing functionality)
    store.store("http://localhost", {"PHPSESSID": "abc123"})
    assert store.has_session("http://localhost")
    assert store.cookie_header("http://localhost") == "PHPSESSID=abc123"
    
    # Test shell session storage (new functionality)
    shell_session = ShellSession(
        session_id="msf_1",
        session_type="metasploit",
        host="10.10.11.5",
        user="www-data",
    )
    
    store.shell_sessions.add_session(shell_session)
    assert store.shell_sessions.get_session("msf_1") == shell_session
    
    # Test combined serialization
    data = store.to_dict()
    assert "sessions" in data
    assert "shell_sessions" in data
    assert data["sessions"]["http://localhost"]["PHPSESSID"] == "abc123"
    assert "msf_1" in data["shell_sessions"]["sessions"]
    
    # Test combined deserialization
    restored = SessionStore.from_dict(data)
    assert restored.has_session("http://localhost")
    assert restored.shell_sessions.get_session("msf_1") is not None


def test_brain_context_with_shell_sessions():
    """Test build_brain_context includes shell session information."""
    findings = [
        Finding(
            hypothesis="Test finding",
            path="http://localhost",
            provenance="test",
            status="hypothesis",
            evidence=["test evidence"],
            confidence=0.7,
        )
    ]
    
    engagement = EngagementState(phase="foothold")
    
    # Without shell sessions
    context_without = build_brain_context(findings, engagement)
    assert "Active shell sessions: 0" not in context_without
    
    # With shell sessions
    session_store = SessionStore()
    shell_session = ShellSession(
        session_id="msf_1",
        session_type="metasploit",
        host="10.10.11.5",
        user="www-data",
        cwd="/var/www/html",
    )
    session_store.shell_sessions.add_session(shell_session)
    
    context_with = build_brain_context(findings, engagement, session_store=session_store)
    assert "Active shell sessions: 1" in context_with
    assert "metasploit:msf_1" in context_with
    assert "10.10.11.5" in context_with
    assert "www-data" in context_with


def test_phase_hypotheses_with_shell_sessions():
    """Test phase_hypotheses uses shell sessions when available."""
    engagement = EngagementState(phase="foothold")
    
    # Without shell sessions
    hypotheses_without = phase_hypotheses(engagement, "http://10.10.11.5")
    shell_hypotheses_without = [h for h in hypotheses_without if h.metadata.get("intent") == "shell_command_execution"]
    assert len(shell_hypotheses_without) == 0
    
    # With shell sessions
    session_store = SessionStore()
    shell_session = ShellSession(
        session_id="msf_1",
        session_type="metasploit",
        host="10.10.11.5",
        user="www-data",
    )
    session_store.shell_sessions.add_session(shell_session)
    
    hypotheses_with = phase_hypotheses(engagement, "http://10.10.11.5", session_store=session_store)
    shell_hypotheses_with = [h for h in hypotheses_with if h.metadata.get("intent") == "shell_command_execution"]
    assert len(shell_hypotheses_with) > 0
    
    # Check that shell hypotheses have commands
    for hyp in shell_hypotheses_with:
        assert "command" in hyp.metadata
        assert hyp.metadata["command"] is not None


def test_adapter_shell_detection():
    """Test HexstrikeAdapter shell session detection."""
    adapter = HexstrikeAdapter()
    
    # Test Metasploit session detection
    msf_output = "[*] Meterpreter session 1 opened (10.10.11.5:4444 -> 10.10.14.5:5555)"
    session = adapter._detect_shell_session(msf_output, "", "10.10.11.5")
    assert session is not None
    assert session.session_type == "metasploit"
    assert session.session_id == "1"
    assert session.host == "10.10.11.5"
    
    # Test generic shell detection
    shell_output = "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
    session = adapter._detect_shell_session(shell_output, "", "10.10.11.5")
    assert session is not None
    assert session.session_type == "web_shell"
    assert session.host == "10.10.11.5"
    
    # Test no detection
    no_shell_output = "Port 80/tcp open http"
    session = adapter._detect_shell_session(no_shell_output, "", "10.10.11.5")
    assert session is None


if __name__ == "__main__":
    test_shell_session_creation()
    test_shell_session_update()
    test_shell_session_store()
    test_shell_session_store_persistence()
    test_session_store_integration()
    test_brain_context_with_shell_sessions()
    test_phase_hypotheses_with_shell_sessions()
    test_adapter_shell_detection()
    print("All shell session tests passed!")
