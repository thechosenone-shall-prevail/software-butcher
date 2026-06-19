from software_butcher.shelves.hexstrike.adapter import HexstrikeAdapter

def test_hexstrike_command_injection():
    target = "http://example.com/a;rm -rf /"
    command = HexstrikeAdapter._build_tool_command("nmap", target)
    
    assert "';'" not in command
    assert command.startswith("nmap -sV -T4 '") and command.endswith("'")
    assert "a;rm" in command
