import subprocess

def block_ip(attacker_ip):
    """Adds a robust PowerShell Firewall rule to block an IP."""
    rule_name = f"XAI_IDS_BLOCK_{attacker_ip}"
    
    # PowerShell command for bidirectional blocking
    ps_cmd = f"New-NetFirewallRule -DisplayName '{rule_name}' -Direction Inbound -Action Block -RemoteAddress {attacker_ip} -Protocol Any -Profile Any"
    
    try:
        # Check if rule exists first
        check_cmd = f"Get-NetFirewallRule -DisplayName '{rule_name}'"
        result = subprocess.run(["powershell", "-Command", check_cmd], capture_output=True, text=True)
        
        if result.returncode != 0: # If command failed, the rule doesn't exist
            subprocess.run(["powershell", "-Command", ps_cmd], check=True)
            print(f"[DEFENSE] Successfully blocked IP: {attacker_ip}")
    except Exception as e:
        print(f"[DEFENSE] Failed to block {attacker_ip}: {e}")

def unblock_all():
    """Removes all firewall rules created by the IDS (Manual and Toggle)."""
    # This removes rules starting with XAI_IDS_BLOCK or our Toggle name
    ps_cmd = "Remove-NetFirewallRule -DisplayName 'XAI_IDS_BLOCK_*', 'IDS_TOGGLE_BLOCK'"
    
    try:
        subprocess.run(["powershell", "-Command", ps_cmd], check=True)
        print("[DEFENSE] All IDS blocked rules have been cleared.")
    except Exception as e:
        # If no rules exist, PowerShell might throw an error; we can ignore it
        print("[DEFENSE] No rules found to clear or error occurred.")