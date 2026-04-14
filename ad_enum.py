#!/usr/bin/env python3
"""
AD Enumeration Script - ad_enum.py
Connessione LDAP al Domain Controller per enumerare utenti, gruppi e vulnerabilità.

Teoria LDAP:
    LDAP (Lightweight Directory Access Protocol) è il protocollo che Active Directory
    usa per le query. Funziona come un database gerarchico: ogni oggetto (utente, gruppo,
    computer) ha un "Distinguished Name" (DN) che è il suo indirizzo univoco nell'albero.
    Esempio: CN=Marco Rossi,OU=LabUsers,DC=psychosec,DC=local

Teoria UAC (UserAccountControl):
    È un campo numerico su ogni utente AD che contiene flag di configurazione.
    Ogni flag è un bit specifico. Il flag DONT_REQ_PREAUTH (0x400000 = 4194304)
    indica che l'utente non richiede pre-autenticazione Kerberos → vulnerabile ad AS-REP Roasting.
"""

import argparse
import json
import sys
from datetime import datetime

from ldap3 import Server, Connection, ALL, SUBTREE


# Flag UAC che ci interessa: "Do not require Kerberos preauthentication"
UAC_DONT_REQ_PREAUTH = 0x400000  # 4194304 in decimale


def connect_ldap(dc_ip, username=None, password=None):
    """
    Connessione al Domain Controller via LDAP.
    Se username/password sono forniti, fa autenticazione.
    Altrimenti tenta connessione anonima (spesso bloccata in AD moderni).
    """
    server = Server(dc_ip, port=389, get_info=ALL)

    if username and password:
        # Autenticazione con credenziali
        conn = Connection(server, user=username, password=password, auto_bind=True)
        print(f"[+] Connesso a {dc_ip} come {username}")
    else:
        # Tentativo anonimo
        conn = Connection(server, auto_bind=True)
        print(f"[+] Connesso a {dc_ip} (anonimo)")

    # Estrai il base DN dal server info (es. DC=psychosec,DC=local)
    base_dn = server.info.other['defaultNamingContext'][0]
    print(f"[+] Base DN: {base_dn}")

    return conn, base_dn


def enum_users(conn, base_dn):
    """
    Enumera tutti gli utenti del dominio.
    Cerca oggetti con objectClass=user e categoria 'person'.
    Estrae: username, nome, descrizione, quando è stata cambiata la password,
    il flag UserAccountControl e gli SPN.
    """
    print("\n" + "=" * 60)
    print("ENUMERAZIONE UTENTI")
    print("=" * 60)

    # Attributi che vogliamo leggere per ogni utente
    attributes = [
        'sAMAccountName',       # Username (es. m.rossi)
        'cn',                   # Nome completo (es. Marco Rossi)
        'description',          # Descrizione account
        'userAccountControl',   # Flag di configurazione (contiene DONT_REQ_PREAUTH)
        'pwdLastSet',           # Timestamp ultimo cambio password
        'memberOf',             # Gruppi di appartenenza
        'servicePrincipalName', # SPN (se presente → service account)
        'lastLogon',            # Ultimo login
    ]

    # Query LDAP: cerca tutti gli oggetti "user" che sono "person" (esclude computer)
    search_filter = '(&(objectClass=user)(objectCategory=person))'
    conn.search(base_dn, search_filter, SUBTREE, attributes=attributes)

    users = []
    for entry in conn.entries:
        user = {
            'username': str(entry.sAMAccountName) if entry.sAMAccountName else '',
            'fullname': str(entry.cn) if entry.cn else '',
            'description': str(entry.description) if entry.description else '',
            'uac': int(str(entry.userAccountControl)) if entry.userAccountControl else 0,
            'pwd_last_set': str(entry.pwdLastSet) if entry.pwdLastSet else '',
            'member_of': [str(g) for g in entry.memberOf] if entry.memberOf else [],
            'spn': [str(s) for s in entry.servicePrincipalName] if entry.servicePrincipalName else [],
            'last_logon': str(entry.lastLogon) if entry.lastLogon else '',
        }

        # Controlla se il flag DONT_REQ_PREAUTH è attivo
        # Operazione bitwise AND: se il bit è settato, il risultato è != 0
        user['no_preauth'] = bool(user['uac'] & UAC_DONT_REQ_PREAUTH)

        # Se ha SPN, è un service account (potenziale target Kerberoasting)
        user['has_spn'] = len(user['spn']) > 0

        users.append(user)

        # Stampa info utente
        flags = []
        if user['no_preauth']:
            flags.append('NO_PREAUTH')
        if user['has_spn']:
            flags.append(f"SPN: {', '.join(user['spn'])}")

        flag_str = f" [{', '.join(flags)}]" if flags else ""
        print(f"  {user['username']:<20} {user['fullname']:<25}{flag_str}")

    print(f"\n[+] Totale utenti trovati: {len(users)}")
    return users


def enum_groups(conn, base_dn):
    """
    Enumera tutti i gruppi del dominio e i loro membri.
    """
    print("\n" + "=" * 60)
    print("ENUMERAZIONE GRUPPI")
    print("=" * 60)

    attributes = ['cn', 'member', 'description']
    search_filter = '(objectClass=group)'
    conn.search(base_dn, search_filter, SUBTREE, attributes=attributes)

    groups = []
    for entry in conn.entries:
        group = {
            'name': str(entry.cn) if entry.cn else '',
            'description': str(entry.description) if entry.description else '',
            'members': [str(m) for m in entry.member] if entry.member else [],
        }
        groups.append(group)

        member_count = len(group['members'])
        print(f"  {group['name']:<35} ({member_count} membri)")

    print(f"\n[+] Totale gruppi trovati: {len(groups)}")
    return groups


def find_asrep_targets(users):
    """
    Identifica utenti vulnerabili ad AS-REP Roasting.
    Sono quelli con il flag DONT_REQ_PREAUTH attivo.
    """
    print("\n" + "=" * 60)
    print("TARGET AS-REP ROASTING (No Pre-Authentication)")
    print("=" * 60)

    targets = [u for u in users if u['no_preauth']]

    if targets:
        for t in targets:
            print(f"  [!] {t['username']:<20} {t['fullname']}")
        print(f"\n[!] {len(targets)} utenti vulnerabili ad AS-REP Roasting!")
    else:
        print("  Nessun utente vulnerabile trovato.")

    return targets


def find_kerberoast_targets(users):
    """
    Identifica service account vulnerabili a Kerberoasting.
    Sono gli utenti (non computer) con almeno un SPN registrato.
    Esclude krbtgt (account di sistema, non attaccabile in modo utile).
    """
    print("\n" + "=" * 60)
    print("TARGET KERBEROASTING (Service Accounts con SPN)")
    print("=" * 60)

    targets = [u for u in users if u['has_spn'] and u['username'] != 'krbtgt']

    if targets:
        for t in targets:
            print(f"  [!] {t['username']:<20} SPN: {', '.join(t['spn'])}")
        print(f"\n[!] {len(targets)} service account vulnerabili a Kerberoasting!")
    else:
        print("  Nessun service account con SPN trovato.")

    return targets


def find_domain_admins(conn, base_dn, users):
    """
    Identifica i membri del gruppo Domain Admins.
    Questi sono i target più preziosi in un pentest.
    """
    print("\n" + "=" * 60)
    print("DOMAIN ADMINS")
    print("=" * 60)

    conn.search(base_dn, '(&(objectClass=group)(cn=Domain Admins))', SUBTREE, attributes=['member'])

    admins = []
    if conn.entries:
        members = conn.entries[0].member if conn.entries[0].member else []
        for m in members:
            # Estrai il CN dal Distinguished Name
            cn = str(m).split(',')[0].replace('CN=', '')
            admins.append(cn)
            print(f"  [*] {cn}")

    print(f"\n[+] {len(admins)} Domain Admin trovati")
    return admins


def save_results(users, groups, asrep_targets, kerb_targets, admins, output_file):
    """
    Salva tutti i risultati in formato JSON.
    """
    results = {
        'timestamp': datetime.now().isoformat(),
        'total_users': len(users),
        'total_groups': len(groups),
        'users': users,
        'groups': groups,
        'asrep_targets': [t['username'] for t in asrep_targets],
        'kerberoast_targets': [{'username': t['username'], 'spn': t['spn']} for t in kerb_targets],
        'domain_admins': admins,
        'summary': {
            'asrep_vulnerable': len(asrep_targets),
            'kerberoast_vulnerable': len(kerb_targets),
            'domain_admins': len(admins),
        }
    }

    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\n[+] Risultati salvati in {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description='AD Enumeration Tool - Enumerazione Active Directory via LDAP',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Esempi:
  python3 ad_enum.py --dc-ip 192.168.56.10 --username PSYCHOSEC\\\\christian --password Password123
  python3 ad_enum.py --dc-ip 192.168.56.10 -u m.rossi@psychosec.local -p Password123!
        """
    )

    parser.add_argument('--dc-ip', required=True, help='IP del Domain Controller')
    parser.add_argument('-u', '--username', required=True, help='Username (DOMAIN\\\\user o user@domain)')
    parser.add_argument('-p', '--password', required=True, help='Password')
    parser.add_argument('-o', '--output', default='enum_results.json', help='File output JSON (default: enum_results.json)')

    args = parser.parse_args()

    print("""
    ╔══════════════════════════════════════════╗
    ║       AD ENUMERATION TOOL v1.0           ║
    ║       Target: {:<26s}║
    ╚══════════════════════════════════════════╝
    """.format(args.dc_ip))

    try:
        # 1. Connessione LDAP
        conn, base_dn = connect_ldap(args.dc_ip, args.username, args.password)

        # 2. Enumerazione utenti
        users = enum_users(conn, base_dn)

        # 3. Enumerazione gruppi
        groups = enum_groups(conn, base_dn)

        # 4. Identifica target AS-REP Roasting
        asrep_targets = find_asrep_targets(users)

        # 5. Identifica target Kerberoasting
        kerb_targets = find_kerberoast_targets(users)

        # 6. Identifica Domain Admins
        admins = find_domain_admins(conn, base_dn, users)

        # 7. Salva risultati
        save_results(users, groups, asrep_targets, kerb_targets, admins, args.output)

        # Chiudi connessione
        conn.unbind()
        print("\n[+] Enumerazione completata con successo!")

    except Exception as e:
        print(f"\n[-] Errore: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
