# Spray.py

A Python tool for performing password spraying attacks using `kerbrute` with intelligent date-based password generation powered by BloodHound CE.

## Features

- **Smart Password Generation**: Automatically generates passwords based on password last change dates from BloodHound CE
- **Multiple Spray Modes**:
  - `smart`: Intelligent date-based password generation (requires BloodHound CE)
  - `password`: Fixed password spraying
  - `useraspass`: Username-as-password spraying
- **Account Lockout Protection**: Integrates with `netexec` to check account lockout thresholds and filter eligible users
- **Interactive Mode**: Curses-based interactive menu for selecting spray parameters
- **Non-Interactive Mode**: Full CLI support for automation
- **Verbose Logging**: Multiple logging levels (`-v/--verbose` and `--debug`) for detailed output

## Requirements

- Python 3.8+
- [pipx](https://github.com/pypa/pipx) (recommended for installation) or pip/uv
- [kerbrute](https://github.com/ropnop/kerbrute) installed and in PATH
- [netexec](https://github.com/Pennyw0rth/NetExec) (optional, for account lockout protection)
- `ntpdate` or `ntp` package (for time synchronization with PDC)
- BloodHound CE instance running (for `smart` mode)

### System Requirements

**Time Synchronization**: The tool automatically synchronizes system time with the PDC before running kerbrute. This is critical for Kerberos authentication, which requires time synchronization within a 5-minute window.

Install `ntpdate` on your system:
- **Debian/Ubuntu**: `sudo apt install ntpdate`
- **RHEL/CentOS**: `sudo yum install ntpdate` or `sudo dnf install ntpdate`
- **Arch Linux**: `sudo pacman -S ntp`

## Installation

### Using pipx (recommended)

`pipx` installs Python applications in isolated environments, making it the preferred method for CLI tools:

```bash
# Install pipx if you don't have it
python3 -m pip install --user pipx
python3 -m pipx ensurepath

# Install spray.py from GitHub
pipx install git+https://github.com/ADScanPro/spray.py

# Or install from a local clone
git clone https://github.com/ADScanPro/spray.py.git
cd spray.py
pipx install .
```

After installation, `spray.py` will be available in your PATH as `spray`.

### Using uv

`uv` is a fast Python package installer and resolver:

```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install project dependencies
uv pip install -e .

# Or sync from lockfile (recommended for reproducible installs)
uv pip sync requirements.lock
```

### Using pip

```bash
pip install git+https://github.com/ADScanPro/spray.py
# Or from local clone
pip install -e .
```

### Manual Installation

1. Clone the repository:
```bash
git clone https://github.com/ADScanPro/spray.py.git
cd spray.py
```

2. Install dependencies:
```bash
pip install -r requirements.lock
# Or install directly
pip install bloodhound-cli>=1.2.1 loguru>=0.7.0
```

## Configuration

### BloodHound CE Setup

1. Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

2. Edit `.env` with your BloodHound CE credentials:
```bash
BH_CE_BASE_URL=http://localhost:8080
BH_CE_USERNAME=admin
BH_CE_PASSWORD=Bloodhound123!
```

Alternatively, you can set these as environment variables:
```bash
export BH_CE_BASE_URL="http://localhost:8080"
export BH_CE_USERNAME="admin"
export BH_CE_PASSWORD="Bloodhound123!"
```

## Usage

### Check Version

To check the version of the script:

```bash
./spray.py --version
# or if installed via pipx
spray --version
```

Output:
```
spray.py 1.0.1
```

### Smart Mode (Date-based Password Generation)

Intelligent password spraying using password last change dates from BloodHound CE:

```bash
# Interactive mode
./spray.py smart -d cicada.htb --dc-ip 10.129.231.149 -o output.log

# Non-interactive mode
./spray.py smart -d cicada.htb --dc-ip 10.129.231.149 \
  --lang English --type month --case lower --format 1 \
  -o output.log
```

**Options:**
- `-d, --domain`: Target domain (required)
- `--dc-ip`: Domain Controller IP address (required)
- `-o, --output`: Output file for kerbrute results
- `--lang`: Language for month names (English/Spanish)
- `--type`: Spray type (currently only 'month')
- `-c, --case`: Case format (lower/upper)
- `-f, --format`: Format ID (1-10, see format options below)
- `-v, --verbose`: Enable verbose output (shows INFO level messages with detailed progress)
- `--debug`: Enable debug mode (very detailed information, includes tracebacks, DEBUG messages, and all executed commands)
- `--kerbrute-path`: Path to kerbrute binary (if not in PATH)

**Note**: By default, only warnings and errors are shown. Use `-v/--verbose` to see detailed progress information. Use `--debug` to see all executed commands (netexec, kerbrute, ntpdate, etc.).

**Format Options:**
1. `{month}{full_year}` (e.g., january2025)
2. `{month}.{full_year}` (e.g., january.2025)
3. `{month}{full_year}.` (e.g., january2025.)
4. `{month}@{full_year}` (e.g., january@2025)
5. `{month}{full_year}!` (e.g., january2025!)
6. `{month}{year_short}` (e.g., january25)
7. `{month}.{year_short}` (e.g., january.25)
8. `{month}{year_short}.` (e.g., january25.)
9. `{month}@{year_short}` (e.g., january@25)
10. `{month}{year_short}!` (e.g., january25!)

### Password Mode (Fixed Password)

Spray a fixed password against a list of users:

```bash
./spray.py password -d cicada.htb --dc-ip 10.129.231.149 \
  -u users.txt -p 'Password123!' \
  -ul domain_user -pl domain_password \
  -t 2 -o output.log
```

**Options:**
- `-d, --domain`: Target domain (required)
- `--dc-ip`: Domain Controller IP address (required)
- `-u`: Path to user list file (required)
- `-p`: Password to spray (required)
- `-ul`: Username for netexec (optional, for lockout protection)
- `-pl`: Password for netexec (optional, for lockout protection)
- `-t`: Safe threshold for remaining lockout attempts (default: 0)
- `-o, --output`: Output file for kerbrute results
- `-v, --verbose`: Enable verbose output (shows INFO level messages with detailed progress)
- `--debug`: Enable debug mode (very detailed information, includes tracebacks, DEBUG messages, and all executed commands)
- `--kerbrute-path`: Path to kerbrute binary (if not in PATH)

**Note**: By default, only warnings and errors are shown. Use `-v/--verbose` to see detailed progress information. Use `--debug` to see all executed commands (netexec, kerbrute, ntpdate, etc.).

### User-as-Pass Mode

Spray using usernames as passwords:

```bash
# Exact username as password
./spray.py useraspass -d cicada.htb --dc-ip 10.129.231.149 \
  -u users.txt -o output.log

# Lowercase username as password
./spray.py useraspass -d cicada.htb --dc-ip 10.129.231.149 \
  -u users.txt --low -o output.log

# Capitalized username as password
./spray.py useraspass -d cicada.htb --dc-ip 10.129.231.149 \
  -u users.txt --up -o output.log
```

**Options:**
- `-d, --domain`: Target domain (required)
- `--dc-ip`: Domain Controller IP address (required)
- `-u`: Path to user list file (required)
- `--low`: Use lowercase username as password
- `--up`: Use capitalized username as password
- `-o, --output`: Output file for kerbrute results
- `-v, --verbose`: Enable verbose output (shows INFO level messages with detailed progress)
- `--debug`: Enable debug mode (very detailed information, includes tracebacks, DEBUG messages, and all executed commands)
- `--kerbrute-path`: Path to kerbrute binary (if not in PATH)

**Note**: By default, only warnings and errors are shown. Use `-v/--verbose` to see detailed progress information. Use `--debug` to see all executed commands (netexec, kerbrute, ntpdate, etc.).

## Account Lockout Protection

When using `-ul` and `-pl` options, the tool will:

1. Query the domain's account lockout threshold using `netexec`
2. Get each user's current `BadPwdCount` from `netexec`
3. Filter users to only include those with remaining attempts above the threshold (`-t`)

This helps prevent account lockouts during password spraying.

## Examples

### Example 1: Smart Mode with Interactive Selection

```bash
./spray.py smart -d cicada.htb --dc-ip 10.129.231.149 -o results.log
```

This will:
1. Connect to BloodHound CE
2. Show an interactive menu to select language, case, and format
3. Generate passwords based on password last change dates
4. Execute kerbrute with the generated passwords

### Example 2: Non-Interactive Smart Mode

```bash
./spray.py smart -d cicada.htb --dc-ip 10.129.231.149 \
  --lang Spanish --type month --case lower --format 1 \
  -o results.log
```

### Example 3: Password Mode with Lockout Protection

```bash
./spray.py password -d cicada.htb --dc-ip 10.129.231.149 \
  -u domains/cicada.htb/users.txt \
  -p 'Cicada$M6Corpb*@Lp#nZp!8' \
  -ul domain_user -pl domain_password \
  -t 2 -o domains/cicada.htb/kerberos/spray.log
```

### Example 4: Using Custom Kerbrute Path

If kerbrute is not in your PATH, specify its location:

```bash
./spray.py password -d cicada.htb --dc-ip 10.129.231.149 \
  -u users.txt -p 'Password123!' \
  --kerbrute-path /opt/tools/kerbrute/kerbrute \
  -o output.log
```

## Dependencies

### Python Dependencies

- **bloodhound-cli** (>=1.2.1): For querying BloodHound CE database
- **loguru** (>=0.7.0): For enhanced logging with colored output and better tracebacks

All dependencies are managed via `pyproject.toml` and locked in `requirements.lock`.

### External Tools

- **kerbrute**: External tool for Kerberos password spraying (must be in PATH)
- **netexec** (optional): External tool for account lockout protection (must be in PATH)

### Dependency Management

This project uses `uv` for dependency management. To update dependencies:

```bash
# Update lockfile after modifying pyproject.toml
uv pip compile pyproject.toml --output-file requirements.lock
```

## Development

### Setup Development Environment

```bash
# Install with development dependencies
uv pip install -e ".[dev]"

# Or with pip
pip install -e ".[dev]"
```

### Code Formatting

```bash
# Format code with Black
black spray.py

# Or with ruff
ruff format spray.py
```

### Linting

```bash
# Run ruff
ruff check spray.py

# Run pylint
pylint spray.py
```

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

This tool is for authorized security testing and educational purposes only. Unauthorized access to computer systems is illegal. Use responsibly and only on systems you own or have explicit permission to test.

