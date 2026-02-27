# NullSec RegDump

D language registry forensics tool demonstrating compile-time features and system-level safety.

## Features

- **CTFE** - Compile-time function execution for patterns
- **Ranges** - Lazy evaluation for memory efficiency
- **@safe/@trusted** - Memory safety attributes
- **Strong Typing** - Type-safe registry structures
- **Pattern Matching** - Suspicious entry detection

## Detections

| Category | Severity | Description |
|----------|----------|-------------|
| Persistence | Medium | Run/RunOnce keys |
| Services | Medium | Auto-start services |
| Security | High | UAC/FW disabled |
| Antivirus | Critical | Defender disabled |
| Credentials | High | SAM/LSA access |
| Malware | Critical | Known tools |

## Build

```bash
# With DMD
dmd -O -release regdump.d -of=regdump

# With LDC
ldc2 -O3 regdump.d -of=regdump

# With GDC
gdc -O3 regdump.d -o regdump
```

## Usage

```bash
# Basic analysis
./regdump SYSTEM

# Specify hive type
./regdump -t SOFTWARE C:\Windows\System32\config\SOFTWARE

# JSON output
./regdump -j NTUSER.DAT > forensics.json

# Verbose all entries
./regdump -a -v SAM
```

## Supported Hives

- SYSTEM - Services, drivers, hardware
- SOFTWARE - Installed apps, policies
- SAM - User accounts, passwords
- SECURITY - LSA secrets, policies
- NTUSER - User-specific settings
- USRCLASS - User shell settings

## Author

bad-antics | [Discord](https://x.com/AnonAntics)

## License

MIT
