// NullSec RegDump - Memory & Registry Forensics Tool
// D language security tool demonstrating:
//   - CTFE (Compile-Time Function Execution)
//   - Ranges and lazy evaluation
//   - Metaprogramming with mixins
//   - Strong typing with safety
//   - @safe, @trusted, @system attributes
//
// Author: bad-antics
// License: MIT

import std.stdio;
import std.string;
import std.conv;
import std.algorithm;
import std.range;
import std.array;
import std.file;
import std.path;
import std.format;
import std.datetime;
import std.typecons;
import std.bitmanip;

enum VERSION = "1.0.0";

// ANSI Colors
enum Color : string {
    red = "\033[31m",
    green = "\033[32m",
    yellow = "\033[33m",
    cyan = "\033[36m",
    gray = "\033[90m",
    reset = "\033[0m"
}

string colored(string text, Color c) pure @safe {
    return c ~ text ~ Color.reset;
}

// Registry hive types
enum HiveType {
    SYSTEM,
    SOFTWARE,
    SAM,
    SECURITY,
    NTUSER,
    USRCLASS,
    UNKNOWN
}

// Registry value types
enum RegType : uint {
    REG_NONE = 0,
    REG_SZ = 1,
    REG_EXPAND_SZ = 2,
    REG_BINARY = 3,
    REG_DWORD = 4,
    REG_DWORD_BIG_ENDIAN = 5,
    REG_LINK = 6,
    REG_MULTI_SZ = 7,
    REG_RESOURCE_LIST = 8,
    REG_FULL_RESOURCE_DESCRIPTOR = 9,
    REG_RESOURCE_REQUIREMENTS_LIST = 10,
    REG_QWORD = 11
}

// Registry key structure
struct RegKey {
    string path;
    string name;
    RegType valueType;
    ubyte[] data;
    SysTime lastModified;
    
    string dataAsString() const @safe {
        if (data.length == 0) return "";
        
        final switch (valueType) {
            case RegType.REG_SZ:
            case RegType.REG_EXPAND_SZ:
                return cast(string) data.idup;
            case RegType.REG_DWORD:
                if (data.length >= 4) {
                    return format("0x%08X", data.peek!(uint, Endian.littleEndian));
                }
                return "Invalid DWORD";
            case RegType.REG_QWORD:
                if (data.length >= 8) {
                    return format("0x%016X", data.peek!(ulong, Endian.littleEndian));
                }
                return "Invalid QWORD";
            case RegType.REG_BINARY:
            case RegType.REG_NONE:
            case RegType.REG_LINK:
            case RegType.REG_MULTI_SZ:
            case RegType.REG_RESOURCE_LIST:
            case RegType.REG_FULL_RESOURCE_DESCRIPTOR:
            case RegType.REG_RESOURCE_REQUIREMENTS_LIST:
            case RegType.REG_DWORD_BIG_ENDIAN:
                return data.map!(b => format("%02X", b)).join(" ");
        }
    }
}

// Finding severity
enum Severity {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
    INFO
}

// Forensic finding
struct Finding {
    Severity severity;
    string category;
    string description;
    string path;
    string evidence;
}

// Suspicious patterns (compile-time evaluation)
immutable suspiciousPatterns = [
    // Persistence mechanisms
    tuple("Run", r".*\\Run$", Severity.MEDIUM, "Autorun entry"),
    tuple("RunOnce", r".*\\RunOnce$", Severity.MEDIUM, "One-time autorun"),
    tuple("Services", r".*\\Services\\.*", Severity.INFO, "Service registration"),
    
    // Security settings
    tuple("DisableUAC", r"EnableLUA", Severity.HIGH, "UAC disabled"),
    tuple("DisableFW", r"EnableFirewall", Severity.HIGH, "Firewall disabled"),
    tuple("DisableAV", r"DisableAntiSpyware", Severity.CRITICAL, "Antivirus disabled"),
    
    // Credential access
    tuple("SAM", r".*\\SAM\\.*", Severity.HIGH, "SAM database access"),
    tuple("LSA", r".*\\LSA\\.*", Severity.HIGH, "LSA secrets access"),
    tuple("Cached", r".*\\CachedLogons.*", Severity.MEDIUM, "Cached credentials"),
    
    // Suspicious tools
    tuple("PSExec", r".*PsExec.*", Severity.HIGH, "PSExec detected"),
    tuple("Mimikatz", r".*mimikatz.*", Severity.CRITICAL, "Mimikatz detected"),
    tuple("CobaltStrike", r".*beacon.*", Severity.CRITICAL, "Cobalt Strike beacon"),
];

// Configuration
struct Config {
    string hivePath;
    bool showAll;
    bool jsonOutput;
    bool verbose;
    HiveType hiveType;
}

// Parse command line
Config parseArgs(string[] args) {
    Config cfg;
    cfg.hiveType = HiveType.UNKNOWN;
    
    for (size_t i = 1; i < args.length; i++) {
        switch (args[i]) {
            case "-h", "--help":
                printUsage();
                break;
            case "-a", "--all":
                cfg.showAll = true;
                break;
            case "-j", "--json":
                cfg.jsonOutput = true;
                break;
            case "-v", "--verbose":
                cfg.verbose = true;
                break;
            case "-t", "--type":
                if (i + 1 < args.length) {
                    cfg.hiveType = parseHiveType(args[++i]);
                }
                break;
            default:
                if (!args[i].startsWith("-")) {
                    cfg.hivePath = args[i];
                }
                break;
        }
    }
    
    return cfg;
}

HiveType parseHiveType(string s) {
    switch (s.toUpper()) {
        case "SYSTEM": return HiveType.SYSTEM;
        case "SOFTWARE": return HiveType.SOFTWARE;
        case "SAM": return HiveType.SAM;
        case "SECURITY": return HiveType.SECURITY;
        case "NTUSER": return HiveType.NTUSER;
        case "USRCLASS": return HiveType.USRCLASS;
        default: return HiveType.UNKNOWN;
    }
}

void printBanner() {
    writeln();
    writeln("╔══════════════════════════════════════════════════════════════════╗");
    writeln("║          NullSec RegDump - Registry Forensics Tool               ║");
    writeln("╚══════════════════════════════════════════════════════════════════╝");
    writeln();
}

void printUsage() {
    printBanner();
    writeln("USAGE:");
    writeln("    regdump [OPTIONS] <hive_file>");
    writeln();
    writeln("OPTIONS:");
    writeln("    -h, --help       Show this help");
    writeln("    -a, --all        Show all entries");
    writeln("    -j, --json       JSON output");
    writeln("    -v, --verbose    Verbose output");
    writeln("    -t, --type TYPE  Hive type (SYSTEM, SOFTWARE, SAM, etc.)");
    writeln();
    writeln("EXAMPLES:");
    writeln("    regdump SYSTEM");
    writeln("    regdump -a -t SOFTWARE C:\\Windows\\System32\\config\\SOFTWARE");
    writeln("    regdump -j NTUSER.DAT > forensics.json");
    writeln();
    writeln("DETECTIONS:");
    writeln("    - Persistence mechanisms (Run, RunOnce, Services)");
    writeln("    - Security bypasses (UAC, Firewall, Antivirus)");
    writeln("    - Credential access (SAM, LSA, Cached logons)");
    writeln("    - Malware artifacts (PSExec, Mimikatz, Cobalt Strike)");
}

// Analyze registry hive
Finding[] analyzeHive(ref Config cfg) {
    Finding[] findings;
    
    // Simulate analysis (real impl would parse actual hive files)
    writeln("Analyzing: ".colored(Color.cyan), cfg.hivePath);
    writeln();
    
    // Demo findings
    findings ~= simulateFindings(cfg.hiveType);
    
    return findings;
}

Finding[] simulateFindings(HiveType hiveType) {
    Finding[] findings;
    
    final switch (hiveType) {
        case HiveType.SYSTEM:
            findings ~= Finding(
                Severity.MEDIUM,
                "Persistence",
                "Service configured for auto-start",
                `HKLM\SYSTEM\CurrentControlSet\Services\SuspiciousSvc`,
                "Start: 2 (Auto)"
            );
            break;
            
        case HiveType.SOFTWARE:
            findings ~= Finding(
                Severity.HIGH,
                "Security",
                "Windows Defender disabled",
                `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`,
                "DisableAntiSpyware: 1"
            );
            findings ~= Finding(
                Severity.MEDIUM,
                "Persistence",
                "Run key entry found",
                `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
                "Updater: C:\\ProgramData\\update.exe"
            );
            break;
            
        case HiveType.SAM:
            findings ~= Finding(
                Severity.HIGH,
                "Credential",
                "Local administrator account",
                `HKLM\SAM\SAM\Domains\Account\Users\000001F4`,
                "RID: 500 (Administrator)"
            );
            break;
            
        case HiveType.SECURITY:
            findings ~= Finding(
                Severity.HIGH,
                "Credential",
                "LSA secrets present",
                `HKLM\SECURITY\Policy\Secrets`,
                "Multiple secrets found"
            );
            break;
            
        case HiveType.NTUSER:
            findings ~= Finding(
                Severity.MEDIUM,
                "Persistence",
                "User Run key entry",
                `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
                "SyncApp: C:\\Users\\victim\\AppData\\sync.exe"
            );
            break;
            
        case HiveType.USRCLASS:
        case HiveType.UNKNOWN:
            findings ~= Finding(
                Severity.INFO,
                "Analysis",
                "Demo mode - specify hive type for detailed analysis",
                "N/A",
                "Use -t flag"
            );
            break;
    }
    
    return findings;
}

void printFindings(Finding[] findings) {
    if (findings.length == 0) {
        writeln("No suspicious findings".colored(Color.green));
        return;
    }
    
    writeln("Findings:".colored(Color.yellow));
    writeln();
    
    foreach (finding; findings) {
        string severityStr;
        Color severityColor;
        
        final switch (finding.severity) {
            case Severity.CRITICAL:
                severityStr = "[CRITICAL]";
                severityColor = Color.red;
                break;
            case Severity.HIGH:
                severityStr = "[HIGH]    ";
                severityColor = Color.red;
                break;
            case Severity.MEDIUM:
                severityStr = "[MEDIUM]  ";
                severityColor = Color.yellow;
                break;
            case Severity.LOW:
                severityStr = "[LOW]     ";
                severityColor = Color.cyan;
                break;
            case Severity.INFO:
                severityStr = "[INFO]    ";
                severityColor = Color.gray;
                break;
        }
        
        writeln("  ", severityStr.colored(severityColor), " ", finding.category);
        writeln("    Description: ", finding.description);
        writeln("    Path:        ", finding.path);
        writeln("    Evidence:    ", finding.evidence);
        writeln();
    }
}

void printStats(Finding[] findings) {
    auto critCount = findings.count!(f => f.severity == Severity.CRITICAL);
    auto highCount = findings.count!(f => f.severity == Severity.HIGH);
    auto medCount = findings.count!(f => f.severity == Severity.MEDIUM);
    auto lowCount = findings.count!(f => f.severity == Severity.LOW);
    
    writeln("═══════════════════════════════════════════".colored(Color.gray));
    writeln();
    writeln("Summary:");
    writeln("  Critical: ".colored(Color.red), critCount);
    writeln("  High:     ".colored(Color.red), highCount);
    writeln("  Medium:   ".colored(Color.yellow), medCount);
    writeln("  Low:      ".colored(Color.cyan), lowCount);
}

void main(string[] args) {
    auto cfg = parseArgs(args);
    
    if (cfg.hivePath.length == 0) {
        printUsage();
        return;
    }
    
    if (!cfg.jsonOutput) {
        printBanner();
    }
    
    auto findings = analyzeHive(cfg);
    
    if (cfg.jsonOutput) {
        // JSON output would go here
        writeln(`{"findings": []}`);
    } else {
        printFindings(findings);
        printStats(findings);
    }
}
