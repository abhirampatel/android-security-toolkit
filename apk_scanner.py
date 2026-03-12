#!/usr/bin/env python3
"""
APK Security Scanner
Author: Uppula Abhiram
Description: Static analysis toolkit for Android APK files.
             Extracts hardcoded secrets, checks manifest misconfigurations,
             scans for dangerous API usage, and generates a security report.
"""

import argparse
import json
import logging
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Any

# ============================================================================
# CONFIGURATION
# ============================================================================

# Pre-compile regex patterns for significant performance optimizations
SECRET_PATTERNS: Dict[str, re.Pattern] = {
    "Google API Key":        re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "AWS Access Key":        re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS Secret Key":        re.compile(r"(?i)aws(.{0,20})?secret(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]"),
    "Firebase URL":          re.compile(r"https://[a-z0-9-]+\.firebaseio\.com"),
    "Firebase API Key":      re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Private Key Header":    re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"),
    "Generic Secret":        re.compile(r"(?i)(secret|passwd|password|api_key|apikey|token|auth)['\"\s]*[:=]['\"\s]*[A-Za-z0-9+/=_\-]{8,}"),
    "Bearer Token":          re.compile(r"(?i)bearer\s+[a-zA-Z0-9\-_\.]+"),
    "Basic Auth":            re.compile(r"(?i)basic\s+[a-zA-Z0-9+/=]{8,}"),
    "MD5 Hash":              re.compile(r"\b[0-9a-fA-F]{32}\b"),
    "SHA1 Hash":             re.compile(r"\b[0-9a-fA-F]{40}\b"),
    "Internal IP":           re.compile(r"\b(192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})\b"),
    "HTTP Endpoint":         re.compile(r"http://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(/[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;=%]*)?"),
}

DANGEROUS_FUNCTIONS: set = {
    "Runtime.exec", "ProcessBuilder", "System.loadLibrary", "DexClassLoader",
    "PathClassLoader", "getExternalStorage", "MODE_WORLD_READABLE", 
    "MODE_WORLD_WRITEABLE", "setJavaScriptEnabled", "addJavascriptInterface",
    "openFileOutput", "getSharedPreferences", "SQLiteDatabase", 
    "javax.crypto.Cipher", "MessageDigest", "Log.d", "Log.e", "Log.v", "Log.i",
}

# Supported file extensions for analysis
TEXT_EXTENSIONS: set = {'.java', '.kt', '.smali', '.xml', '.js', '.txt', '.json'}
SKIPPED_EXTENSIONS: set = {'.png', '.jpg', '.jpeg', '.gif', '.mp3', '.mp4',
                           '.wav', '.ttf', '.otf', '.woff', '.zip', '.so',
                           '.dex', '.keystore', '.jks'}

# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class Finding:
    """Represents a single security vulnerability/finding."""
    type: str
    severity: str
    title: str
    detail: str
    file: str

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)


# ============================================================================
# CORE SCANNER LOGIC
# ============================================================================

class APKScanner:
    """
    Main class responsible for extracting and statically analyzing APK files.
    """
    
    def __init__(self, apk_path: Path):
        self.apk_path: Path = apk_path
        self.apk_name: str = self.apk_path.stem
        self.raw_dir: Path = Path(f"/tmp/apk_scan_{self.apk_name}")
        self.decompiled_dir: Optional[Path] = None
        self.findings: List[Finding] = []
        self.package_name: str = "unknown"
        
        # Configure logging
        logging.basicConfig(level=logging.INFO, format='%(message)s')
        self.logger = logging.getLogger(__name__)

    def _print_banner(self) -> None:
        """Prints the tool banner."""
        banner = f"""
╔══════════════════════════════════════════════════╗
║          APK Security Scanner v2.0               ║
║          Author: Uppula Abhiram                  ║
║          Mobile Security Researcher              ║
╚══════════════════════════════════════════════════╝
        """
        self.logger.info(banner)

    def _run_shell_command(self, cmd: List[str], desc: str) -> subprocess.CompletedProcess:
        """Utility method to safely execute shell commands."""
        try:
            return subprocess.run(cmd, capture_output=True, text=True, check=False)
        except Exception as e:
            self.logger.error(f"[!] Command execution failed for {desc}: {e}")
            raise

    def extract_apk(self) -> None:
        """Extracts the APK to raw files and attempts decompilation using APKTool."""
        self.logger.info(f"[*] Extracting APK: {self.apk_path}")
        
        if self.raw_dir.exists():
            shutil.rmtree(self.raw_dir)
        self.raw_dir.mkdir(parents=True, exist_ok=True)

        try:
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                z.extractall(self.raw_dir)
            self.logger.info(f"[+] Raw extraction complete -> {self.raw_dir}")
        except zipfile.BadZipFile as e:
            self.logger.error(f"[!] Invalid or corrupted APK file: {e}")
            sys.exit(1)

        # Attempt Decompilation using apktool
        target_decomp_dir = Path(f"{self.raw_dir}_decompiled")
        result = self._run_shell_command(
            ["apktool", "d", str(self.apk_path), "-o", str(target_decomp_dir), "--force"],
            "apktool decompilation"
        )
        
        if result.returncode == 0:
            self.decompiled_dir = target_decomp_dir
            self.logger.info(f"[+] APKTool decompilation complete -> {self.decompiled_dir}")
        else:
            self.logger.warning("[!] APKTool not found or failed. Falling back to raw extraction.")
            self.logger.warning(f"    Details: {result.stderr[:200]}")

    def analyze_manifest(self) -> None:
        """Parses AndroidManifest.xml for misconfigurations and dangerous permissions."""
        manifest_path = self.decompiled_dir / "AndroidManifest.xml" if self.decompiled_dir else None
        
        if manifest_path is None or not manifest_path.exists():
            self.logger.warning("[!] AndroidManifest.xml not found. Skipping manifest analysis.")
            return

        self.logger.info("[*] Parsing AndroidManifest.xml")
        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            ns = "http://schemas.android.com/apk/res/android"
            ns_fmt = lambda tag: f"{{{ns}}}{tag}"

            self.package_name = root.get("package", "unknown")
            self.logger.info(f"    Package: {self.package_name}")

            app = root.find("application")
            if app is not None:
                if app.get(ns_fmt("debuggable")) == "true":
                    self._add_finding("MANIFEST", "HIGH", "Application is debuggable", 
                                      'android:debuggable="true" -> app can be attached to a debugger', "AndroidManifest.xml")
                
                if app.get(ns_fmt("allowBackup")) == "true":
                    self._add_finding("MANIFEST", "MEDIUM", "Backup allowed", 
                                      'android:allowBackup="true" -> app data extractable via ADB without root', "AndroidManifest.xml")
                
                if app.get(ns_fmt("networkSecurityConfig")) is None:
                    self._add_finding("MANIFEST", "LOW", "No Network Security Config defined", 
                                      'App may allow cleartext traffic or trust user CAs', "AndroidManifest.xml")

            # Validate exported components without permissions
            for component in ["activity", "service", "receiver", "provider"]:
                for elem in root.iter(component):
                    is_exported = elem.get(ns_fmt("exported")) == "true"
                    has_permission = bool(elem.get(ns_fmt("permission")))
                    name = elem.get(ns_fmt("name"), "unknown")
                    
                    if is_exported and not has_permission:
                        self._add_finding("MANIFEST", "HIGH", f"Exported {component} with no permission", 
                                          f"{name} is freely accessible to any app on the device", "AndroidManifest.xml")

            dangerous_perms = {
                "READ_CONTACTS", "WRITE_CONTACTS", "READ_SMS", "SEND_SMS",
                "READ_CALL_LOG", "RECORD_AUDIO", "CAMERA", "ACCESS_FINE_LOCATION",
                "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE"
            }
            
            for perm in root.iter("uses-permission"):
                perm_name = perm.get(ns_fmt("name"), "")
                if any(dp in perm_name for dp in dangerous_perms):
                    self._add_finding("MANIFEST", "INFO", "Dangerous permission declared", perm_name, "AndroidManifest.xml")

        except ET.ParseError as e:
            self.logger.error(f"[!] Failed to parse manifest: {e}")

    def analyze_source_code(self) -> None:
        """
        O(1) I/O file scanner utilizing pre-compiled regex for findings.
        Scans for both hardcoded secrets and dangerous functions simultaneously 
        to reduce expensive system file-read operations.
        """
        search_dir = self.decompiled_dir if self.decompiled_dir else self.raw_dir
        self.logger.info(f"[*] Analyzing source paths for secrets and vulnerabilities in: {search_dir}")
        scanned_count = 0

        for filepath in search_dir.rglob("*"):
            if not filepath.is_file():
                continue
            
            # Optimization: Quickly skip binary and image assets
            if filepath.suffix.lower() in SKIPPED_EXTENSIONS or "assets/images" in filepath.parts or "assets/fonts" in filepath.parts:
                continue

            try:
                content = filepath.read_text(encoding='utf-8', errors='ignore')
                scanned_count += 1
                relative_path = str(filepath.relative_to(search_dir))

                # 1. Scan Secrets using pre-compiled regex generators
                for pattern_name, regex in SECRET_PATTERNS.items():
                    # Optimization: finditer is memory efficient compared to findall
                    for match in regex.finditer(content):
                        match_text = match.group(0)
                        
                        # Guard rails to avoid hash false positives
                        if pattern_name in ("MD5 Hash", "SHA1 Hash") and len(match_text) < 32:
                            continue
                            
                        severity = "HIGH" if any(k in pattern_name for k in ("Key", "Token", "Secret")) else "MEDIUM"
                        snippet = (match_text[:80] + "...") if len(match_text) > 80 else match_text
                        self._add_finding("SECRET", severity, f"Potential {pattern_name} found", snippet, relative_path)

                # 2. Scan API/Functions (only relevant extensions)
                if filepath.suffix.lower() in TEXT_EXTENSIONS:
                    for line_num, line in enumerate(content.splitlines(), start=1):
                        for func in DANGEROUS_FUNCTIONS:
                            if func in line:
                                snippet = line.strip()[:120]
                                self._add_finding("DANGEROUS_API", "MEDIUM", f"Dangerous API usage: {func}", snippet, f"{relative_path}:{line_num}")

            except Exception as e:
                self.logger.debug(f"Failed to process {filepath.name}: {e}")

        self.logger.info(f"    Scanned {scanned_count} files.")

    def analyze_native_libs(self) -> None:
        """Extracts and analyzes strings from native shared objects (.so)."""
        lib_base_dir = self.raw_dir / "lib"
        if not lib_base_dir.exists():
            return

        found_libs = list(lib_base_dir.rglob("*.so"))
        if not found_libs:
            return

        self.logger.info(f"[*] Analyzing {len(found_libs)} native library/libraries")

        suspicious_patterns = {
            "URL in binary":     re.compile(r"https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}"),
            "IP in binary":      re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
            "Unsafe C function": re.compile(r"\b(strcpy|strcat|sprintf|gets|scanf)\b"),
            "Crypto reference":  re.compile(r"\b(AES|DES|MD5|SHA1|RSA|EVP_)\b"),
        }

        for lib_path in found_libs:
            lib_name = lib_path.name
            arch = lib_path.parent.name
            relative_path = f"lib/{arch}/{lib_name}"
            
            self._add_finding("NATIVE_LIB", "INFO", f"Native library present: {lib_name}", 
                              f"Architecture: {arch} -> recommend manual static analysis", relative_path)

            result = self._run_shell_command(["strings", str(lib_path)], "strings extraction")
            if result.returncode != 0:
                continue

            strings_output = result.stdout
            for label, regex in suspicious_patterns.items():
                matches = list(set(regex.findall(strings_output)))[:5]
                if matches:
                    severity = "HIGH" if "Unsafe" in label else "MEDIUM" if ("URL" in label or "IP" in label) else "INFO"
                    self._add_finding("NATIVE_LIB", severity, f"{label} in {lib_name}", ", ".join(matches), relative_path)

    def generate_report(self) -> None:
        """Generates comprehensive JSON and cleanly formatted plain-text reports."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_base = f"security_report_{self.apk_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        txt_filename = f"{report_base}.txt"
        json_filename = f"{report_base}.json"

        categories = {
            "HIGH":   [f for f in self.findings if f.severity == "HIGH"],
            "MEDIUM": [f for f in self.findings if f.severity == "MEDIUM"],
            "LOW":    [f for f in self.findings if f.severity == "LOW"],
            "INFO":   [f for f in self.findings if f.severity == "INFO"]
        }

        # JSON generation
        json_report = {
            "apk": self.apk_name,
            "package": self.package_name,
            "timestamp": timestamp,
            "summary": {k.lower(): len(v) for k, v in categories.items()},
            "findings": [f.to_dict() for f in self.findings]
        }
        Path(json_filename).write_text(json.dumps(json_report, indent=2))

        # TXT generation
        lines = [
            "=" * 60,
            "  APK SECURITY SCAN REPORT",
            "  Generated by APK Security Scanner v2.0",
            "=" * 60,
            f"  APK:       {self.apk_name}",
            f"  Package:   {self.package_name}",
            f"  Timestamp: {timestamp}",
            "=" * 60,
            "",
            "SUMMARY"
        ]

        icons = {"HIGH": "🔴", "MEDIUM": "🔶", "LOW": "⚠️ ", "INFO": "ℹ️ "}
        for severity, items in categories.items():
            lines.append(f"  {icons[severity]} {severity:<8}: {len(items)}")
        
        lines.append("")

        for severity, items in categories.items():
            if not items:
                continue
            lines.extend([
                "─" * 60,
                f"  {icons[severity]} {severity} FINDINGS ({len(items)})",
                "─" * 60
            ])
            for i, f in enumerate(items, 1):
                lines.extend([
                    f"  [{i}] {f.title}",
                    f"      Type   : {f.type}",
                    f"      Detail : {f.detail}",
                    f"      File   : {f.file}",
                    ""
                ])

        lines.extend([
            "=" * 60,
            "  END OF REPORT",
            "  Next step: Manual verification of HIGH vulnerabilities",
            "=" * 60
        ])
        
        report_text = "\n".join(lines)
        Path(txt_filename).write_text(report_text)
        
        self.logger.info(f"\n{'─'*50}")
        self.logger.info("  SCAN COMPLETE — RESULTS SAVED")
        self.logger.info(f"{'─'*50}")
        self.logger.info(f"[+] Text Report: {txt_filename}")
        self.logger.info(f"[+] JSON Report: {json_filename}")

    def clean_up(self) -> None:
        """Cleans up internal temporary directories explicitly created during extraction."""
        self.logger.info("\n[*] Cleaning up temporary artifacts...")
        for d in (self.raw_dir, self.decompiled_dir):
            if d and d.exists():
                shutil.rmtree(d, ignore_errors=True)
        self.logger.info("[✓] Cleanup complete.")

    def _add_finding(self, f_type: str, severity: str, title: str, detail: str, file_path: str) -> None:
        """Internal helper to structure finding additions efficiently."""
        self.findings.append(Finding(f_type, severity, title, detail, str(file_path)))

    def run(self) -> None:
        """Executes the full scanning lifecycle cleanly, utilizing Safe cleanup blocks."""
        self._print_banner()
        self.logger.info(f"[*] Target: {self.apk_path}")
        
        try:
            self.extract_apk()
            self.analyze_manifest()
            self.analyze_source_code()
            self.analyze_native_libs()
            self.generate_report()
        except KeyboardInterrupt:
            self.logger.warning("\n[!] Scan interrupted by user.")
        except Exception as e:
            self.logger.error(f"\n[!] An unexpected error occurred: {e}")
            raise
        finally:
            self.clean_up()


# ============================================================================
# ENTRY POINT
# ============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Static analysis toolkit for Android APK files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python3 apk_scanner.py target_app.apk"
    )
    parser.add_argument("apk_path", type=str, help="Path to the APK file to scan")
    args = parser.parse_args()

    apk_path = Path(args.apk_path)
    if not apk_path.is_file():
        logging.error(f"[!] Error: File not found or is a directory -> {apk_path}")
        sys.exit(1)

    scanner = APKScanner(apk_path)
    scanner.run()

if __name__ == "__main__":
    main()
