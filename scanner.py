import os
import hashlib
import shutil
import json
import logging
import argparse
import time
from pathlib import Path
from datetime import datetime
from typing import Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ─────────────────────────────────────────────
#  LOGGING SETUP
# ─────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("antivirus.log"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger("AV-Sim")

# ─────────────────────────────────────────────
#  KNOWN MALWARE SIGNATURE DATABASE
#  (SHA256 hashes — add real ones here)
# ─────────────────────────────────────────────

DEFAULT_SIGNATURES: dict[str, str] = {
    # hash : malware name
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Empty.File.Suspicious",
    "44d88612fea8a8f36de82e1278abb02f": "EICAR.Test.Signature",
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR.Test.SHA256",
    "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899": "FakeMalware.Sample.A",
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef": "FakeMalware.Sample.B",
}

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".vbs", ".ps1", ".sh",
    ".dll", ".scr", ".pif", ".com", ".msi", ".jar",
    ".hta", ".wsf", ".reg", ".lnk"
}

SUSPICIOUS_STRINGS = [
    b"eval(base64_decode",
    b"powershell -enc",
    b"cmd.exe /c",
    b"WScript.Shell",
    b"CreateObject",
    b"shell_exec(",
    b"system(",
    b"os.system(",
    b"subprocess.Popen(",
    b"nc -e /bin/sh",
    b"rm -rf /",
    b"/dev/tcp/",
]

# ─────────────────────────────────────────────
#  CORE SCANNER
# ─────────────────────────────────────────────

class SignatureScanner:
    def __init__(
        self,
        signatures: dict[str, str],
        quarantine_dir: str = "quarantine",
        db_path: Optional[str] = None
    ):
        self.signatures = dict(signatures)
        self.quarantine_dir = Path(quarantine_dir)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.scan_results: list[dict] = []
        self.db_path = db_path

        if db_path and Path(db_path).exists():
            self._load_signature_db(db_path)

    def _load_signature_db(self, path: str):
        try:
            with open(path, "r") as f:
                extra = json.load(f)
            self.signatures.update(extra)
            log.info(f"Loaded {len(extra)} signatures from {path}")
        except (json.JSONDecodeError, OSError) as e:
            log.warning(f"Failed to load signature DB: {e}")

    def _hash_file(self, filepath: Path) -> tuple[str, str]:
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                while chunk := f.read(65536):
                    md5.update(chunk)
                    sha256.update(chunk)
            return md5.hexdigest(), sha256.hexdigest()
        except (PermissionError, OSError) as e:
            log.warning(f"Cannot read {filepath}: {e}")
            return "", ""

    def _check_suspicious_strings(self, filepath: Path) -> list[str]:
        found = []
        try:
            with open(filepath, "rb") as f:
                content = f.read(1_048_576)  # Read first 1MB
            for pattern in SUSPICIOUS_STRINGS:
                if pattern in content:
                    found.append(pattern.decode(errors="ignore"))
        except (PermissionError, OSError):
            pass
        return found

    def _check_extension(self, filepath: Path) -> bool:
        return filepath.suffix.lower() in SUSPICIOUS_EXTENSIONS

    def scan_file(self, filepath: Path) -> dict:
        filepath = Path(filepath)
        result = {
            "file": str(filepath),
            "timestamp": datetime.now().isoformat(),
            "status": "clean",
            "threat_name": None,
            "md5": None,
            "sha256": None,
            "suspicious_strings": [],
            "suspicious_extension": False,
            "quarantined": False,
            "size_bytes": 0,
        }

        if not filepath.is_file():
            result["status"] = "skipped"
            return result

        try:
            result["size_bytes"] = filepath.stat().st_size
        except OSError:
            pass

        md5, sha256 = self._hash_file(filepath)
        result["md5"] = md5
        result["sha256"] = sha256

        # Signature match (SHA256)
        if sha256 in self.signatures:
            result["status"] = "malicious"
            result["threat_name"] = self.signatures[sha256]
            log.warning(f"[THREAT] {filepath.name} → {result['threat_name']} (SHA256 match)")

        # Signature match (MD5)
        elif md5 in self.signatures:
            result["status"] = "malicious"
            result["threat_name"] = self.signatures[md5]
            log.warning(f"[THREAT] {filepath.name} → {result['threat_name']} (MD5 match)")

        else:
            # Heuristic checks
            suspicious_strs = self._check_suspicious_strings(filepath)
            ext_suspicious = self._check_extension(filepath)

            result["suspicious_strings"] = suspicious_strs
            result["suspicious_extension"] = ext_suspicious

            if suspicious_strs and ext_suspicious:
                result["status"] = "suspicious"
                result["threat_name"] = "Heuristic.MultiFlag"
                log.warning(f"[SUSPICIOUS] {filepath.name} → suspicious extension + {len(suspicious_strs)} pattern(s)")
            elif suspicious_strs:
                result["status"] = "suspicious"
                result["threat_name"] = "Heuristic.StringMatch"
                log.info(f"[SUSPICIOUS] {filepath.name} → matched: {suspicious_strs[0]}")
            elif ext_suspicious:
                result["status"] = "warning"
                result["threat_name"] = "Heuristic.SuspiciousExtension"
                log.info(f"[WARNING] {filepath.name} → suspicious extension ({filepath.suffix})")
            else:
                log.info(f"[CLEAN] {filepath.name}")

        self.scan_results.append(result)
        return result

    def quarantine_file(self, filepath: Path) -> bool:
        filepath = Path(filepath)
        try:
            dest = self.quarantine_dir / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filepath.name}.quarantine"
            shutil.move(str(filepath), str(dest))
            log.info(f"[QUARANTINED] {filepath.name} → {dest}")
            return True
        except (PermissionError, OSError) as e:
            log.error(f"Quarantine failed for {filepath}: {e}")
            return False

    def scan_directory(
        self,
        directory: str,
        recursive: bool = True,
        auto_quarantine: bool = False,
        extensions: Optional[list[str]] = None
    ) -> list[dict]:
        directory = Path(directory)
        if not directory.is_dir():
            log.error(f"Not a valid directory: {directory}")
            return []

        pattern = "**/*" if recursive else "*"
        files = [f for f in directory.glob(pattern) if f.is_file()]

        if extensions:
            files = [f for f in files if f.suffix.lower() in {e.lower() for e in extensions}]

        log.info(f"Scanning {len(files)} files in {directory} ...")
        print(f"\n{'='*60}")
        print(f"  Target    : {directory}")
        print(f"  Files     : {len(files)}")
        print(f"  Recursive : {recursive}")
        print(f"  Quarantine: {auto_quarantine}")
        print(f"{'='*60}\n")

        for filepath in files:
            result = self.scan_file(filepath)
            if auto_quarantine and result["status"] in ("malicious", "suspicious"):
                quarantined = self.quarantine_file(filepath)
                result["quarantined"] = quarantined

        return self.scan_results

    def generate_report(self, output_path: Optional[str] = None) -> dict:
        total = len(self.scan_results)
        malicious = [r for r in self.scan_results if r["status"] == "malicious"]
        suspicious = [r for r in self.scan_results if r["status"] == "suspicious"]
        warnings = [r for r in self.scan_results if r["status"] == "warning"]
        clean = [r for r in self.scan_results if r["status"] == "clean"]
        quarantined = [r for r in self.scan_results if r["quarantined"]]

        report = {
            "scan_time": datetime.now().isoformat(),
            "summary": {
                "total_scanned": total,
                "malicious": len(malicious),
                "suspicious": len(suspicious),
                "warnings": len(warnings),
                "clean": len(clean),
                "quarantined": len(quarantined),
            },
            "threats": malicious + suspicious,
            "all_results": self.scan_results,
        }

        print(f"\n{'='*60}")
        print(f"  SCAN REPORT — {report['scan_time']}")
        print(f"{'='*60}")
        print(f"  Total Scanned : {total}")
        print(f"  Malicious     : {len(malicious)}")
        print(f"  Suspicious    : {len(suspicious)}")
        print(f"  Warnings      : {len(warnings)}")
        print(f"  Clean         : {len(clean)}")
        print(f"  Quarantined   : {len(quarantined)}")
        print(f"{'='*60}")

        if malicious or suspicious:
            print("\n  THREATS FOUND:")
            for r in malicious + suspicious:
                q = " [QUARANTINED]" if r["quarantined"] else ""
                print(f"    [{r['status'].upper()}] {r['file']}")
                print(f"           → {r['threat_name']}{q}")
                print(f"           → SHA256: {r['sha256']}")
        else:
            print("\n  No threats detected.")

        print()

        if output_path:
            try:
                with open(output_path, "w") as f:
                    json.dump(report, f, indent=2)
                log.info(f"Report saved to {output_path}")
            except OSError as e:
                log.error(f"Failed to save report: {e}")

        return report


# ─────────────────────────────────────────────
#  REAL-TIME MONITOR (watchdog)
# ─────────────────────────────────────────────

class RealTimeMonitor(FileSystemEventHandler):
    def __init__(self, scanner: SignatureScanner, auto_quarantine: bool = False):
        self.scanner = scanner
        self.auto_quarantine = auto_quarantine

    def on_created(self, event):
        if not event.is_directory:
            self._process(event.src_path, "CREATED")

    def on_modified(self, event):
        if not event.is_directory:
            self._process(event.src_path, "MODIFIED")

    def _process(self, filepath: str, action: str):
        path = Path(filepath)
        log.info(f"[MONITOR] {action}: {path.name}")
        result = self.scanner.scan_file(path)
        if self.auto_quarantine and result["status"] in ("malicious", "suspicious"):
            self.scanner.quarantine_file(path)
            result["quarantined"] = True

def start_monitor(directory: str, scanner: SignatureScanner, auto_quarantine: bool = False):
    handler = RealTimeMonitor(scanner, auto_quarantine)
    observer = Observer()
    observer.schedule(handler, directory, recursive=True)
    observer.start()
    log.info(f"[MONITOR] Watching {directory} — press Ctrl+C to stop")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        log.info("[MONITOR] Stopped.")
    observer.join()


# ─────────────────────────────────────────────
#  SIGNATURE DB UTILS
# ─────────────────────────────────────────────

def add_signature(db_path: str, file_path: str, threat_name: str):
    path = Path(file_path)
    if not path.is_file():
        print(f"[!] File not found: {file_path}")
        return
    sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
    db: dict = {}
    if Path(db_path).exists():
        with open(db_path, "r") as f:
            db = json.load(f)
    db[sha256] = threat_name
    with open(db_path, "w") as f:
        json.dump(db, f, indent=2)
    print(f"[+] Added: {sha256} → {threat_name}")

def hash_file_standalone(file_path: str):
    path = Path(file_path)
    if not path.is_file():
        print(f"[!] File not found: {file_path}")
        return
    md5 = hashlib.md5(path.read_bytes()).hexdigest()
    sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
    print(f"File   : {path.name}")
    print(f"MD5    : {md5}")
    print(f"SHA256 : {sha256}")


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Basic Antivirus Simulation — Signature Scanner",
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command")

    # scan command
    scan_p = subparsers.add_parser("scan", help="Scan a file or directory")
    scan_p.add_argument("target", help="File or directory to scan")
    scan_p.add_argument("-r", "--recursive", action="store_true", default=True)
    scan_p.add_argument("-q", "--quarantine", action="store_true", help="Auto-quarantine threats")
    scan_p.add_argument("--db", help="Path to custom signature DB (JSON)")
    scan_p.add_argument("--report", help="Save JSON report to this path")
    scan_p.add_argument("--ext", nargs="*", help="Only scan these extensions e.g. .py .bat")

    # monitor command
    mon_p = subparsers.add_parser("monitor", help="Real-time directory monitor")
    mon_p.add_argument("directory", help="Directory to watch")
    mon_p.add_argument("-q", "--quarantine", action="store_true")
    mon_p.add_argument("--db", help="Signature DB path")

    # hash command
    hash_p = subparsers.add_parser("hash", help="Print file hashes")
    hash_p.add_argument("file", help="File to hash")

    # add-sig command
    sig_p = subparsers.add_parser("add-sig", help="Add a file signature to DB")
    sig_p.add_argument("file", help="File to fingerprint")
    sig_p.add_argument("name", help="Threat name e.g. Trojan.Generic.A")
    sig_p.add_argument("--db", default="signatures.json")

    args = parser.parse_args()

    if args.command == "scan":
        scanner = SignatureScanner(
            signatures=DEFAULT_SIGNATURES,
            db_path=args.db
        )
        target = Path(args.target)
        if target.is_file():
            result = scanner.scan_file(target)
            if args.quarantine and result["status"] in ("malicious", "suspicious"):
                scanner.quarantine_file(target)
        elif target.is_dir():
            scanner.scan_directory(
                str(target),
                recursive=args.recursive,
                auto_quarantine=args.quarantine,
                extensions=args.ext
            )
        else:
            print(f"[!] Target not found: {target}")
            return
        scanner.generate_report(output_path=args.report)

    elif args.command == "monitor":
        scanner = SignatureScanner(
            signatures=DEFAULT_SIGNATURES,
            db_path=args.db
        )
        start_monitor(args.directory, scanner, auto_quarantine=args.quarantine)

    elif args.command == "hash":
        hash_file_standalone(args.file)

    elif args.command == "add-sig":
        add_signature(args.db, args.file, args.name)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
