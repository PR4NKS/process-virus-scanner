import psutil
import requests
import hashlib
import time
import os
import sys


VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3"

RATE_LIMIT_BATCH     = 4     # Free API: 4 requests per minute
RATE_LIMIT_WAIT      = 16    # Seconds to pause after each batch
ANALYSIS_POLL_MAX    = 12    # Max attempts to wait for VT analysis
ANALYSIS_POLL_DELAY  = 5     # Seconds between each poll attempt
MAX_ENGINES_SHOWN    = 5     # How many detecting engines to display


class ProcessScanner:
    """
    Scans all running processes on the system using the VirusTotal API.

    For each process:
      1. Compute its SHA-256 hash
      2. Look it up in the VT database
      3. Upload it if unknown, then wait for results
      4. Report detections and offer termination options
    """

    def __init__(self, api_key: str):
        self.api_key     = api_key
        self.session     = requests.Session()
        self.session.headers.update({
            "x-apikey": api_key,
            "Accept":   "application/json"
        })
        self.scanned_count = 0
        self.threats_found = []


    # ------------------------------------------------------------------ #
    #  Process enumeration                                                 #
    # ------------------------------------------------------------------ #

    def collect_processes(self) -> list[dict]:
        """
        Return a list of running processes that have a readable executable path.
        Silently skips processes we can't access (protected, zombie, gone).
        """
        processes = []

        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "create_time"]):
            try:
                info = proc.info
                exe  = info.get("exe")

                if exe and os.path.exists(exe):
                    processes.append(info)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass  # Process disappeared or is off-limits — skip quietly

        return processes


    # ------------------------------------------------------------------ #
    #  Hashing                                                             #
    # ------------------------------------------------------------------ #

    def compute_sha256(self, filepath: str) -> str | None:
        """
        Read the file in chunks and return its SHA-256 hash.
        Returns None if the file can't be read.
        """
        try:
            hasher = hashlib.sha256()

            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hasher.update(chunk)

            return hasher.hexdigest()

        except OSError:
            return None


    # ------------------------------------------------------------------ #
    #  VirusTotal API calls                                                #
    # ------------------------------------------------------------------ #

    def lookup_hash(self, file_hash: str) -> dict | None:
        """
        Ask VirusTotal if it already has results for this file hash.
        Returns the full response dict, or None if the file is unknown / on error.
        """
        url = f"{VIRUSTOTAL_API_URL}/files/{file_hash}"

        try:
            response = self.session.get(url, timeout=30)

            if response.status_code == 200:
                return response.json()

            if response.status_code == 404:
                return None  # File is not yet in the VT database

            print(f"  [!] Hash lookup returned HTTP {response.status_code}")
            return None

        except requests.RequestException as error:
            print(f"  [!] Hash lookup failed: {error}")
            return None


    def upload_file(self, filepath: str) -> dict | None:
        """
        Upload a file to VirusTotal for fresh scanning.
        Returns the submission response, or None on failure.
        """
        url = f"{VIRUSTOTAL_API_URL}/files"

        try:
            with open(filepath, "rb") as f:
                filename = os.path.basename(filepath)
                response = self.session.post(
                    url,
                    files={"file": (filename, f)},
                    timeout=60
                )

            if response.status_code == 200:
                return response.json()

            print(f"  [!] Upload returned HTTP {response.status_code}")
            return None

        except (OSError, requests.RequestException) as error:
            print(f"  [!] Upload failed: {error}")
            return None


    def wait_for_analysis(self, analysis_id: str) -> dict | None:
        """
        Poll the VT analysis endpoint until the scan finishes (or we give up).
        Returns the completed analysis dict, or None on timeout/failure.
        """
        url = f"{VIRUSTOTAL_API_URL}/analyses/{analysis_id}"

        for attempt in range(1, ANALYSIS_POLL_MAX + 1):
            time.sleep(ANALYSIS_POLL_DELAY)

            try:
                response = self.session.get(url, timeout=30)

                if response.status_code != 200:
                    continue

                data   = response.json()
                status = data["data"]["attributes"]["status"]

                if status == "completed":
                    return data

                if status == "failed":
                    print(f"  [!] Analysis failed on VT's end")
                    return None

            except (requests.RequestException, KeyError):
                continue  # Try again on network hiccup or unexpected response shape

        print(f"  [!] Analysis timed out after {ANALYSIS_POLL_MAX * ANALYSIS_POLL_DELAY}s")
        return None


    # ------------------------------------------------------------------ #
    #  Per-process analysis                                                #
    # ------------------------------------------------------------------ #

    def analyze_process(self, proc: dict, index: int, total: int) -> dict | None:
        """
        Fully analyze one process:
          - Hash the executable
          - Check VT database (or upload if new)
          - Print findings
          - Return threat info dict if malicious, else None
        """
        print(f"\n{'─' * 60}")
        print(f"[{index}/{total}] {proc['name']}  (PID {proc['pid']})")
        print(f"  Path : {proc['exe']}")

        # Step 1 — hash the file
        file_hash = self.compute_sha256(proc["exe"])
        if not file_hash:
            print("  [!] Cannot read file — may be protected by the OS")
            return None

        print(f"  SHA256 : {file_hash[:20]}...")

        # Step 2 — ask VirusTotal
        print("  Checking VirusTotal database...")
        vt_data = self.lookup_hash(file_hash)

        if vt_data:
            threat = self._process_existing_result(vt_data, proc, file_hash)
        else:
            threat = self._upload_and_analyze(proc, file_hash)

        self.scanned_count += 1
        return threat


    def _process_existing_result(self, vt_data: dict, proc: dict, file_hash: str) -> dict | None:
        """Parse results for a file that VT already knows about."""
        print("  Found in database")

        attrs       = vt_data["data"]["attributes"]
        stats       = attrs.get("last_analysis_stats", {})
        malicious   = stats.get("malicious",  0)
        suspicious  = stats.get("suspicious", 0)
        total_scans = sum(stats.values())

        print(f"  Results  →  {malicious} malicious  /  {suspicious} suspicious  /  {total_scans} engines")

        # Show which engines flagged this file
        engines       = attrs.get("last_analysis_results", {})
        flagged_lines = [
            f"    • {engine}: {result['result']}"
            for engine, result in engines.items()
            if result["category"] in ("malicious", "suspicious")
        ]

        if flagged_lines:
            print("  Flagged by:")
            for line in flagged_lines[:MAX_ENGINES_SHOWN]:
                print(line)

        if malicious > 0:
            return self._record_threat(proc, file_hash, malicious, suspicious, source="database")

        print("  Clean — no threats detected")
        return None


    def _upload_and_analyze(self, proc: dict, file_hash: str) -> dict | None:
        """Upload an unknown file to VT and wait for the scan to finish."""
        print("  Not in database — uploading for scanning...")
        submission = self.upload_file(proc["exe"])

        if not submission:
            print("  [!] Upload failed — skipping this process")
            return None

        analysis_id = submission["data"]["id"]
        print(f"  Waiting for analysis (up to {ANALYSIS_POLL_MAX * ANALYSIS_POLL_DELAY}s)...")

        result = self.wait_for_analysis(analysis_id)
        if not result:
            return None

        stats      = result["data"]["attributes"].get("stats", {})
        malicious  = stats.get("malicious",  0)
        suspicious = stats.get("suspicious", 0)

        print(f"  Results  →  {malicious} malicious  /  {suspicious} suspicious")

        if malicious > 0:
            return self._record_threat(proc, file_hash, malicious, suspicious, source="fresh scan")

        print("  Clean — no threats detected")
        return None


    def _record_threat(
        self,
        proc:       dict,
        file_hash:  str,
        malicious:  int,
        suspicious: int,
        source:     str
    ) -> dict:
        """Build a threat entry, log it, and add it to the internal list."""
        vt_url = f"https://www.virustotal.com/gui/file/{file_hash}"

        threat = {
            "pid":        proc["pid"],
            "name":       proc["name"],
            "path":       proc["exe"],
            "malicious":  malicious,
            "suspicious": suspicious,
            "vt_url":     vt_url,
            "source":     source,
        }

        self.threats_found.append(threat)

        print(f"\n  *** THREAT DETECTED ({source}) ***")
        print(f"  {malicious} engine(s) flagged this file as malware")
        print(f"  Report : {vt_url}")

        return threat


    # ------------------------------------------------------------------ #
    #  Main scan loop                                                      #
    # ------------------------------------------------------------------ #

    def run(self):
        """
        Entry point for a full system scan.
        Enumerates all processes, scans each one, then prints the final report.
        """
        print("\n" + "=" * 60)
        print("PROCESS VIRUS SCANNER  —  powered by VirusTotal")
        print("=" * 60)

        # Collect targets
        print("\nGathering running processes...")
        processes = self.collect_processes()
        total     = len(processes)

        if total == 0:
            print("No scannable processes found.")
            return

        print(f"Found {total} processes to scan\n")
        print("Starting scan (this may take a while on the free API tier)...")

        # Scan each process, pause every RATE_LIMIT_BATCH to respect the free quota
        for index, proc in enumerate(processes, start=1):
            self.analyze_process(proc, index, total)

            if index % RATE_LIMIT_BATCH == 0 and index < total:
                print(f"\n  Pausing {RATE_LIMIT_WAIT}s to respect API rate limit...")
                time.sleep(RATE_LIMIT_WAIT)

        self.print_report()


    # ------------------------------------------------------------------ #
    #  Final report                                                        #
    # ------------------------------------------------------------------ #

    def print_report(self):
        """Print a summary of all detections and prompt the user for actions."""
        print("\n" + "=" * 60)
        print("SCAN COMPLETE")
        print("=" * 60)
        print(f"Processes scanned : {self.scanned_count}")
        print(f"Threats found     : {len(self.threats_found)}")

        if not self.threats_found:
            print("\nAll scanned processes appear to be clean.")
            return

        print("\nThe following processes were flagged as malicious:\n")

        for threat in self.threats_found:
            print(f"  Process : {threat['name']}  (PID {threat['pid']})")
            print(f"  Path    : {threat['path']}")
            print(f"  Flagged : {threat['malicious']} engine(s)  |  Source: {threat['source']}")
            print(f"  Report  : {threat['vt_url']}")

            print("\n  What would you like to do?")
            print("    1 — Keep running (do nothing)")
            print("    2 — Terminate the process")
            print("    3 — Investigate manually (open VT report link above)")

            choice = input(f"\n  Choice for PID {threat['pid']} [1/2/3]: ").strip()

            if choice == "2":
                self._terminate_process(threat["pid"])
            elif choice == "3":
                print("  Open the VT report link above in your browser for full details.")

            print()

        print("=" * 60)


    def _terminate_process(self, pid: int):
        """
        Attempt a graceful termination, escalating to SIGKILL if the process
        is still alive after two seconds.
        """
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            print(f"  Termination signal sent to PID {pid}...")
            time.sleep(2)

            if proc.is_running():
                proc.kill()
                print(f"  Force-killed PID {pid}")
            else:
                print(f"  PID {pid} terminated successfully")

        except psutil.NoSuchProcess:
            print(f"  PID {pid} no longer exists")
        except psutil.AccessDenied:
            print(f"  Access denied — cannot terminate PID {pid} (try running as Administrator)")
        except Exception as error:
            print(f"  Could not terminate PID {pid}: {error}")


# ------------------------------------------------------------------ #
#  Entry point                                                         #
# ------------------------------------------------------------------ #

def check_admin_windows():
    """Warn the user if they're not running as Administrator on Windows."""
    if os.name != "nt":
        return

    try:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("\n[!] Not running as Administrator.")
            print("    Some system processes may be inaccessible.")
            input("    Press Enter to continue anyway...\n")
    except Exception:
        pass


def prompt_api_key() -> str:
    """Ask the user for their VirusTotal API key and do basic validation."""
    print("\nEnter your VirusTotal API key")
    print("(Don't have one? Sign up free at https://www.virustotal.com/gui/join-us)\n")

    api_key = input("API key: ").strip()

    if not api_key:
        print("\n[!] No API key provided. Exiting.")
        sys.exit(1)

    if len(api_key) < 30:
        print("\n[!] This key looks too short — it may be invalid.")
        confirm = input("Continue anyway? [y/n]: ").strip().lower()
        if confirm != "y":
            sys.exit(1)

    return api_key


def main():
    print("=" * 60)
    print("REAL-TIME PROCESS VIRUS SCANNER")
    print("=" * 60)
    print()
    print("What this tool does:")
    print("  - Lists all running processes on your system")
    print("  - Hashes each executable (SHA-256)")
    print("  - Checks every hash against VirusTotal's 70+ AV engines")
    print("  - Uploads unknown files automatically for fresh scanning")
    print("  - Lets you terminate anything flagged as malicious")
    print()
    print("Estimated time: 15–30 min for a typical system (free API: 4 req/min)")
    print("Tip: run as Administrator / sudo for full process access")
    print("=" * 60)

    check_admin_windows()

    api_key = prompt_api_key()
    scanner = ProcessScanner(api_key)

    try:
        scanner.run()

    except KeyboardInterrupt:
        print(f"\n\nScan interrupted.")
        print(f"Scanned {scanner.scanned_count} process(es) before stopping.")

        if scanner.threats_found:
            print(f"Threats found so far: {len(scanner.threats_found)}")

    except Exception as error:
        print(f"\n[!] Unexpected error: {error}")
        print("    Try running with Administrator / root privileges.")
        sys.exit(1)


if __name__ == "__main__":
    main()