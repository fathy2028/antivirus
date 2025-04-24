import os
import hashlib
import shutil
import json
import argparse
import logging
import time
from pathlib import Path

# --- Configuration ---
CONFIG = {
    "signature_db": "signatures.db",
    "quarantine_dir": "quarantine",
    "quarantine_manifest": "quarantine/manifest.json",
    "log_file": "scan.log",
    "default_action": "report", # report, quarantine, remove
    "heuristic_level": 1, # 0: off, 1: basic (name/size), 2: content (entropy/strings)
    "max_file_size_heuristic": 50 * 1024 * 1024 # Skip heuristics on huge files
}

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] %(message)s',
                    handlers=[
                        logging.FileHandler(CONFIG["log_file"]),
                        logging.StreamHandler() # Also print to console
                    ])

# --- Signature Handling ---
def load_signatures(db_path):
    signatures = {}
    try:
        with open(db_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and ',' in line:
                    sha256, malware_name = line.split(',', 1)
                    signatures[sha256] = malware_name
        logging.info(f"Loaded {len(signatures)} signatures from {db_path}")
    except FileNotFoundError:
        logging.warning(f"Signature file {db_path} not found.")
    except Exception as e:
        logging.error(f"Error loading signatures: {e}")
    return signatures

def check_signature(file_path, signatures):
    try:
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                hasher.update(chunk)
        file_hash = hasher.hexdigest()
        
        if file_hash in signatures:
            return True, signatures[file_hash], file_hash # Detected, Malware Name, Hash
    except IOError as e:
        logging.warning(f"Could not read file {file_path} for hashing: {e}")
    except Exception as e:
        logging.error(f"Error hashing file {file_path}: {e}")
    return False, None, None # Not detected

# --- Heuristic Handling (Basic Examples) ---
def check_heuristics(file_path):
    suspicion_score = 0
    reasons = []
    file_name = os.path.basename(file_path)
    file_ext = os.path.splitext(file_name)[1].lower()
    
    try:
        file_size = os.path.getsize(file_path)

        # Rule: Suspicious double extensions
        if file_name.count('.') >= 2 and any(ext in file_name.lower() for ext in ['.exe.', '.scr.', '.com.', '.bat.', '.vbs.']):
             suspicion_score += 2
             reasons.append("Double Extension")
             
        # Rule: Disguised executable extensions
        if file_ext in ['.exe', '.scr', '.bat', '.vbs', '.ps1'] and any(doc_ext in file_name.lower() for doc_ext in ['.pdf', '.doc', '.xls', '.jpg']):
             suspicion_score += 2
             reasons.append("Disguised Executable")

        # Rule: Very small executable (potential downloader)
        if file_ext == '.exe' and file_size > 0 and file_size < 50 * 1024: # < 50 KB
            suspicion_score += 1
            reasons.append("Small Executable")

        # Add more rules (entropy, strings - requires reading content) if heuristic_level > 1
        # ... (example entropy calculation or string search) ...

    except OSError as e:
        logging.warning(f"Could not get stats for file {file_path}: {e}")
        return False, None # Cannot analyze

    if suspicion_score > 1: # Threshold
         return True, f"Heuristic Score: {suspicion_score} ({', '.join(reasons)})"
         
    return False, None # Not suspicious


# --- Quarantine Handling ---
def load_quarantine_manifest():
    try:
        if os.path.exists(CONFIG["quarantine_manifest"]):
            with open(CONFIG["quarantine_manifest"], 'r') as f:
                return json.load(f)
        return {}
    except Exception as e:
        logging.error(f"Error loading quarantine manifest: {e}")
        return {}

def save_quarantine_manifest(manifest):
    try:
        os.makedirs(os.path.dirname(CONFIG["quarantine_manifest"]), exist_ok=True)
        with open(CONFIG["quarantine_manifest"], 'w') as f:
            json.dump(manifest, f, indent=4)
    except Exception as e:
        logging.error(f"Error saving quarantine manifest: {e}")


def quarantine_file(file_path, reason):
    logging.info(f"Quarantining {file_path} due to: {reason}")
    if not os.path.exists(file_path):
         logging.error(f"File not found for quarantine: {file_path}")
         return False
         
    try:
        os.makedirs(CONFIG["quarantine_dir"], exist_ok=True)
        manifest = load_quarantine_manifest()

        quarantine_id = str(int(time.time() * 1000)) # Simple timestamp-based ID
        quarantined_filename = f"{quarantine_id}.quar"
        quarantined_filepath = os.path.join(CONFIG["quarantine_dir"], quarantined_filename)

        # Simple XOR 'encryption' (optional, basic obfuscation)
        # key = 0xAA # Example simple key
        # with open(file_path, 'rb') as f_in, open(quarantined_filepath, 'wb') as f_out:
        #     while True:
        #         chunk = f_in.read(4096)
        #         if not chunk: break
        #         encoded_chunk = bytes([b ^ key for b in chunk])
        #         f_out.write(encoded_chunk)
        # If not encoding, just move/copy:
        shutil.move(file_path, quarantined_filepath) # Use move to take it out of circulation

        manifest[quarantine_id] = {
            "original_path": os.path.abspath(file_path),
            "reason": reason,
            "timestamp": time.time(),
            "quarantined_filename": quarantined_filename
        }
        save_quarantine_manifest(manifest)
        logging.info(f"File quarantined successfully as {quarantined_filename} (ID: {quarantine_id})")
        return True

    except Exception as e:
        logging.error(f"Failed to quarantine {file_path}: {e}")
        # Attempt to move back if failed mid-way? Complex recovery.
        if os.path.exists(quarantined_filepath):
             # Maybe try to put it back if move failed? Risky.
             logging.warning("Quarantine partially failed. File might be moved but not recorded.")
        return False

def restore_quarantined_file(quarantine_id):
    manifest = load_quarantine_manifest()
    if quarantine_id not in manifest:
        print(f"Error: Quarantine ID {quarantine_id} not found.")
        logging.warning(f"Attempt to restore non-existent quarantine ID: {quarantine_id}")
        return

    item = manifest[quarantine_id]
    quarantined_filepath = os.path.join(CONFIG["quarantine_dir"], item["quarantined_filename"])
    original_path = item["original_path"]
    original_dir = os.path.dirname(original_path)

    if not os.path.exists(quarantined_filepath):
        print(f"Error: Quarantined file not found: {quarantined_filepath}")
        logging.error(f"Quarantined file missing for ID {quarantine_id}: {quarantined_filepath}")
        # Clean up manifest entry?
        # del manifest[quarantine_id]
        # save_quarantine_manifest(manifest)
        return

    try:
        os.makedirs(original_dir, exist_ok=True)
        # Add XOR decoding here if encoding was used during quarantine
        shutil.move(quarantined_filepath, original_path)
        logging.info(f"Restored {quarantined_filepath} to {original_path}")
        del manifest[quarantine_id]
        save_quarantine_manifest(manifest)
        print(f"File restored successfully to: {original_path}")
    except Exception as e:
        print(f"Error restoring file: {e}")
        logging.error(f"Failed to restore {quarantine_id} from {quarantined_filepath} to {original_path}: {e}")

def list_quarantine():
     manifest = load_quarantine_manifest()
     if not manifest:
         print("Quarantine is empty.")
         return
     print("Quarantined Items:")
     print("-" * 40)
     for qid, item in manifest.items():
         ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(item.get('timestamp', 0)))
         print(f"ID          : {qid}")
         print(f"Original Path: {item.get('original_path', 'N/A')}")
         print(f"Reason      : {item.get('reason', 'N/A')}")
         print(f"Date        : {ts}")
         print(f"Stored As   : {item.get('quarantined_filename', 'N/A')}")
         print("-" * 40)


# --- Removal Handling ---
def remove_file(file_path, reason):
    logging.warning(f"Removing infected file: {file_path} (Reason: {reason})")
    try:
        os.remove(file_path)
        logging.info(f"File removed successfully: {file_path}")
        return True
    except OSError as e:
        logging.error(f"Failed to remove file {file_path}: {e}")
        return False
    except Exception as e:
        logging.error(f"Unexpected error removing file {file_path}: {e}")
        return False

# --- Scanner Engine ---
def scan_path(target_path, signatures, action):
    scan_summary = {"files_scanned": 0, "threats_found": 0, "actions_taken": 0}
    target_path = Path(target_path) # Use pathlib for easier path handling

    if not target_path.exists():
        logging.error(f"Path does not exist: {target_path}")
        return scan_summary

    items_to_scan = []
    if target_path.is_file():
        items_to_scan.append(target_path)
    elif target_path.is_dir():
        # Could use Path.rglob('*') for recursion
        for root, _, files in os.walk(target_path):
            for file in files:
                items_to_scan.append(Path(root) / file)
    else:
         logging.warning(f"Target path is neither a file nor a directory: {target_path}")
         return scan_summary


    logging.info(f"Starting scan on {target_path}...")
    for file_path in items_to_scan:
        scan_summary["files_scanned"] += 1
        file_path_str = str(file_path) # Convert back for functions expecting strings
        
        if not file_path.is_file(): # Skip directories, symlinks etc.
             continue

        logging.debug(f"Scanning: {file_path_str}")

        detected = False
        detection_type = "N/A"
        malware_name = "N/A"

        # 1. Check Signature
        sig_detected, sig_name, file_hash = check_signature(file_path_str, signatures)
        if sig_detected:
            detected = True
            detection_type = "Signature"
            malware_name = sig_name
            logging.warning(f"SIGNATURE DETECTED: {file_path_str} -> {malware_name} ({file_hash})")
        
        # 2. Check Heuristics (if no signature match or configured always)
        # Add condition: and CONFIG["heuristic_level"] > 0 and os.path.getsize(file_path_str) < CONFIG["max_file_size_heuristic"]
        if not detected and CONFIG["heuristic_level"] > 0 :
             try:
                 if file_path.stat().st_size <= CONFIG["max_file_size_heuristic"]:
                     heur_detected, heur_reason = check_heuristics(file_path_str)
                     if heur_detected:
                         detected = True
                         detection_type = "Heuristic"
                         malware_name = heur_reason
                         logging.warning(f"HEURISTIC DETECTED: {file_path_str} -> {malware_name}")
                 else:
                     logging.debug(f"Skipping heuristic scan for large file: {file_path_str}")
             except OSError as e:
                  logging.warning(f"Cannot get size for heuristic check: {file_path_str}: {e}")

        # 3. Take Action
        if detected:
            scan_summary["threats_found"] += 1
            action_taken = False
            if action == "quarantine":
                action_taken = quarantine_file(file_path_str, f"{detection_type}: {malware_name}")
            elif action == "remove":
                action_taken = remove_file(file_path_str, f"{detection_type}: {malware_name}")
            elif action == "report":
                logging.info(f"Threat reported (no action taken): {file_path_str}")
                action_taken = True # Reporting is considered an action outcome
            
            if action_taken and action != "report":
                 scan_summary["actions_taken"] += 1
        else:
             logging.debug(f"Clean: {file_path_str}")


    logging.info("Scan Complete.")
    logging.info(f"Summary: Files Scanned: {scan_summary['files_scanned']}, Threats Found: {scan_summary['threats_found']}, Actions Taken: {scan_summary['actions_taken']}")
    return scan_summary


# --- Main CLI ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Lightweight Antivirus Scanner")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Scan command
    parser_scan = subparsers.add_parser("scan", help="Scan a file or directory")
    parser_scan.add_argument("path", help="File or directory path to scan")
    parser_scan.add_argument("--action", choices=["report", "quarantine", "remove"],
                             default=CONFIG["default_action"], help="Action to take on detection")
    # Add more options like --recursive, --heuristic-level etc.

    # Quarantine management commands
    parser_q = subparsers.add_parser("quarantine", help="Manage quarantined files")
    q_subparsers = parser_q.add_subparsers(dest="q_command", required=True)
    q_subparsers.add_parser("list", help="List quarantined items")
    parser_q_restore = q_subparsers.add_parser("restore", help="Restore a quarantined item by ID")
    parser_q_restore.add_argument("id", help="Quarantine ID to restore")
    parser_q_delete = q_subparsers.add_parser("delete", help="Delete an item from quarantine")
    parser_q_delete.add_argument("id", help="Quarantine ID to delete permanently")

    # Update command (basic - just points to a new file)
    parser_update = subparsers.add_parser("update", help="Update signature database (specify new file path)")
    parser_update.add_argument("db_path", help="Path to the new signature database file")


    args = parser.parse_args()

    if args.command == "scan":
        signatures = load_signatures(CONFIG["signature_db"])
        scan_path(args.path, signatures, args.action)
    elif args.command == "quarantine":
        if args.q_command == "list":
             list_quarantine()
        elif args.q_command == "restore":
             restore_quarantined_file(args.id)
        elif args.q_command == "delete":
             # Implement permanent deletion from quarantine store + manifest
             print(f"Quarantine delete for ID {args.id} - not fully implemented yet.")
             pass
    elif args.command == "update":
         # Basic update: Just copy the new DB file or change config to point to it
         # A real update would involve downloading, verifying, merging etc.
         if os.path.exists(args.db_path):
              # Simplistic: Overwrite the current one
              # Be careful with permissions here!
              try:
                   shutil.copyfile(args.db_path, CONFIG["signature_db"])
                   logging.info(f"Signature database updated from {args.db_path}")
                   print("Signature database updated.")
              except Exception as e:
                   logging.error(f"Failed to update signature database: {e}")
                   print(f"Error updating database: {e}")
         else:
              print(f"Error: New database file not found: {args.db_path}")
              logging.error(f"Update failed: New DB file not found at {args.db_path}")