#!/usr/bin/env python3

import os
import hashlib
import shutil
import json
import argparse
import logging
import time
import csv
import sys
from pathlib import Path

# --- Configuration ---
CONFIG = {
    "signature_db": "signatures.db",  # Output file for processed signatures
    "quarantine_dir": "quarantine",
    "quarantine_manifest": "quarantine/manifest.json",
    "log_file": "scan.log",
    "default_action": "report",  # report, quarantine, remove
    "heuristic_level": 1,       # 0: off, 1: basic (name/size), 2: content (entropy/strings)
    "max_file_size_heuristic": 50 * 1024 * 1024 # Skip heuristics on huge files
}

# --- Logging Setup ---
# Check if logging is already configured (e.g., if imported)
if not logging.getLogger().hasHandlers():
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s [%(levelname)s] %(message)s',
                        handlers=[
                            logging.FileHandler(CONFIG["log_file"]),
                            logging.StreamHandler() # Also print to console
                        ])

# --- MalwareBazaar CSV Processing ---
# --- MalwareBazaar CSV Processing ---
def preprocess_bazaar_csv(input_csv_path, output_db_path):
    """
    Reads a MalwareBazaar CSV export, extracts SHA256 hashes and names,
    and writes them to a simple hash,name format file (signatures.db).
    Handles quoted fields from the CSV.
    """
    processed_count = 0
    hashes_written = set()

    # Define column indices based on the provided header:
    # "first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter",
    # "file_name","file_type_guess","mime_type","signature","clamav", ...
    SHA256_IDX = 1
    SIGNATURE_IDX = 8
    CLAMAV_IDX = 9
    FILE_TYPE_IDX = 6

    try:
        print(f"Processing MalwareBazaar CSV: {input_csv_path}")
        logging.info(f"Starting processing of MalwareBazaar CSV: {input_csv_path}")
        with open(input_csv_path, 'r', newline='', encoding='utf-8') as infile, \
             open(output_db_path, 'w', encoding='utf-8') as outfile:

            # Use csv.reader which handles standard CSV quoting/escaping
            reader = csv.reader(infile)
            header_skipped = False

            for row_num, row in enumerate(reader):
                # Skip comment lines at the beginning
                # Check if the row is non-empty before accessing row[0]
                if row and row[0].startswith('#'):
                    logging.debug(f"Skipping comment line {row_num+1}")
                    continue

                # Skip the header row (assuming it's the first non-comment line)
                if not header_skipped:
                     # Basic check if it looks like the header we expect
                     if row and 'sha256_hash' in row and 'reporter' in row:
                        logging.info(f"Skipping detected header row: {row}")
                        header_skipped = True
                        continue
                     elif row: # If it's the first line but doesn't look like header, log warning maybe?
                        logging.warning(f"First non-comment row doesn't look like expected header: {row}. Attempting to process.")
                        header_skipped = True # Still assume header is passed or missing
                     else: # Skip empty rows
                        continue


                # --- Process data rows ---
                required_len = max(SHA256_IDX, SIGNATURE_IDX, CLAMAV_IDX, FILE_TYPE_IDX) + 1
                if len(row) >= required_len:
                    # Extract field - csv.reader should have handled quotes already if standard CSV
                    # But we add .strip() for whitespace and .strip('"') just in case of non-standard quoting
                    sha256_hash = row[SHA256_IDX].strip().strip('"') # <-- *** THE FIX ***

                    # Basic validation of hash
                    # Use lower() for consistent checking
                    is_valid_hash = (len(sha256_hash) == 64 and all(c in '0123456789abcdef' for c in sha256_hash.lower()))

                    if is_valid_hash:
                        # Extract other fields, stripping potential quotes too
                        signature = row[SIGNATURE_IDX].strip().strip('"')
                        clamav_name = row[CLAMAV_IDX].strip().strip('"')
                        file_type = row[FILE_TYPE_IDX].strip().strip('"')

                        # Determine the best available name
                        malware_name = "Unknown"
                        if signature and signature.lower() != 'n/a':
                            malware_name = signature
                        elif clamav_name and clamav_name.lower() != 'n/a':
                            malware_name = clamav_name
                        elif file_type and file_type.lower() != 'n/a':
                             malware_name = f"Malware_{file_type}"
                        else:
                             malware_name = "Malware_Generic"

                        # Clean the name
                        malware_name = malware_name.replace(',', '_').replace('"', '').replace("'", "").strip()
                        if not malware_name:
                            malware_name = "Malware_Generic_Cleaned"

                        # Avoid duplicate hash entries (use lowercase for comparison)
                        hash_lower = sha256_hash.lower()
                        if hash_lower not in hashes_written:
                            # Write lowercase hash to the db file for consistency
                            outfile.write(f"{hash_lower},{malware_name}\n")
                            hashes_written.add(hash_lower)
                            processed_count += 1
                            if processed_count % 50000 == 0: # Log progress less often
                                 logging.info(f"Processed {processed_count} unique entries...")
                    else:
                         # Only log invalid format warnings occasionally to avoid flooding
                         if (row_num + 1) % 1000 == 0 :
                             logging.warning(f"Skipping row {row_num+1} due to invalid SHA256 format after stripping: '{sha256_hash[:15]}...'")
                else:
                     # Log short rows occasionally
                     if (row_num + 1) % 1000 == 0:
                        logging.warning(f"Skipping row {row_num+1}: Too few columns ({len(row)} found, needed >= {required_len})")

        print("-" * 30)
        print(f"Successfully created signature file: {output_db_path}")
        print(f"Total unique signatures written: {processed_count}")
        print("-" * 30)
        logging.info(f"Finished processing. Created {output_db_path} with {processed_count} unique signatures.")
        return True

    except FileNotFoundError:
        print(f"Error: Input CSV file not found at '{input_csv_path}'", file=sys.stderr)
        logging.error(f"Input CSV file not found at '{input_csv_path}'")
        return False
    except Exception as e:
        print(f"An error occurred during CSV processing: {e}", file=sys.stderr)
        logging.exception("An error occurred during CSV processing")
        return False
# --- Signature Handling ---
def load_signatures(db_path):
    signatures = {}
    try:
        with open(db_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and ',' in line:
                    try:
                        sha256, malware_name = line.split(',', 1)
                        # Basic validation on load as well
                        if len(sha256) == 64 and all(c in '0123456789abcdefABCDEF' for c in sha256.lower()):
                             signatures[sha256.lower()] = malware_name # Store hash in lowercase for case-insensitive matching
                        else:
                             logging.warning(f"Ignoring invalid hash format in signature db: {sha256[:10]}...")
                    except ValueError:
                        logging.warning(f"Ignoring malformed line in signature db: {line[:50]}...")
        logging.info(f"Loaded {len(signatures)} signatures from {db_path}")
    except FileNotFoundError:
        logging.warning(f"Signature file {db_path} not found. No signature scanning possible.")
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
        file_hash = hasher.hexdigest().lower() # Compare lowercase

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
    p_file_path = Path(file_path) # Use Path object
    file_name = p_file_path.name
    # Get primary extension robustly
    file_ext = ''.join(p_file_path.suffixes).lower() # Handles .tar.gz -> .tar.gz

    try:
        file_size = p_file_path.stat().st_size

        # Rule: Suspicious double extensions involving executables
        suspicious_combos = ['.exe.', '.scr.', '.com.', '.bat.', '.vbs.']
        if file_name.count('.') >= 2 and any(combo in file_name.lower() for combo in suspicious_combos):
             suspicion_score += 2
             reasons.append("Double Extension")

        # Rule: Disguised executable extensions
        exec_exts = ['.exe', '.scr', '.bat', '.vbs', '.ps1', '.com', '.cmd']
        doc_like = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.jpg', '.jpeg', '.png', '.gif', '.txt', '.rtf']
        # Check if the *final* extension is executable but *looks* like a document earlier
        if file_ext in exec_exts:
            stem = p_file_path.stem # Filename without final extension
            if any(doc_ext in stem.lower() for doc_ext in doc_like):
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

    # Threshold determination (can be tuned)
    if suspicion_score > 1: # Example threshold
         return True, f"Heuristic Score: {suspicion_score} ({', '.join(reasons)})"

    return False, None # Not suspicious


# --- Quarantine Handling ---
def load_quarantine_manifest():
    manifest_path = CONFIG["quarantine_manifest"]
    try:
        if os.path.exists(manifest_path):
            with open(manifest_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {}
    except json.JSONDecodeError:
        logging.error(f"Error decoding quarantine manifest {manifest_path}. Returning empty.")
        # Optionally backup the corrupt file
        # shutil.copy(manifest_path, f"{manifest_path}.corrupt_{int(time.time())}")
        return {}
    except Exception as e:
        logging.error(f"Error loading quarantine manifest {manifest_path}: {e}")
        return {}

def save_quarantine_manifest(manifest):
    manifest_path = CONFIG["quarantine_manifest"]
    quarantine_dir = os.path.dirname(manifest_path)
    try:
        os.makedirs(quarantine_dir, exist_ok=True)
        with open(manifest_path, 'w', encoding='utf-8') as f:
            json.dump(manifest, f, indent=4)
        return True
    except Exception as e:
        logging.error(f"Error saving quarantine manifest {manifest_path}: {e}")
        return False

def quarantine_file(file_path, reason):
    logging.info(f"Attempting quarantine for {file_path} due to: {reason}")
    if not os.path.exists(file_path):
         logging.error(f"File not found for quarantine: {file_path}")
         return False

    quarantine_dir = CONFIG["quarantine_dir"]
    try:
        os.makedirs(quarantine_dir, exist_ok=True)
        manifest = load_quarantine_manifest()

        # Generate unique ID based on timestamp and part of hash for robustness
        ts_part = str(int(time.time() * 1000))
        # Use file name hash part if possible, fallback if hashing fails
        try:
             hash_part = hashlib.sha1(file_path.encode()).hexdigest()[:8]
        except Exception:
             hash_part = "xxxx"
        quarantine_id = f"{ts_part}-{hash_part}"

        quarantined_filename = f"{quarantine_id}.quar"
        quarantined_filepath = os.path.join(quarantine_dir, quarantined_filename)

        # --- Simple Obfuscation (Optional - XOR with a fixed key) ---
        # try:
        #     key = 0xAA # Example simple key
        #     with open(file_path, 'rb') as f_in, open(quarantined_filepath, 'wb') as f_out:
        #         while True:
        #             chunk = f_in.read(4096)
        #             if not chunk: break
        #             encoded_chunk = bytes([b ^ key for b in chunk])
        #             f_out.write(encoded_chunk)
        #     os.remove(file_path) # Remove original only after successful write+encode
        #     logging.debug(f"File XOR encoded and moved to {quarantined_filepath}")
        # except Exception as e:
        #      logging.error(f"Failed to XOR encode/move file {file_path}: {e}")
        #      # Cleanup partially written file if it exists
        #      if os.path.exists(quarantined_filepath):
        #          os.remove(quarantined_filepath)
        #      return False
        # --- End Optional Obfuscation ---

        # --- Direct Move (Simpler) ---
        try:
            shutil.move(file_path, quarantined_filepath) # Use move to take it out of circulation
            logging.debug(f"File moved to {quarantined_filepath}")
        except Exception as e:
            logging.error(f"Failed to move file {file_path} to quarantine: {e}")
            return False
        # --- End Direct Move ---

        manifest[quarantine_id] = {
            "original_path": os.path.abspath(file_path),
            "reason": reason,
            "timestamp": time.time(),
            "quarantined_filename": quarantined_filename
        }
        if save_quarantine_manifest(manifest):
            logging.info(f"File quarantined successfully as {quarantined_filename} (ID: {quarantine_id})")
            return True
        else:
            # Attempt to roll back the move if saving manifest failed
            logging.error("Failed to save quarantine manifest after moving file. Attempting rollback.")
            try:
                shutil.move(quarantined_filepath, file_path)
                logging.info(f"Rollback successful: Moved {quarantined_filename} back to {file_path}")
            except Exception as rollback_e:
                logging.critical(f"Rollback failed! File is quarantined ({quarantined_filepath}) but not recorded in manifest: {rollback_e}")
            return False

    except Exception as e:
        logging.error(f"Unexpected error during quarantine of {file_path}: {e}")
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
        # Consider removing the dangling manifest entry
        # del manifest[quarantine_id]
        # save_quarantine_manifest(manifest)
        return

    try:
        os.makedirs(original_dir, exist_ok=True)

        # --- Add XOR decoding here if encoding was used during quarantine ---
        # try:
        #     key = 0xAA # Must be the same key used for encoding
        #     with open(quarantined_filepath, 'rb') as f_in, open(original_path, 'wb') as f_out:
        #         while True:
        #             chunk = f_in.read(4096)
        #             if not chunk: break
        #             decoded_chunk = bytes([b ^ key for b in chunk])
        #             f_out.write(decoded_chunk)
        #     os.remove(quarantined_filepath) # Remove encoded file after successful write
        #     logging.debug(f"File XOR decoded and restored to {original_path}")
        # except Exception as e:
        #     logging.error(f"Failed to XOR decode/restore file {quarantined_filepath}: {e}")
        #     # Don't proceed if decoding failed
        #     return
        # --- End Optional Decoding ---

        # --- Direct Move (Simpler) ---
        try:
            shutil.move(quarantined_filepath, original_path)
            logging.debug(f"File moved from quarantine to {original_path}")
        except Exception as e:
            logging.error(f"Failed to move file {quarantined_filepath} back to {original_path}: {e}")
            # Don't update manifest if move failed
            return
        # --- End Direct Move ---

        # Update manifest only after successful restore
        del manifest[quarantine_id]
        if save_quarantine_manifest(manifest):
            logging.info(f"Restored {item['quarantined_filename']} to {original_path}")
            print(f"File restored successfully to: {original_path}")
        else:
            logging.error("Failed to save manifest after successful restore. Manifest may be inconsistent.")
            print("Error: File restored, but failed to update quarantine records.")

    except Exception as e:
        print(f"Error restoring file: {e}")
        logging.error(f"Failed to restore {quarantine_id} from {quarantined_filepath} to {original_path}: {e}")

def list_quarantine():
     manifest = load_quarantine_manifest()
     if not manifest:
         print("Quarantine is empty.")
         return
     print("\nQuarantined Items:")
     print("-" * 60)
     for qid, item in manifest.items():
         ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(item.get('timestamp', 0)))
         print(f"ID          : {qid}")
         print(f"Original Path: {item.get('original_path', 'N/A')}")
         print(f"Reason      : {item.get('reason', 'N/A')}")
         print(f"Date        : {ts}")
         print(f"Stored As   : {item.get('quarantined_filename', 'N/A')}")
         print("-" * 60)

def delete_quarantined_file(quarantine_id):
    manifest = load_quarantine_manifest()
    if quarantine_id not in manifest:
        print(f"Error: Quarantine ID {quarantine_id} not found.")
        logging.warning(f"Attempt to delete non-existent quarantine ID: {quarantine_id}")
        return

    item = manifest[quarantine_id]
    quarantined_filepath = os.path.join(CONFIG["quarantine_dir"], item["quarantined_filename"])

    deleted_file = False
    if os.path.exists(quarantined_filepath):
        try:
            os.remove(quarantined_filepath)
            logging.info(f"Deleted quarantined file: {quarantined_filepath}")
            deleted_file = True
        except OSError as e:
            print(f"Error deleting file {quarantined_filepath}: {e}")
            logging.error(f"Failed to delete file {quarantined_filepath} for ID {quarantine_id}: {e}")
            # Don't proceed to delete manifest entry if file deletion failed
            return
    else:
        logging.warning(f"Quarantined file not found for deletion, but manifest entry exists: {quarantined_filepath}")
        # Allow deleting the manifest entry even if file is missing
        deleted_file = True

    if deleted_file:
        try:
            del manifest[quarantine_id]
            if save_quarantine_manifest(manifest):
                logging.info(f"Removed manifest entry for quarantine ID: {quarantine_id}")
                print(f"Successfully deleted quarantined item (ID: {quarantine_id}).")
            else:
                 logging.error("Failed to save manifest after deleting quarantine entry.")
                 print("Error: Deleted file (or file was missing), but failed to update quarantine records.")
        except Exception as e:
             logging.error(f"Error removing manifest entry for {quarantine_id}: {e}")
             print("Error: Failed to update quarantine records after file deletion.")


# --- Removal Handling ---
def remove_file(file_path, reason):
    logging.warning(f"Attempting to remove infected file: {file_path} (Reason: {reason})")
    try:
        os.remove(file_path)
        logging.info(f"File removed successfully: {file_path}")
        print(f"Removed file: {file_path}")
        return True
    except FileNotFoundError:
         logging.error(f"File not found for removal: {file_path}")
         print(f"Error: File not found for removal: {file_path}")
         return False
    except OSError as e:
        logging.error(f"Failed to remove file {file_path}: {e}")
        print(f"Error removing file {file_path}: {e}")
        return False
    except Exception as e:
        logging.error(f"Unexpected error removing file {file_path}: {e}")
        print(f"Unexpected error removing file {file_path}: {e}")
        return False

# --- Scanner Engine ---
def scan_path(target_path_str, signatures, action):
    scan_summary = {"files_scanned": 0, "threats_found": 0, "actions_taken": 0, "errors": 0}
    target_path = Path(target_path_str) # Use pathlib

    if not target_path.exists():
        logging.error(f"Path does not exist: {target_path}")
        print(f"Error: Path does not exist: {target_path}")
        return scan_summary

    items_to_scan = []
    if target_path.is_file():
        items_to_scan.append(target_path)
    elif target_path.is_dir():
        logging.info(f"Recursively scanning directory: {target_path}")
        # Use rglob for simpler recursive iteration
        try:
            # Scan files only, excluding directories and handling potential permission errors during iteration
            items_to_scan = [item for item in target_path.rglob('*') if item.is_file()]
        except PermissionError:
             logging.error(f"Permission denied accessing parts of directory: {target_path}. Some files may be skipped.")
             print(f"Warning: Permission denied accessing parts of directory: {target_path}")
             # Fallback to os.walk which might handle some errors better per directory
             items_to_scan = []
             for root, _, files in os.walk(target_path, onerror=lambda e: logging.warning(f"Error walking directory {e.filename}: {e.strerror}")):
                  for file in files:
                       items_to_scan.append(Path(root) / file)
        except Exception as e:
             logging.error(f"Error listing files in {target_path}: {e}")
             print(f"Error listing files in {target_path}: {e}")
             return scan_summary
    else:
         logging.warning(f"Target path is not a file or directory: {target_path}")
         print(f"Warning: Target path is not a file or directory: {target_path}")
         return scan_summary

    logging.info(f"Starting scan on {len(items_to_scan)} files found under {target_path_str}...")
    print(f"Scanning {len(items_to_scan)} files found under {target_path_str}...")

    for file_path in items_to_scan:
        scan_summary["files_scanned"] += 1
        file_path_str = str(file_path) # Convert back for functions expecting strings

        # Basic check if it's still a file (could have changed during scan)
        if not file_path.is_file():
             logging.debug(f"Skipping non-file item: {file_path_str}")
             continue

        logging.debug(f"Scanning: {file_path_str}")

        detected = False
        detection_type = "N/A"
        malware_name = "N/A"
        detection_details = ""

        # 1. Check Signature
        try:
            sig_detected, sig_name, file_hash = check_signature(file_path_str, signatures)
            if sig_detected:
                detected = True
                detection_type = "Signature"
                malware_name = sig_name
                detection_details = file_hash
                logging.warning(f"SIGNATURE DETECTED: {file_path_str} -> {malware_name} ({file_hash})")
                print(f"[!] SIGNATURE DETECTED: {file_path_str} -> {malware_name}")
        except Exception as e:
            logging.error(f"Error during signature check for {file_path_str}: {e}")
            scan_summary["errors"] += 1
            continue # Skip heuristics and actions if signature check failed critically

        # 2. Check Heuristics (if no signature match or configured always)
        if not detected and CONFIG["heuristic_level"] > 0:
             try:
                 # Avoid checking huge files with heuristics unless level is very high?
                 if file_path.stat().st_size <= CONFIG["max_file_size_heuristic"]:
                     heur_detected, heur_reason = check_heuristics(file_path_str)
                     if heur_detected:
                         detected = True
                         detection_type = "Heuristic"
                         malware_name = heur_reason
                         detection_details = heur_reason
                         logging.warning(f"HEURISTIC DETECTED: {file_path_str} -> {malware_name}")
                         print(f"[!] HEURISTIC DETECTED: {file_path_str} -> {malware_name}")
                 else:
                     logging.debug(f"Skipping heuristic scan for large file: {file_path_str}")
             except OSError as e:
                  logging.warning(f"Cannot get size for heuristic check: {file_path_str}: {e}")
                  scan_summary["errors"] += 1
             except Exception as e:
                  logging.error(f"Error during heuristic check for {file_path_str}: {e}")
                  scan_summary["errors"] += 1
                  # Decide whether to continue to action based on heuristic error

        # 3. Take Action
        if detected:
            scan_summary["threats_found"] += 1
            action_taken_successfully = False
            full_reason = f"{detection_type}: {malware_name}"

            if action == "quarantine":
                if quarantine_file(file_path_str, full_reason):
                    action_taken_successfully = True
            elif action == "remove":
                if remove_file(file_path_str, full_reason):
                     action_taken_successfully = True
            elif action == "report":
                logging.info(f"Threat reported (no action taken): {file_path_str}")
                action_taken_successfully = True # Reporting is considered a successful outcome

            if action_taken_successfully and action != "report":
                 scan_summary["actions_taken"] += 1
            elif not action_taken_successfully and action != "report":
                 logging.error(f"Failed to perform action '{action}' on {file_path_str}")
                 print(f"[!] FAILED ACTION '{action}' on: {file_path_str}")
                 scan_summary["errors"] += 1
        # else: # Optional: Log clean files
             # logging.debug(f"Clean: {file_path_str}")

    logging.info("Scan Complete.")
    logging.info(f"Summary: Files Scanned: {scan_summary['files_scanned']}, Threats Found: {scan_summary['threats_found']}, Actions Taken: {scan_summary['actions_taken']}, Errors: {scan_summary['errors']}")
    print("\n--- Scan Summary ---")
    print(f"Files Scanned   : {scan_summary['files_scanned']}")
    print(f"Threats Found   : {scan_summary['threats_found']}")
    print(f"Actions Taken   : {scan_summary['actions_taken']}")
    print(f"Scan Errors     : {scan_summary['errors']}")
    print("--------------------")
    return scan_summary


# --- Main CLI ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Lightweight Antivirus Scanner (app2.py)",
        formatter_class=argparse.RawTextHelpFormatter # Preserve newline formatting in help
        )
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # --- Scan command ---
    parser_scan = subparsers.add_parser("scan", help="Scan a file or directory for malware.")
    parser_scan.add_argument("path", help="File or directory path to scan.")
    parser_scan.add_argument("--action", choices=["report", "quarantine", "remove"],
                             default=CONFIG["default_action"],
                             help=f"Action on detection (default: {CONFIG['default_action']}).\n"
                                  "  report: Log and print detection only.\n"
                                  "  quarantine: Move detected file to quarantine directory.\n"
                                  "  remove: Permanently delete detected file (USE WITH CAUTION!).")
    # Add more options like --recursive (though default is now recursive), --heuristic-level etc.

    # --- Quarantine management commands ---
    parser_q = subparsers.add_parser("quarantine", help="Manage quarantined files.")
    q_subparsers = parser_q.add_subparsers(dest="q_command", required=True, help="Quarantine actions")
    q_subparsers.add_parser("list", help="List all items currently in quarantine.")
    parser_q_restore = q_subparsers.add_parser("restore", help="Restore a specific item from quarantine by its ID.")
    parser_q_restore.add_argument("id", help="Quarantine ID of the item to restore (from 'quarantine list').")
    parser_q_delete = q_subparsers.add_parser("delete", help="Permanently delete a specific item from quarantine.")
    parser_q_delete.add_argument("id", help="Quarantine ID of the item to delete permanently.")

    # --- Update command ---
    parser_update = subparsers.add_parser(
        "update",
        help=f"Process a MalwareBazaar CSV file to create/update the signature database ({CONFIG['signature_db']})."
        )
    parser_update.add_argument(
        "csv_path",
        help="Path to the MalwareBazaar CSV export file (e.g., full.csv) to process."
        )

    args = parser.parse_args()

    # --- Execute Commands ---
    if args.command == "scan":
        print(f"Loading signatures from: {CONFIG['signature_db']}")
        signatures = load_signatures(CONFIG["signature_db"])
        if not signatures:
             print("Warning: No signatures loaded. Only heuristic scanning will be performed.")
        scan_path(args.path, signatures, args.action)

    elif args.command == "quarantine":
        if args.q_command == "list":
             list_quarantine()
        elif args.q_command == "restore":
             restore_quarantined_file(args.id)
        elif args.q_command == "delete":
             delete_quarantined_file(args.id)

    elif args.command == "update":
         print(f"Attempting to update signatures from CSV: {args.csv_path}")
         print(f"Output signature file will be: {CONFIG['signature_db']}")
         if preprocess_bazaar_csv(args.csv_path, CONFIG["signature_db"]):
             print("Signature database update process completed.")
         else:
             print("Signature database update process failed. Check logs for details.")

    print("\nOperation finished.")