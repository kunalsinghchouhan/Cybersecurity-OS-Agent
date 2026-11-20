import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

def show_menu():
    print("\n======================")
    print(" CYBERSECURITY OS AGENT")
    print("======================")
    print("1. Integrated Monitoring")
    print("2. Network Monitoring Snapshot")
    print("3. Exit")

try:
    while True:
        show_menu()
        choice = input("Select an option: ").strip()

        if choice == "1":
            subprocess.run(
                [sys.executable, str(BASE_DIR / "monitor_engine.py")],
                cwd=BASE_DIR
            )

        elif choice == "2":
            subprocess.run(
                [sys.executable, str(BASE_DIR / "network_monitor.py")],
                cwd=BASE_DIR
            )

        elif choice == "3":
            print("Cybersecurity OS Agent stopped.")
            break

        else:
            print("Invalid option. Please try again.")

except KeyboardInterrupt:
    print("\nCybersecurity OS Agent stopped safely.")