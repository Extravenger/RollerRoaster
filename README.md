# RollerRoaster 🎢

RollerRoaster is a tool designed for performing enumeration and exploitation of Kerberoasting attack in Active Directory environments.</br>
Built with security in mind. It incorporates features such as controlled delays between Service Principal Name (SPN) requests to avoid detection and Event Tracing for Windows (ETW) bypass to enhance stealth.

## 🔧 Features

**Service Account List**: Identify accounts with Service Principal Names (SPNs).</br>
**Optional Delay between SPN Hashes Extraction**: Delay the process of SPN extraction to avoid AV/EDR.</br>
**Optional ETW bypass prior tickets extraction**: Patch ETW before tickets dumping.</br>
**SPN Hashes in Hashcat Output Format**: Retrieves encrypted SPN ticket's in hashcat format for offline cracking.

## 📘 Usage

Simply download the binary or build manually, and execute:

- `.\RollerRoaster.exe /domain:north.sevenkingdoms.local /list`

## 🎥 Demo

https://github.com/user-attachments/assets/f602d1b2-42a6-4475-9798-e066eacedd74

## ⚠️ Disclaimer

RollerRoaster is intended for authorized security testing and educational purposes only.</br>
Unauthorized use against systems you do not own or have permission to test is illegal and unethical. Use responsibly.
