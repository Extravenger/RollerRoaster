# RollerRoaster 🎢

RollerRoaster is a tool designed for performing enumeration and exploitation of Kerberoasting attack in Active Directory environments.</br>
Developed with security in mind. It incorporates features such as controlled delays between Service Principal Name (SPN) requests to avoid detection and Event Tracing for Windows (ETW) patch to enhance stealth.

## 🔧 Features

- 🔐 Identify accounts with Service Principal Names (SPNs)</br>
- ⏳ Optional Delay between SPN Hashes Extraction requests</br>
- 🛡️ Optional ETW Patch prior to Tickets Extraction</br>
- 💥 SPN Hashes in Hashcat Output Format

## 📘 Usage

Simply download the binary or build manually, and execute:

- `.\RollerRoaster.exe /domain:north.sevenkingdoms.local /list`

## 🎥 Demo

https://github.com/user-attachments/assets/f602d1b2-42a6-4475-9798-e066eacedd74

## ⚠️ Disclaimer

RollerRoaster is intended for authorized security testing and educational purposes only.</br>
Unauthorized use against systems you do not own or have permission to test is illegal and unethical. Use responsibly.
