# RollerRoaster 🎢

[<img src=](https://camo.githubusercontent.com/bdddb867fc7eae72bcd4bc5ed892b1ecfe73ada505b188879e073a11aea35f7d/68747470733a2f2f696d672e736869656c64732e696f2f6769746875622f6c6963656e73652f6c79346b2f43657274697079)

RollerRoaster is a tool designed for performing enumeration and exploitation of Kerberoasting attack in Active Directory environments.</br>
Developed with security in mind. It incorporates features such as controlled delays between Service Principal Name (SPN) requests to avoid detection and Event Tracing for Windows (ETW) bypass to enhance stealth.

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
