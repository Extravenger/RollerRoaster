# RollerRoaster 🎢

![GitHub License](https://img.shields.io/github/license/Extravenger/RollerRoaster)

RollerRoaster is a tool designed for performing enumeration and exploitation of Kerberoasting attack in Active Directory environments.</br>
Developed with stealth in mind, it incorporates features such as controlled delays between Service Principal Name (SPN) requests to evade detection, and an Event Tracing for Windows (ETW) patch to enhance stealth.

## 🔧 Features

- 🔐 Identify accounts with Service Principal Names (SPNs)</br>
- ⏳ Optional delay between SPN requests</br>
- 🛡️ Optional ETW patch prior to SPN requests</br>
- 🔑 SPN Hashes in hashcat output format for offline cracking

## 📘 Usage



- `.\RollerRoaster.exe /domain:north.sevenkingdoms.local /list`

## 🎥 Demo

https://github.com/user-attachments/assets/4e00e25d-a812-4f75-a5b4-006679347f9f

## ⚠️ Disclaimer

RollerRoaster is intended for authorized security testing and educational purposes only.</br>
Unauthorized use against systems you do not own or have permission to test is illegal and unethical. Use responsibly.
