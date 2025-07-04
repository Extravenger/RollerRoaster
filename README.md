# RollerRoaster 🎢

RollerRoaster is a powerful and user-friendly tool designed for performing Kerberoasting attacks in Active Directory environments.

## Features

**Service Account List**: Identify accounts with Service Principal Names (SPNs).  
**Optional Delay between SPN Hashes Extraction**: Delay the process of SPN extraction to avoid AV/EDR.  
**Optional ETW bypass prior tickets extraction**: Patch ETW before tickets dumping. 
**SPN Hashes in Hashcat Output Format**: Retrieves encrypted SPN ticket's in hashcat format for offline cracking.

## Usage

Simply download the binary from the Releases page, and execute:

- `.\RollerRoaster.exe /domain:north.sevenkingdoms.local /list`

## Demo

https://github.com/user-attachments/assets/4752355f-3962-44a3-80cd-b5e6ad318ace

## Disclaimer
RollerRoaster is intended for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have permission to test is illegal and unethical. Use responsibly.
