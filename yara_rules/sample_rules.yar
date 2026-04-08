rule Suspicious_Binary_Strings
{
    meta:
        description = "Detects suspicious strings in binary samples"
        author = "SOAR Team"
        date = "2026-04-08"
        severity = "high"
        family = "Suspicious.Binary"
        tags = "binary suspicious behavioral"
    
    strings:
        $domain = /[a-zA-Z0-9]+\.(com|net|org|io|xyz)/ nocase
        $ip = /(\d{1,3}\.){3}\d{1,3}/
        $url = /https?:\/\/[a-zA-Z0-9\-._~:\/\?#\[\]@!$&'()*+,;=]+/ nocase
        $registry = /HKEY_[A-Z_]+/ nocase
        $file_path = /[A-Z]:\\[a-zA-Z0-9\\._\-]+\.exe/ nocase
    
    condition:
        1 of them
}

rule Suspicious_Network_Communications
{
    meta:
        description = "Detects suspicious network communication patterns"
        author = "SOAR Team"
        date = "2026-04-08"
        severity = "high"
        family = "Suspicious.Network"
        tags = "network c2 behavioral"
    
    strings:
        $c2_behavior = /cmd|powershell|curl|wget/ nocase
        $encoded = /base64|encoded|encrypt/ nocase
        $socket = /socket|WSASocket|connect/ nocase
        $winsock = "ws2_32" nocase
        $wininet = "wininet" nocase
    
    condition:
        2 of them
}

rule Suspicious_File_Operations
{
    meta:
        description = "Detects suspicious file operation patterns"
        author = "SOAR Team"
        date = "2026-04-08"
        severity = "medium"
        family = "Suspicious.FileOps"
        tags = "file dropper behavioral"
    
    strings:
        $file_op = /CreateFileA|WriteFile|CreateProcessA|CreateProcessW/ nocase
        $temp = /TEMP|Temp|temp/ nocase
        $system32 = /System32|system32|Syswow64/ nocase
        $registry_op = /RegOpenKeyEx|RegSetValueEx|RegCreateKey/ nocase
    
    condition:
        2 of them
}

rule Registry_Persistence
{
    meta:
        description = "Detects registry-based persistence techniques"
        author = "SOAR Team"
        date = "2026-04-08"
        severity = "high"
        family = "Persistence.Registry"
        tags = "registry persistence defense-evasion"
    
    strings:
        $persistence_path = /Software\\Microsoft\\Windows\\CurrentVersion\\Run/i
        $startup = /Startup/ nocase
        $winlogon = /Winlogon/ nocase
        $services = /Services/ nocase
        $shell_exec = /ShellExecute/ nocase
    
    condition:
        2 of them
}
