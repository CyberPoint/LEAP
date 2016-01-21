 ▄█          ▄████████    ▄████████    ▄███████▄         ▄█   ▄█▄  ▄█      ███     
███         ███    ███   ███    ███   ███    ███        ███ ▄███▀ ███  ▀█████████▄ 
███         ███    █▀    ███    ███   ███    ███        ███▐██▀   ███▌    ▀███▀▀██ 
███        ▄███▄▄▄       ███    ███   ███    ███       ▄█████▀    ███▌     ███   ▀ 
███       ▀▀███▀▀▀     ▀███████████ ▀█████████▀       ▀▀█████▄    ███▌     ███     
███         ███    █▄    ███    ███   ███               ███▐██▄   ███      ███     
███▌    ▄   ███    ███   ███    ███   ███               ███ ▀███▄ ███      ███     
█████▄▄██   ██████████   ███    █▀   ▄████▀             ███   ▀█▀ █▀      ▄████▀   
▀                                                       ▀                          


## [L]ocal [E]levation [A]ttack [P]latform

LEAP is a toolkit designed to aid in quickly gaining local elevated privileges  within in Microsoft Windows 7 - 10 environments against insecure applications through DLL Hijacking/Binary Planting/SideLoading methods.

The kit currently has three different modules to target three different type of LPE attack methods:

[1] DragonPunch -> Race Condition Binary Planting Attacks
[2] PathPoison -> Malicious User PATH Hijack + Brute Force Planting
[3] WeakLinks -> Abuse Insecre Directory/File Permissions/CodeSigning 



## DragonPunch
This script will exploit weaknesses in race conditions in which a privileged application such as an SYSTEM level installer or service executes or loads a temporary binary from an insecure directory.  This behavior is often performed by update systems which will download and execute an temporary binary before deleting the file.

This script can be made to monitor a directory and its subdirectories for modification and then plant a malicious file in the directory before the targeted application can supply their own application or replacing the legitimate binary with the malicious file instead.

This ultimately results in potentially malicious code being executed in the context of the targeted application, ideally Local SYSTEM; however any application can be targeted, allowing the toolkit to be used for persistence or local privilege elevation attacks equally.


## PathPoison
This is the simplest tool within LEAP and allows a local attacker to abuse any application in which searching for a missing DLL reaches the user’s PATH variable content and does not appear anywhere earlier in the DLLSearchOrder chain.

This script will take a user defined folder and place it in the beginning of the current user’s PATH variable in order to beat any existing PATH variables defined by previous application installations.

Furthermore, the script will also populate the specified PATH folder with a list of commonly requested and known DLLs that are commonly abused by hijacking attacks.  This list can be directly modified in order to accommodate custom or newly discovered hijackable DLLs for different targets.

### DLL Hijack List
The list of the DLLs that PathPoison will generate in the user’s specified PATH folder are as follows:
* VERSION.DLL
* imageres.dll
* msTracer.dll
* msfte.dll
* bcrypt.dll
* urlmon.dll
* SensApi.dll
* dbghelp.dll
* dbgcore.DLL
* USERENV.DLL
* MSIMG32.DLL
* RASAPI32.DLL
* dwrite.dll
* wow64log.dll
* tv_x64.dll
* OLEACC.dll
* OLEACCRC.dll
* DUI70.dll
* dwmapi.dll
* WINSTA.dll
* msvcp110.dll
* iertutil.dll
* PROPSYS.dll
* SspiCli.dll
* WINMM.dll
* WTSAPI32.dll
* Bcp47Langs.dll
* wincorlib.DLL

### Substitution Dropped DLLs
A user can modify the script manually to include support for additional DLLs.

### Subfolder Hijack List
In addition to the PATH folder generated, PoisonPath will also make the following subfolders in order to attempt to hijack DLLs being loaded using malformed paths.  This can occur due to poorly written code attempting to parse variables or truncate strings improperly, resulting in DLLs being loaded from invalid (non-exploitable) or erroneous (possibly exploitable) locations.
* %PATH%\Windows\
* %PATH%\C\Windows\
* %PATH%\Windows\System32\
* %PATH%\C\Windows\System32\
* %PATH%\System32\





## WeakLinks
This script will attempt to discover insecure folders and files that can be targeted for DLL Hijacking or Binary Planting attacks.

### Security Checks & Search Criteria
WeakLinks can be used to identify insecure files using several methods or prerequisites:

* It can identify files that contain specified strings in their FileInfo metadata.  This is ideal for identifying files that belong to a specific vendor or product that can be potentially exploited.

* It will identify files that have weak or no Authenticode signatures.  These files may be susceptible to being overwritten and could potentially aid a malicious attacker or user into gaining elevated privileges.

* It will identify files with weak ACL permissions that could potentially allow a specified user account the ability to overwrite the insecure file with a trojanized file and gain elevated permissions.

## LEAPInject.DLL
LEAP also comes with example source of LEAPInject.DLL.  This DLL can be compiled with Visual Studio in order to have a DLL to visually indicate a successful injection.

### LEAPInject DLL Behavior
LEAPInject.dll will write to the current %TEMP% folder a log file called DLLHooks.txt containing the following information:
* Process Name that loaded the DLL
* Process’ current Integrity Level
* Current Username / Account the process is being executed as
* Name of the DLL loaded 
* Date/Time Stamp

LEAPInject.dll will also display a MessageBox using Windows API in order to visually indicate that a successful injection has occured.

### Substitution DLLs
A user may replace LEAPInject.dll at any point with a DLL file of their own choosing.  This allows the user to execute their own custom code or payloads as they see fit.



## Getting Started & Using LEAP
Each component of LEAP has their own specific instructions for operation, for more details see their own help pages.





