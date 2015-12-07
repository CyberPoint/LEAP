<#


.SYNOPSIS
WeakLink.ps1
A component of Windows 7.x, 8.x, and 10.x Local Elevation of Attacker's Privileges Toolkit (LEAP) by Greg Linares (@Laughing_Mantis)
and Cyberpoint SRT team.

WeakLink is designed to find insecure files that can be hijacked or overwritten by malicious users or applications to either gain elevated 
privileges or to persist ona system after a reboot.

WeakLink can be used to identify insecure files using several methods or prerequisites:

- It can identify files that contain specified strings in their FileInfo metadata.  This is ideal for identifying files that belong 
to a specific vendor or product that can be potentially exploited.

- It will identify files that have weak or no Authenticode signatures.  These files may be suseptible to being overwritten and could
potentially aid a malicious attacker or user into gaining elevated privileges.

- It will identify files with weak ACL permissions that could potentially allow a specified user account the ability to overwrite the
insecure file with a trojanized file and gain elevated permissions.


.EXAMPLE
.\Weaklinks.ps1 -Path C:\Users\User\AppData\Local\Temp\ -Include * -Recurse 

PATH
Specifies which folder to crawl for files that match the search criteria in order to discover possible vulnerabilities on the file system

Important Note: Due to how Powershell passes path values, values should be tab-completed in the command-line and enclosed with double quotes (") to fully resolve.


META
File metadata values to match against in order to flag them for inspection (case insensitive string search)
Metadata sections inspected are the following areas:
    - Filename
    - File Path
    - All sections of the VersionInfo block of the file

Default: "Microsoft"
Disable Metasearch: "-META ANY" will act as a wild card to search all files and ignore any metadata
Example: "-META JAVA" will search any file with JAVA listed in its VersionInfo, Path, or Filename


INCLUDE
Specifies which files by extension to search for in the location specified by the PATH parameter

Default: By default this value will search "*.exe, *.dll, and *.sys" files
Example: "-INCLUDE *" will include all files
Example: "-INCLUDE *.dll" will search only DLL files

Important Note: Due to how PowerShell parses array objects, in order to look for multiple files, the best way to perform searches against multiple file types simultaneously is to edit the default value of the INCLUDE parameter in the Param section below.  Otherwise search each file extension type individually.


RECURSE
This is a flag to crawl the PATH specified folder recursively (include all subfolders) or just limit searching to the folder specified by PATH.  By not including this value, the script will not crawl any sub directories.
Default: Flag is not set, therefore no subdirectories are crawled by default
Example: "-RECURSE" will set the flag value to true and search subfolders of the PATH


IGNOREINFO
Boolean flag to specify if the script should parse FileInfo / FileVersion blocks to search for META and to display their content.  This flag can be set in order to speed up the search process of files, or when the targeted files do not carry FileVersion Info, such as searching for vulnerable text based files (XML, INI, CONFIG, INF) etc.
Example: "-IGNOREINFO" will disable file info META searching and displaying their content


IGNORESIG
Boolean flag to specify that the script ignore all file signature (codesignature) based checks.  
This flag can be set in order to speed up the search process of files, target applications which have no code signing restrictions, or when the targeted files are not subjected to code signing, such as searching for vulnerable text based files (XML, INI, CONFIG, INF) etc
Example: "-IGNORESIG" will disable code signing checks


FULL
Boolean flag to specify that the script look for files only with FULL ACCESS permissions based on the account specified by USER parameters.
Default: If FULL, WRITE, and READ are all not specified the script will default to WRITE access
Example: "-FULL" will search for files with FULL access (Read, Write, and Execute)


WRITE
Boolean flag to specify the the script look for files with WRITE access permissions based on the account specified by USER parameters
Default: If FULL, WRITE, and READ are all not specified the script will default to WRITE access
Example: "-WRITE" will search for files with WRITE access enabled


READ
Boolean flag to specify the the script look for files with READ access permissions based on the account specified by USER parameters
Default: If FULL, WRITE, and READ are all not specified the script will default to WRITE access
Example: "-READ" will search for files with READ access enabled


FOLDERS
Boolean flag to specify that the script look only at folders and not files.  Values specified by META are still taken into consideration with this flag in order to assist in searching for folders containing a specific string value.  

This is particularly useful for looking for folders with improper or weak permissions enabled.

By setting this flag, 'IGNORESIG' and 'IGNOREINFO' are enabled.

Default: This value is set to false by default (file searching is default action)
Example: "-FOLDERS" will set the script to search for Folders 

USER
The local account username or groupname in which to perform permission based checks (CACLS/ACL/DACLs) as.

Default: This value is set to the current user account
Example: "-USER USERS" will use the all users account / group on the system as perspective for ACL checks
Example: "-USER SYSTEM" will use any SYSTEM based account as perspective for ACL checks
Example: "-USER Administrator" will use the Administrator



.EXAMPLE
Powershell -ExecutionPolicy Bypass -File C:\tools\LEAP\WeakLinks.ps1 -PATH "C:\ProgramData" -RECURSE -META ANY

Will search "C:\ProgramFiles\" and its subdirectories for any exe, dll, or sys file that meet the following requirements:

No Code Signature OR Weak Code Signature (Expired, Incomplete chain, Invalid chain, Invalid signarures)
AND
Has WRITE access permissions from the CurrentUser or EVERYONE accounts

Passed parameters:
Scanning C:\ProgramData
Recurse Directories: True
Included Files: *.exe *.dll *.sys
FileInfo Metadata Search: ANY
Validate User Permissions Against: CurrentUser
Flag Against Read Access: False
Flag Against Write Access: True
Flag Against Full Access: False
Ignore Signatures: False
Ignore File Info: False
Inspect Folders: False

==============================================================
Example 2: Powershell -ExecutionPolicy Bypass -File C:\tools\LEAP\WeakLinks.ps1 -PATH "C:\ProgramData" -RECURSE -META ANY -INCLUDE *.INI -IGNORESIG -IGNOREINFO

This will search for any INI file within "C:\ProgramData\" and its sub folders with WRITE access from the current user

Scanning C:\ProgramData
Recurse Directories: True
Included Files: *.INI
FileInfo Metadata Search: ANY
Validate User Permissions Against: CurrentUser
Flag Against Read Access: False
Flag Against Write Access: True
Flag Against Full Access: False
Ignore Signatures: True
Ignore File Info: True
Inspect Folders: False

==============================================================
Example 3: Powershell -ExecutionPolicy Bypass -File C:\tools\LEAP\WeakLink2.ps1 -PATH "C:\ProgramData" -META Service -USER USERS -RECURSE -IGNORESIG -INCLUDE *.EXE

Identify any EXE within "C:\ProgramData\" and its sub-folders that contain the word "Service" in its file information or path, and can be overwritten by USERS on the system and ignore any code signature protection in place


Scanning C:\ProgramData
Recurse Directories: True
Included Files: *.EXE
FileInfo Metadata Search: Service
Validate User Permissions Against: USERS
Flag Against Read Access: False
Flag Against Write Access: True
Flag Against Full Access: False
Ignore Signatures: True
Ignore File Info: False
Inspect Folders: False

==============================================================

.OUTPUT

Example: powershell -executionpolicy bypass -file C:\tools\LEAP\WeakLink.ps1 -PATH "C:\ProgramData" -META Service -USER USERS -RECURSE -IGNORESIG -INCLUDE *.EXE

Scanning C:\ProgramData
Recurse Directories: True
Included Files: *.EXE
FileInfo Metadata Search: Service
Validate User Permissions Against: USERS
Flag Against Read Access: False
Flag Against Write Access: True
Flag Against Full Access: False
Ignore Signatures: True
Ignore File Info: False
Inspect Folders: False

C:\ProgramData\NVIDIA Corporation\GeForce Experience\Update\GFExperience.NvStreamSrv\amd64\server\NvStreamNetworkService.exe

File Information :

FileVersionRaw     : 4.1.2014.398
ProductVersionRaw  : 4.1.240.0
Comments           :
CompanyName        : NVIDIA Corporation
FileBuildPart      : 2014
*FileDescription    : NVIDIA Network Stream Service
FileMajorPart      : 4
FileMinorPart      : 1
*FileName           : C:\ProgramData\NVIDIA Corporation\GeForce Experience\Update\GFExperience.NvStreamSrv\amd64\server\NvStreamNetworkService.exe
FilePrivatePart    : 398
FileVersion        : 4.1.2014.0398
*InternalName       : NvStreamNetworkService
IsDebug            : False
IsPatched          : False
IsPrivateBuild     : False
IsPreRelease       : False
IsSpecialBuild     : False
Language           : English
LegalCopyright     : (C) 2015 NVIDIA Corporation. All rights reserved.
LegalTrademarks    :
*OriginalFilename   : NvStreamNetworkService.exe
PrivateBuild       :
ProductBuildPart   : 240
ProductMajorPart   : 4
ProductMinorPart   : 1
ProductName        : NVIDIA Streaming
ProductPrivatePart : 0
ProductVersion     : 4.1.0240.0
SpecialBuild       :



Weak ACL Permissions:

Rights     : FullControl
FullPath   : C:\ProgramData\NVIDIA Corporation\GeForce Experience\Update\GFExperience.NvStreamSrv\amd64\server\NvStreamNetworkService.exe
Domain     : Everyone
ID         :
AccessType : Allow

Note: * next to File Information indicates colored areas which matched against META parameter searches

=============================================================

Example2: powershell -executionpolicy bypass -file C:\tools\LEAP\WeakLink.ps1 -PATH "C:\ProgramData" -META ANY -USER USERS -RECURSE

Scanning C:\ProgramData
Recurse Directories: True
Included Files: *.exe *.dll *.sys
FileInfo Metadata Search: ANY
Validate User Permissions Against: USERS
Flag Against Read Access: False
Flag Against Write Access: True
Flag Against Full Access: False
Ignore Signatures: False
Ignore File Info: False
Inspect Folders: False

C:\ProgramData\NVIDIA Corporation\GeForce Experience\Update\GFExperience.NvStreamSrv\amd64\server\nvinject.dll

File Information :

FileVersionRaw     : 4.1.1997.4842
ProductVersionRaw  : 4.1.240.0
Comments           :
CompanyName        : NVIDIA Corporation
FileBuildPart      : 1997
FileDescription    : NVIDIA nvinject
FileMajorPart      : 4
FileMinorPart      : 1
FileName           : C:\ProgramData\NVIDIA Corporation\GeForce Experience\Update\GFExperience.NvStreamSrv\amd64\server\nvinject.dll
FilePrivatePart    : 4842
FileVersion        : 4.1.1997.4842
InternalName       : nvinject
IsDebug            : False
IsPatched          : False
IsPrivateBuild     : False
IsPreRelease       : False
IsSpecialBuild     : False
Language           : English
LegalCopyright     : (C) 2015 NVIDIA Corporation. All rights reserved.
LegalTrademarks    :
OriginalFilename   : nvinject.dll
PrivateBuild       :
ProductBuildPart   : 240
ProductMajorPart   : 4
ProductMinorPart   : 1
ProductName        : NVIDIA Streamer
ProductPrivatePart : 0
ProductVersion     : 4.1.0240.0
SpecialBuild       :


Code Signature Status:
[UnknownError]
Authenticode Status Details: A certificate chain could not be built to a trusted root authority

Authenticode Certificate Details:
[Subject]
  CN=NVIDIA Corporation PE Sign v2014

[Issuer]
  CN=NVIDIA Subordinate CA 2014, DC=nvidia, DC=com

[Serial Number]
  6130049C000000000003

[Not Before]
  7/14/2014 7:47:24 PM

[Not After]
  7/11/2016 1:40:28 PM

[Thumbprint]
  C5FD151381CA7F5EA982331EBC76D75613C8CCA7

Weak ACL Permissions:

Rights     : FullControl
FullPath   : C:\ProgramData\NVIDIA Corporation\GeForce Experience\Update\GFExperience.NvStreamSrv\amd64\server\nvinject.dll
Domain     : Everyone
ID         :
AccessType : Allow

PS: Somebody you should probably look into this ;) just saying


#>


Param
(
    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Path = (Get-Location -PSProvider FileSystem).Path,

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [string]$Meta = 'Microsoft',

        
    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [string[]]$Include = @('*.exe','*.dll','*.sys'),

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [switch]$Recurse,

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [switch]$IgnoreInfo,

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [switch]$IgnoreSig,
    
    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [switch]$Full,

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [switch]$Write,

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [switch]$Read,

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [switch]$Folders,

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [string]$User = [Environment]::UserName
)


Clear-Host

if (!($Path.EndsWith('\*')) -and (!($Recurse)))
{
    $Path = $Path + '\*'
}

if ((!($Read)) -and (!($Write)) -and (!($Full)))
{
    $Write = $TRUE
}

if ($Folders)
{
    $IgnoreSig = $TRUE
    
    $IgnoreInfo = $TRUE
    
}


Write-Host "Scanning $Path"
Write-Host "Recurse Directories: $Recurse"
Write-Host "Included Files: $Include"
Write-Host "FileInfo Metadata Search: $Meta"
Write-Host "Validate User Permissions Against: $User"
Write-Host "Flag Against Read Access: $Read"
Write-Host "Flag Against Write Access: $Write"
Write-Host "Flag Against Full Access: $Full"
Write-Host "Ignore Signatures: $IgnoreSig"
Write-Host "Ignore File Info: $IgnoreInfo"
Write-Host "Inspect Folders: $Folders"



$FileCount = 0
$VulnFiles = 0
$MetaSearch = $TRUE

# If user specifies -meta ANY then no metadata search is performed 
if ($Meta -eq "ANY")
{
    $MetaSearch = $FALSE
}

Try
{
    if (!($Folders))
    {
        $Files = Get-ChildItem $Path -Include $Include -Recurse:$Recurse -Force -ErrorAction SilentlyContinue | Where-Object{!($_.PSIsContainer)}
    }
    else
    {
         $Files = Get-ChildItem $Path -Dir -Recurse:$Recurse -Force -ErrorAction SilentlyContinue | Where-Object{($_.PSIsContainer)}
    }
}
Catch
{
    #Error Message for Access Denial on files
}

ForEach($Item In $Files)
{
    
    $File = $Item.FullName
    $FileMatch = $TRUE
    $FileCount++
    $FileInfo = [string]::Empty
    
    $FileLen = $File | measure-object -character | select -expandproperty characters 
    
    if ($FileLen -eq "0")
    {
        Write-Host "No Files Scanned"
        Exit
    }

    if ($MetaSearch)
    {
        if ($Folders)
        {
            if (!($File.ToLower().Contains($Meta.ToLower())))
            {
                $FileMatch = $FALSE
            }            
        }
        else
        {
            $FileInfo = (Get-Item $File -ErrorAction SilentlyContinue).VersionInfo | Format-List * -Force | Out-String 
            if (!($FileInfo.ToLower().Contains($Meta.ToLower())))
            {
                $FileMatch = $FALSE
            }
        }
        
    }

    

    if ($FileMatch)
    {
        try
        {
            $obj_acl = Get-Acl $File -ErrorAction SilentlyContinue
            $acls = $obj_acl.Access
        }
        catch
        {
            
        }
        $FileMatch = $FALSE
        $WeakACLs = [string]::Empty
        Write-Verbose "Inspecting $File"

        foreach($acl in $acls)
        {
            $ACLMatch = $FALSE

            $WeakACL = @{'FullPath' = $File; 
                                            'Domain' = $acl.IdentityReference.Value.Split('\')[0];
                                            'ID' = $acl.IdentityReference.Value.Split('\')[1];
                                            'Rights' = $acl.FileSystemRights;
                                            'AccessType' = $acl.AccessControlType}

            $WeakACL = New-Object -TypeName PSObject -Property $WeakACL | Format-List * -Force | Out-String

            Write-Verbose $WeakACL

            if (($acl.IdentityReference.Value.Split('\')[1] -eq $User) -or ($acl.IdentityReference.Value.Split('\')[0] -eq "Everyone") -or (($acl.IdentityReference.Value.Split('\')[0] -eq "BUILTIN" -and $acl.IdentityReference.Value.Split('\')[1] -eq "USERS")))
            {
                switch -Wildcard ($acl.FileSystemRights)
                {
                    "*Write*" 
                    {
                        if ($Write)
                        {
                            if ($acl.AccessControlType -eq "Allow")
                            {
                                $ACLMatch = $TRUE
                                Write-Verbose "Matched Write"
                            }
                        }
                    }
                    "*FullControl*"
                    {
                        if ($Write)
                        {
                            if ($acl.AccessControlType -eq "Allow")
                            {
                                $ACLMatch = $TRUE
                                Write-Verbose "Matched Full Write"
                            }
                        }
                        if ($Full)
                        {
                            if ($acl.AccessControlType -eq "Allow")
                            {
                                $ACLMatch = $TRUE
                                Write-Verbose "Matched Full Full"
                            }
                        }
                        if ($Read)
                        {
                            if ($acl.AccessControlType -eq "Allow")
                            {
                                $ACLMatch = $TRUE
                                Write-Verbose "Matched Full Read"
                            }
                        }
                    }
                    "*Read*"
                    {
                        if ($Read)
                        {
                            if ($acl.AccessControlType -eq "Allow")
                            {
                                $ACLMatch = $TRUE
                                Write-Verbose "Matched Read"
                            }
                        }
                    }
                }
                
                if ($ACLMatch)
                {
                    $WeakACL = @{'FullPath' = $File; 
                                            'Domain' = $acl.IdentityReference.Value.Split('\')[0];
                                            'ID' = $acl.IdentityReference.Value.Split('\')[1];
                                            'Rights' = $acl.FileSystemRights;
                                            'AccessType' = $acl.AccessControlType}
        
                    $WeakACLs += New-Object -TypeName PSObject -Property $WeakACL | Format-List * -Force | Out-String
                    $FileMatch = $TRUE
                    
                }
            }
        }
        if ($FileMatch)
        {
            $FileMatch = $FALSE
            #Write-Host "Inspecting $Info"

            if (!($IgnoreSig))
            {
                $sig = $(Get-AuthenticodeSignature $File -ErrorAction SilentlyContinue) 
                if (!($sig.Status -eq "Valid"))
                {
                    $FileMatch = $TRUE
                }
            }
            else
            {
                $FileMatch = $TRUE
            }



            if ($FileMatch)
            {
                Write-Host $File

                if (!($IgnoreInfo))
                {
                    Write-Host "`r`nFile Information :" -NoNewline
                    if ($MetaSearch)
                    {
                    
                    
                        $lines = $FileInfo.Split("`r")              
                    
                        foreach($line in $lines)
                        {
                            if ($line.toLower().Contains($Meta.ToLower()))
                            {
                                Write-Host $($line) -NoNewLine -ForegroundColor Red
                            }
                            else
                            {
                                Write-Host $line -NoNewline
                            }
                        }
                    }
                    else
                    {
                        $FileInfo = (Get-Item $File -ErrorAction SilentlyContinue).VersionInfo | Format-List * -Force | Out-String
                        Write-Host $FileInfo
                    }
                }

                if (!($IgnoreSig))
                {
                    if (!($sig.Status -eq "Valid"))
                    {
                        Write-Host "Code Signature Status:"
                         
                        if ($sig.Status -eq "NotSigned")
                        {
                            Write-Host [$($sig.Status)] -ForegroundColor Red
                            Write-Host "`r`n"
                            Write-Host "Code Sign Status Details:"
                            Write-Host "$File is not digitally signed.`r`n" -ForegroundColor Red
                            #Write-Host "Status Details: $($sig.StatusMessage)`r`n" -ForegroundColor Red
                        }
                        else
                        {
                            Write-Host [$($sig.Status)] -ForegroundColor Yellow
                            Write-Host "$($sig.SignatureType) Status Details: $($sig.StatusMessage)`r`n" -ForegroundColor Yellow
                            Write-Host "Authenticode Certificate Details: "
                            Write-Host $sig.SignerCertificate -ForegroundColor Yellow
                        }

                        if ($sig.IsOSBinary)
                        {
                            Write-Host "$File is registered as an OS Binary`r`n" -ForegroundColor Green
                        }
                    }
                }
                Write-Host "Weak ACL Permissions: " -NoNewline
                Write-Host $WeakACLs -ForegroundColor Red
                Write-Host "=========================================================================================="
                $VulnFiles ++
            }
        }
    }
}
Write-Host "Total Files Scanned: $FileCount"
Write-Host "Potentially Vulnerable Files Identified: $VulnFiles"