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


.SYNTAX



.EXAMPLE


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
        $Files = Get-ChildItem $Path -Include $Include -Recurse:$Recurse -Force -ErrorAction SilentlyContinue
    }
    else
    {
         $Files = Get-ChildItem $Path -Dir -Recurse:$Recurse -Force -ErrorAction SilentlyContinue
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
        Write-Verbose "Examing $File"

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