### Module - zWindowsUpdate

<#
.NOTES
    ######################
     mail@nimbus117.co.uk
    ######################  
.SYNOPSIS
    Search for, download and install windows updates.
.DESCRIPTION
    By default this script will search for, download and install all software updates but will not reboot the computer if required. Optionally Search for specific update types, such as CriticalUpdates or SecurityUpdates, exclude optional updates, automatically reboot if required, search for updates only or download updates without installing them. All output is written to an .xml logfile in the directory the script is run, you can use Import-Clixml to view the log. There is no output to the host unless you use the -Verbose parameter.
.PARAMETER AcceptEula
    Accept update EULA if needed.
.PARAMETER AutoSelect
    Only include updates that are flagged to be automatically selected by Windows Update.
.PARAMETER DownloadOnly
    Download updates but do not install them.
.PARAMETER ExcludeKB
    Exclude updates by KB number.
.PARAMETER ExcludeOptional
    Exclude updates that are considered optional.
.PARAMETER IncludeKB
    Include updates by KB number.
.PARAMETER Reboot
    Attempt to reboot the computer if required after installing updates.
.PARAMETER SearchOnly
    Search for updates only, do not download or install them.
.PARAMETER Service
    Select update service. Possible values are 'MicrosoftUpdate', 'WindowsUpdate', 'WSUS'. When not specified the system default is used. The script will attempt to add the MicrosoftUpdate service if it is not registered.
.PARAMETER SmtpFrom
    From address for the email report.
.PARAMETER SmtpServer
    Smtp server used to send the email report.
.PARAMETER SmtpTo
    To address for the email report.
.PARAMETER UpdateType
    Specify which update types to search for, such as CriticalUpdates or SecurityUpdates. Possible values are 'Application', 'CriticalUpdates', 'Definitions', 'FeaturePacks', 'SecurityUpdates', 'ServicePacks', 'Tools', 'UpdateRollups', 'Updates'. The default is all software updates.
.EXAMPLE
    PS C:\> .\zWUScript.ps1 -UpdateType CriticalUpdates,SecurityUpdates -SearchOnly
    Search for needed critical and security updates.
.EXAMPLE
    PS C:\> .\zWUScript.ps1 -AutoSelect -Reboot -SmtpFrom zWU@domain.com -SmtpTo john@domain.com -SmtpServer mail.domain.com
    Search for, download and install automatically selected updates. The computer will be restarted automatically if required and a report email will be sent.
#>

#Requires -Version 4.0

[cmdletbinding(DefaultParameterSetName='Install')]

param( 

    [parameter(ParameterSetName = 'DownloadOnly')]
    [parameter(ParameterSetName = 'Install')]
    [switch]$AcceptEula,

    [switch]$AutoSelect,

    [parameter(ParameterSetName = 'DownloadOnly')]
    [switch]$DownloadOnly,

    [ValidateScript({$_ -match 'kb[0-9]{6,}'})]
    [string[]]$ExcludeKB,

    [switch]$ExcludeOptional,

    [ValidateScript({$_ -match 'kb[0-9]{6,}'})]
    [string[]]$IncludeKB,

    [parameter(ParameterSetName = 'Install')]
    [switch]$Reboot,

    [parameter(ParameterSetName = 'SearchOnly')]
    [switch]$SearchOnly,

    [ValidateSet('MicrosoftUpdate', 'WindowsUpdate', 'WSUS')]
    [ValidateNotNullOrEmpty()]
    [string]$Service,
    
    [Net.Mail.MailAddress]$SmtpFrom,

    [ValidateNotNullOrEmpty()]
    [string]$SmtpServer,

    [Net.Mail.MailAddress]$SmtpTo,

    [ValidateSet('Application', 'CriticalUpdates', 'Definitions', 'FeaturePacks', 'SecurityUpdates', 'ServicePacks', 'Tools', 'UpdateRollups', 'Updates')]
    [ValidateNotNullOrEmpty()]
    [string[]]$UpdateType
)

if ($SmtpFrom -and $SmtpTo -and $SmtpServer) {$SendEmail = $true}

elseif ($SmtpFrom -or $SmtpTo -or $SmtpServer) {throw "$(Get-Location)\$($MyInvocation.MyCommand.Name) : Provide all -Smtp* parameters"}

$LogPath = '.\zWUScriptLog.xml'

## Write to xml log

function WULog {

    param(
        
        [Parameter(Position = 0,Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Message,

        [Parameter(Position=1)]
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info',

        [switch]$Overwrite
    )

    $Date = Get-Date

    $Log = $Message | ForEach-Object {

        [PSCustomObject]@{Timestamp = $Date ; Level = $Level ; Message = $_}
        
        Write-Verbose "$Date - $Level - $_"
    }
    
    if (-not $Overwrite) {
        
        if (Test-Path -Path $LogPath -PathType Leaf) {

            $Import = @(Import-Clixml -Path $LogPath)

            $Log = $Import += $Log
        }
    }

    $Log | Export-Clixml -Path $LogPath -Force
}

## Convert units

function WUUnits {

param(
        [Parameter(Position = 0,Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [double]$Bytes,

        [Parameter(Position=1)]
        [ValidateRange(0,5)]
        [int]$Round = 1
)

    $Units = @('B', 'KB', 'MB', 'GB')

    for ($i=0; $Bytes -ge 1024 -and $i -lt $Units.Length; $i++) {$Bytes = $Bytes / 1024}

    "$([Math]::Round($Bytes,$Round))$($Units[$i])"
}

## Format update size

function WUSize {
    
    param(
        
        [Parameter(Position = 0,Mandatory = $True)]
        [double]$MinSize,

        [Parameter(Position = 1,Mandatory = $True)]
        [double]$MaxSize
    )

    if ($MaxSize -eq $MinSize) {"($(WUUnits $MaxSize))"}
                
    else {"($(WUUnits $MinSize)-$(WUUnits $MaxSize))"}
}

## Update title and size for log message

function WUDetails {

    param(
    
        [Parameter(Position = 0,Mandatory = $True)]
        $Update
    )
    
    "$($Update.Title) $(WUSize $Update.MinDownloadSize $Update.MaxDownloadSize)"
}

## Send report email

function WUEmail {
        
    try{

        $Log = Import-Clixml -Path $LogPath

        if ($Log.Level -contains 'Error') {$Colour = 'Red' ; $Level = 'Error'}
        
        elseif ($Log.Level -contains 'Warning') {$Colour = 'Yellow' ; $Level = 'Warning'}
        
        else {$Colour = 'Green' ; $Level = 'Success'}

        $EmailHead = "<style>table {border-collapse: collapse;} table,th,td {border:1px solid black;font-size:14px;text-align:left;vertical-align:middle;padding: 5px;} th {background-color:$Colour;color:Black}</style>"

        $EmailBody = $Log | ConvertTo-Html -As Table -Head $EmailHead | Out-String

        $Message_Params = @{

            Subject = "zWindowsUpdate - $Level - $env:COMPUTERNAME"
            Body = $EmailBody
            BodyAsHtml = $true
            From = $SmtpFrom
            To = $SmtpTo
            SmtpServer = $SmtpServer
        }

        Send-MailMessage @Message_Params
    } 
        
    catch{WULog -Message "Email - $($_.Exception.Message)" -Level Error}

    finally {$Script:Sent = $true}
}

## Script Start

try {

    $CurrentErrorActionPreference = $ErrorActionPreference

    $ErrorActionPreference = 'Stop'

    $ResultCodes = @{0 = 'not started' ; 1 = 'in progress' ; 2 = 'succeeded' ; 3 = 'succeeded with errors' ; 4 = 'failed' ; 5 = 'aborted'}

    WULog -Message '## zWindowsUpdate ##' -Overwrite

    $PMessage = @()
    
    foreach ($P in ($PSBoundParameters.GetEnumerator()) | Sort-Object Key) {$PMessage += "Parameter - $($P.Key) = $($P.Value)"}
    
    if ($PMessage.Count -gt 0) {WULog -Message $PMessage}

    WULog -Message 'Starting windows update session'

    ## Create search criteria

    $SearchCriteria = "Type='Software' and IsInstalled=0 and IsHidden=0"

    if ($ExcludeOptional) {$SearchCriteria = $SearchCriteria + ' and BrowseOnly=0'}

    if ($AutoSelect) {$SearchCriteria = $SearchCriteria + ' and AutoSelectOnWebSites=1'}

    if ($UpdateType) {

        switch ($UpdateType) {

            {$UpdateType -contains 'Application'} {$TypeCriteria = $TypeCriteria + "($SearchCriteria and CategoryIDs contains '5C9376AB-8CE6-464A-B136-22113DD69801') or "}

            {$UpdateType -contains 'CriticalUpdates'} {$TypeCriteria = $TypeCriteria + "($SearchCriteria and CategoryIDs contains 'E6CF1350-C01B-414D-A61F-263D14D133B4') or "}

            {$UpdateType -contains 'Definitions'} {$TypeCriteria = $TypeCriteria + "($SearchCriteria and CategoryIDs contains 'E0789628-CE08-4437-BE74-2495B842F43B') or "}

            {$UpdateType -contains 'FeaturePacks'} {$TypeCriteria = $TypeCriteria + "($SearchCriteria and CategoryIDs contains 'B54E7D24-7ADD-428F-8B75-90A396FA584F') or "}

            {$UpdateType -contains 'SecurityUpdates'} {$TypeCriteria = $TypeCriteria + "($SearchCriteria and CategoryIDs contains '0FA1201D-4330-4FA8-8AE9-B877473B6441') or "}

            {$UpdateType -contains 'ServicePacks'} {$TypeCriteria = $TypeCriteria + "($SearchCriteria and CategoryIDs contains '68C5B0A3-D1A6-4553-AE49-01D3A7827828') or "}

            {$UpdateType -contains 'Tools'} {$TypeCriteria = $TypeCriteria + "($SearchCriteria and CategoryIDs contains 'B4832BD8-E735-4761-8DAF-37F882276DAB') or "}

            {$UpdateType -contains 'UpdateRollups'} {$TypeCriteria = $TypeCriteria + "($SearchCriteria and CategoryIDs contains '28BC880E-0592-4CBF-8F95-C79B17911D5F') or "}

            {$UpdateType -contains 'Updates'} {$TypeCriteria = $TypeCriteria + "($SearchCriteria and CategoryIDs contains 'CD5FFD1E-E932-4E3A-BF74-18BF0B1BBD83') or "}
        }

        $SearchCriteria = $TypeCriteria.TrimEnd(' or ')
    }

    ## Check for a pending reboot

    $PendingReboot = (New-Object -ComObject 'Microsoft.Update.SystemInfo').RebootRequired

    if (-not $PendingReboot) {

        ## Section 1 - Search

        ## Create update session object

        try {$UpdateSession = New-Object -ComObject 'Microsoft.Update.Session'}

        catch {throw "Update session - $($_.Exception.Message)"}

        ## Create update searcher

        try {$UpdateSearcher = $UpdateSession.CreateUpdateSearcher()}

        catch {throw "Update searcher - $($_.Exception.Message)"}

        ## Service selection

        if ($Service -eq 'WSUS') {$UpdateSearcher.ServerSelection = 1}

        elseif ($Service -eq 'WindowsUpdate') {$UpdateSearcher.ServerSelection = 2}

        elseif ($Service -eq 'MicrosoftUpdate') {

            try {
            
                $ServiceManager = $UpdateSession.CreateUpdateServiceManager()

                $MSService = $ServiceManager.Services | Where-Object {$_.name -eq 'Microsoft Update'}

                $UpdateSearcher.ServerSelection = 3

                if ($MSService) {$UpdateSearcher.ServiceID = $MSService.ServiceID}

                else {
                    
                    WULog -Message 'Attempting to add Microsoft Update service'

                    $MSServiceID = '7971f918-a847-4430-9279-4a52d1efe18d'
                    
                    $ServiceManager.AddService2($MSServiceID,2,'') | Out-Null

                    $UpdateSearcher.ServiceID = $MSServiceID
                }
            
            }

            catch {throw "Service - $($_.Exception.Message)"}        
        }

        ## Search for updates

        WULog -Message 'Searching for updates'
    
        try {$Updates = $UpdateSearcher.Search($SearchCriteria).Updates}

        catch {throw "Update searcher - $($_.Exception.Message)"}

        ## Filter updates by KBArticleIDs

        if ($IncludeKB) {

            $Updates = $Updates | ForEach-Object {

                foreach ($KB in $IncludeKB) {if ($KB -match $_.KBArticleIDs) {$_ ; break}}
            }
        }

        if ($ExcludeKB) {

            $Updates = $Updates | ForEach-Object {

                $IncludeUpdate = $true

                foreach ($KB in $ExcludeKB) {if ($KB -match $_.KBArticleIDs) {$IncludeUpdate = $false ; break}}

                if ($IncludeUpdate) {$_}
            }
        }

        $UpdateCount = ($Updates | Measure-Object).Count

        if ($UpdateCount -gt 0) {

            $UpdateMaxSize = ($Updates | Measure-Object -Sum -Property MaxDownloadSize).Sum

            $UpdateMinSize = ($Updates | Measure-Object -Sum -Property MinDownloadSize).Sum

            WULog -Message "Found $UpdateCount update(s) $(WUSize $UpdateMinSize $UpdateMaxSize)"
            
            $UMessage = $Updates | ForEach-Object {"$(WUDetails -Update $_)"}

            WULog -Message $UMessage

            if (-not $SearchOnly) {

                $UpdatesToDownload = @()

                ## Check if EULA needs accepted then either accept or don't download, depending on -AcceptEula parameter

                foreach ($Update in $Updates) {
     
                    if (($Update.EulaAccepted -eq $false)) {
                        
                        if ($AcceptEula) {
                            
                            try {
                                
                                WULog -Message "Accepting EULA - $(WUDetails -Update $Update)"

                                $Update.AcceptEula()

                                $UpdatesToDownload += $Update
                            }
                            
                            catch {WULog -Message "Accepting EULA failed, update will not be downloaded - $($_.Exception.Message) - $(WUDetails -Update $Update)" -Level Error}
                        }

                        else {WULog -Message "Update requires an EULA to be accepted and will not be downloaded - $(WUDetails -Update $Update)" -Level Warning}
                    }

                    else {$UpdatesToDownload += $Update}
                }

                $DownloadCount = ($UpdatesToDownload | Measure-Object).Count
        
                if ($DownloadCount -gt 0) {
                
                    ## Section 2 - Download 

                    $UpdateMaxSize = ($UpdatesToDownload | Measure-Object -Sum -Property MaxDownloadSize).Sum

                    $UpdateMinSize = ($UpdatesToDownload | Measure-Object -Sum -Property MinDownloadSize).Sum

                    WULog -Message "Downloading $DownloadCount update(s) $(WUSize $UpdateMinSize $UpdateMaxSize)"

                    ## Create update downloader

                    try {$UpdateDownloader = $UpdateSession.CreateUpdateDownloader()} 
                
                    catch {throw "Update Downloader - $($_.Exception.Message)"}

                    $UpdatesToInstall = @()

                    $DownloadCounter = 1

                    ## Loop through updates to be downloaded

                    foreach ($Update in $UpdatesToDownload) {

                        ## Check if the update has already been downloaded

                        if ($Update.IsDownloaded -eq $true) {
                        
                            WULog -Message "Download $DownloadCounter of $DownloadCount already completed - $(WUDetails -Update $Update)"

                            $UpdatesToInstall += $Update
                        }

                        else {

                            try {

                                ## Download update

                                WULog -Message "Downloading update $DownloadCounter of $DownloadCount - $(WUDetails -Update $Update)"

                                $UpdateToDownload = New-object -ComObject 'Microsoft.Update.UpdateColl'
                    
                                $UpdateToDownload.Add($Update) | Out-Null
                    
                                $UpdateDownloader.Updates = $UpdateToDownload
                    
                                $DownloadResult = $UpdateDownloader.Download()

                                ## Check download result code

                                if ($DownloadResult.resultCode –eq 2) {
                    
                                    $UpdatesToInstall += $Update

                                    WULog -Message "Download $($ResultCodes[[int]$DownloadResult.ResultCode]) - $(WUDetails -Update $Update)"
                                }

                                elseif ($DownloadResult.resultCode –eq 3) {
                            
                                    $UpdatesToInstall += $Update

                                    WULog -Message "Download $($ResultCodes[[int]$DownloadResult.ResultCode]) - $(WUDetails -Update $Update)" -Level Warning
                                }
                    
                                else {WULog -Message "Download $($ResultCodes[[int]$DownloadResult.ResultCode]) - $(WUDetails -Update $Update)" -Level Error}
                            }

                            catch {WULog -Message "Update download - $($_.Exception.Message) - $(WUDetails -Update $Update)" -Level Error}
                        }

                        $DownloadCounter++
                    }

                    $InstallCount = ($UpdatesToInstall | Measure-Object).Count

                    if (-not $DownloadOnly) {

                        if ($InstallCount -gt 0) {

                            ## Section 3 - Install

                            $UpdateMaxSize = ($UpdatesToInstall | Measure-Object -Sum -Property MaxDownloadSize).Sum

                            $UpdateMinSize = ($UpdatesToInstall | Measure-Object -Sum -Property MinDownloadSize).Sum

                            WULog -Message "Installing $InstallCount update(s) $(WUSize $UpdateMinSize $UpdateMaxSize)"

                            ## Create update installer

                            try {$UpdateInstaller = $UpdateSession.CreateUpdateInstaller()}

                            catch {throw "Update installer - $($_.Exception.Message)"}

                            $InstallCounter = 1

                            $InstalledCount = 0

                            $RebootRequired = $false

                            ## Loop through updates to be installed

                            foreach ($Update in $UpdatesToInstall) {

                                WULog -Message "Installing update $InstallCounter of $InstallCount - $(WUDetails -Update $Update)"

                                try {

                                    ## Install update

                                    $UpdateToInstall = New-object -ComObject 'Microsoft.Update.UpdateColl'
        
                                    $UpdateToInstall.Add($Update) | Out-Null

                                    $UpdateInstaller.Updates = $UpdateToInstall
                        
                                    $InstallResult = $UpdateInstaller.Install()

                                    ## Check install result code

                                    if ($InstallResult.ResultCode –eq 2) {

                                        WULog -Message "Install $($ResultCodes[[int]$InstallResult.ResultCode]) - $(WUDetails -Update $Update)"

                                        if ($InstallResult.RebootRequired) {$RebootRequired = $true}

                                        $InstalledCount++
                                    }

                                    elseif ($InstallResult.resultCode –eq 3) {
                                    
                                        WULog -Message "Install $($ResultCodes[[int]$InstallResult.ResultCode]) - $(WUDetails -Update $Update)" -Level Warning

                                        if ($InstallResult.RebootRequired) {$RebootRequired = $true}

                                        $InstalledCount++
                                    }
                    
                                    else {WULog -Message "Install $($ResultCodes[[int]$InstallResult.ResultCode]) - $(WUDetails -Update $Update)" -Level Error}
                                }

                                catch {WULog -Message "Update Install - $($_.Exception.Message) - $(WUDetails -Update $Update)" -Level Error}

                                $InstallCounter++
                            }

                            if ($RebootRequired) {

                                if ($Reboot) {
                            
                                    WULog -Message "Finished - Attempting to reboot computer - $InstalledCount of $UpdateCount update(s) installed"

                                    if ($SendEmail) {WUEmail}

                                    try {Restart-Computer -Force}
                            
                                    catch {WULog -Message "Reboot failed - $($_.Exception.Message)" -Level Error}
                                }

                                else {WULog -Message "Finished - Reboot required - $InstalledCount of $UpdateCount update(s) installed" -Level Warning}
                            }

                            else {WULog -Message "Finished - No reboot required - $InstalledCount of $UpdateCount update(s) installed"}
                        }

                        else {WULog -Message 'Finished - No updates to install'}
                    }

                    else {WULog -Message "Finished - Download only - $InstallCount of $UpdateCount update(s) downloaded"}
                }

                else {WULog -Message 'Finished - No updates to download'}
            }
        
            else {WULog -Message "Finished - Search only - $UpdateCount update(s) found"}
        }

        else {WULog -Message 'Finished - No updates found'}
    }

    else {
    
        if ($Reboot) {
                            
            WULog -Message 'Finished - Attempting to reboot computer'

            if ($SendEmail) {WUEmail}

            try {Restart-Computer -Force}
                            
            catch {WULog -Message "Reboot failed - $($_.Exception.Message)" -Level Error}
        }

        else {WULog -Message 'Finished - Pending reboot' -Level Warning}
    }
}

catch {WULog -Message "Finished - $($_.Exception.Message)" -Level Error}

finally {

    if ($SendEmail -and -not $Sent) {WUEmail}

    $ErrorActionPreference = $CurrentErrorActionPreference
}