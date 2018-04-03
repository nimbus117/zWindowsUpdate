### Module - zWindowsUpdate

# Task settings

$WU_TaskName = 'zWindowsUpdate'

$WU_TaskDescription = 'Windows update task created by zWindowsUpdate PowerShell module'

$WU_TaskWorkingDirectory = 'C:\Program Files\zWindowsUpdate' # Folder is deleted when running Remove-zWUTask

# File names

$WU_ScriptFileName = 'zWUScript.ps1'

$WU_XmlLogFileName = 'zWUScriptLog.xml'

$WU_LogFileName = 'zWUScript-Error.log'

# zWU Functions

function Get-zWULog {

    <#
    .NOTES
        ######################
         mail@nimbus117.co.uk
        ######################  
    .SYNOPSIS
        Get the log entires for a windows update task.
    .DESCRIPTION
        Returns one or more lines from the log file generated when the task is run. By default the last 1 line is returned.
    .PARAMETER ComputerName
        Specifies the computers on which the command runs.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER Full
        Return the full log.
    .PARAMETER Port
        Specifies the network port on the remote computer that is used for this command. To connect to a remote computer, the remote computer must be listening on the port that the connection uses. The default ports are 5985, which is the WinRM port for HTTP, and 5986, which is the WinRM port for HTTPS.
    .PARAMETER PSSessionOption
        Specifies advanced options for the session. Enter a SessionOption object, such as one that you create by using the New-PSSessionOption cmdlet, or a hash table in which the keys are session option names and the values are session option values.
    .PARAMETER Tail
        Retrun the last n entries of the log.
    .PARAMETER ThrottleLimit
        Specifies the maximum number of concurrent connections that can be established to run this command.
    .PARAMETER UseSSL
        Indicates that this cmdlet uses the Secure Sockets Layer (SSL) protocol to establish a connection to the remote computer. By default, SSL is not used.
    .EXAMPLE
        PS C:\>Get-zWULog 'SRV01', 'SRV02', 'SRV03', 'SRV04', 'SRV05', 'SRV06', 'CLIENT01'

        ComputerName Timestamp           Level   Message
        ------------ ---------           -----   -------
        SRV06        29/07/2017 04:38:40 Warning Finished - Reboot required - 24 of 24 update(s) installed
        SRV02        29/07/2017 03:20:55 Info    Finished - Download only - 3 update(s) downloaded
        SRV01        29/07/2017 03:14:16 Info    Searching for updates
        SRV04        29/07/2017 03:20:55 Info    Finished - Search only - 3 update(s) found
        SRV03        29/07/2017 03:14:19 Info    Downloading update 9 of 24 - Update for Windows Server 2012 R2 (KB2883200) (226.9MB)
        CLIENT01     29/07/2017 03:14:31 Info    Installing update 4 of 10 - Feature update to Windows 10 Enterprise, version 1703 (0B-2.7GB)
        SRV05        29/07/2017 03:14:17 Info    Finished - No reboot required - 1 of 1 update(s) installed

        Get the last line from the update task log on the specified remote computers.
    .EXAMPLE
        PS C:\>Get-zWULog SRV04 -Full | Out-GridView

        Get-the full update task log from the computer SRV04 and display the results in Out-GridView.
    .EXAMPLE
        PS C:\>$cred = Get-Credential
        PS C:\>$PSSessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck

        PS C:\>Get-zWULog 10.10.10.10 -Credential $cred -UseSSL -PSSessionOption $PSSessionOption -Full

        ComputerName Timestamp           Level Message
        ------------ ---------           ----- -------
        10.10.10.10  02/03/2018 16:13:45 Info  ## zWindowsUpdate ##
        10.10.10.10  02/03/2018 16:13:45 Info  Parameter - AutoSelect = True
        10.10.10.10  02/03/2018 16:13:45 Info  Parameter - SearchOnly = True
        10.10.10.10  02/03/2018 16:13:45 Info  Parameter - Service = WindowsUpdate
        10.10.10.10  02/03/2018 16:13:45 Info  Starting windows update session
        10.10.10.10  02/03/2018 16:13:45 Info  Searching for updates
        10.10.10.10  02/03/2018 16:13:53 Info  Found 3 update(s) (0B-1.2GB)
        10.10.10.10  02/03/2018 16:13:53 Info  Windows Malicious Software Removal Tool x64 - February 2018 (KB890830) (0B-38.4MB)
        10.10.10.10  02/03/2018 16:13:53 Info  2018-02 Cumulative Update for Windows Server 2016 for x64-based Systems (KB4074590) (0B-1.1GB)
        10.10.10.10  02/03/2018 16:13:53 Info  Update for Windows Defender antimalware platform - KB4052623 (Version 4.12.17007.18022) (0B-3.1MB)
        10.10.10.10  02/03/2018 16:13:53 Info  Finished - Search only - 3 update(s) found

        Get the full update task log from the computer with the Ip address 10.10.10.10. The connection will use SSL and the PSSessionOptions provided.
    .LINK
        about_zWindowsUpdate
        Get-zWUTask
        New-zWUTask
        Remove-zWUTask
        Start-zWUTask
        Stop-zWUTask
        Wait-zWUTask
    #>
    
    [cmdletbinding(DefaultParameterSetName = 'Tail')]

    param(
        
        [parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias('Name', 'PSComputerName')]
        [string[]]$ComputerName,

        [PSCredential][System.Management.Automation.CredentialAttribute()]$Credential,

        [parameter(ParameterSetName = 'Full')]
        [switch]$Full,

        [ValidateRange(1, 65535)]
        [int]$Port,

        [System.Management.Automation.Remoting.PSSessionOption]$PSSessionOption,

        [parameter(Position=1,ParameterSetName = 'Tail')]
        [uint32]$Tail = 1,

        [uint16]$ThrottleLimit,
        
        [switch]$UseSSL
    )

    begin {

        $Command = $MyInvocation.MyCommand.Name

        $ComputerNames = @()

        $sb = {

            $Task = Get-ScheduledTask -TaskName $using:WU_TaskName -ErrorAction 'SilentlyContinue'

            if ($Task) {

                $Path = Join-Path -Path $Task.Actions.WorkingDirectory -ChildPath $using:WU_XmlLogFileName
                
                if (Test-Path $Path -PathType Leaf) {
                
                    $Import = Import-Clixml -Path $Path -ErrorAction 'Stop'

                    if ($using:Full) {$Import}

                    else {$Import | Select-Object -Last $using:Tail}
                }

                else {Write-Warning "[$env:COMPUTERNAME] $using:Command - No log file found."}
            }

            else {Write-Warning "[$env:COMPUTERNAME] $using:Command - No task named $using:WU_TaskName."}
        }
    }

    process {$ComputerNames += $ComputerName}

    end {

        $Invoke_Params = @{ScriptBlock = $sb ; ComputerName = $ComputerNames}
    
        if ($Credential) {$Invoke_Params += @{Credential = $Credential}}

        if ($ThrottleLimit) {$Invoke_Params += @{ThrottleLimit = $ThrottleLimit}}

        if ($Port) {$Invoke_Params += @{Port = $Port}}

        if ($UseSSL) {$Invoke_Params += @{UseSSL = $UseSSL}}

        if ($PSSessionOption) {$Invoke_Params += @{SessionOption = $PSSessionOption}}

        Invoke-Command @Invoke_Params | Select-Object @{l='ComputerName';e={$_.PSComputerName}}, TimeStamp, Level, Message
    }
}
Set-Alias -Name gzl -Value Get-zWULog

function Get-zWUTask {

    <#
    .NOTES
        ######################
         mail@nimbus117.co.uk
        ######################  
    .SYNOPSIS
        Get a windows update task.
    .DESCRIPTION
        Gets details of a windows update task. The details returned are the task State, LastRunTime and Parameters.
    .PARAMETER CimSessionOption
        Sets advanced options for the new CIM session. Enter the name of a CimSessionOption object created by using the New-CimSessionOption cmdlet.
    .PARAMETER ComputerName
        Specifies the computers on which the command runs.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER Port
        Specifies the network port on the remote computer that is used for this connection. To connect to a remote computer, the remote computer must be listening on the port that the connection uses. The default ports are 5985 (the WinRM port for HTTP) and 5986 (the WinRM port for HTTPS).
    .EXAMPLE
        PS C:\>Get-zWUTask SRV01

        ComputerName State LastRunTime         Parameters
        ------------ ----- -----------         ----------
        SRV01        Ready 29/07/2017 03:14:16 -AcceptEula -DownloadOnly

        This command returns the details for the update task on SRV01.

    .EXAMPLE
        PS C:\>Get-zWUTask 'SRV01', 'SRV02', 'SRV03', 'SRV04', 'SRV05', 'SRV06', 'CLIENT01'
        
        ComputerName State LastRunTime         Parameters
        ------------ ----- -----------         ----------
        SRV05        Ready 29/07/2017 03:14:17 -SearchOnly -UpdateType SecurityUpdates,CriticalUpdates
        SRV06        Ready 29/07/2017 03:14:15 -AcceptEula -AutoSelect -DownloadOnly
        CLIENT01     Ready 29/07/2017 03:14:17 -AcceptEula -SearchOnly -Service WindowsUpdate
        SRV02        Ready 29/07/2017 03:14:24 -SearchOnly -UpdateType SecurityUpdates,CriticalUpdates
        SRV01        Ready 29/07/2017 03:14:16 -AcceptEula -ExcludeKB KB2267602,KB890830 -Reboot
        SRV04        Ready 29/07/2017 03:14:19 -AcceptEula -AutoSelect -DownloadOnly
        SRV03        Ready 29/07/2017 03:14:19 -AcceptEula -ExcludeOptional -Reboot

    .LINK
        about_zWindowsUpdate
        Get-zWULog
        New-zWUTask
        Remove-zWUTask
        Start-zWUTask
        Stop-zWUTask
        Wait-zWUTask
    #>

    [cmdletbinding()]

    param(

        [Microsoft.Management.Infrastructure.Options.WSManSessionOptions]$CimSessionOption,
        
        [parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias('Name', 'PSComputerName')]
        [string[]]$ComputerName,

        [PSCredential][System.Management.Automation.CredentialAttribute()]$Credential,

        [ValidateRange(1, 65535)]
        [int]$Port
    )

    begin {$Command = $MyInvocation.MyCommand.Name}

    process {

        $Cim_Params = @{ComputerName = $ComputerName ; Name = ("$WU_TaskName-" + [guid]::NewGuid().Guid)}
    
        if ($Credential) {$Cim_Params += @{Credential = $Credential}}

        if ($Port) {$Cim_Params += @{Port = $Port}}

        if ($CimSessionOption) {$Cim_Params += @{SessionOption = $CimSessionOption}}

        $CimSession = New-CimSession @Cim_Params

        foreach ($Session in $CimSession) {

            $Task = Get-ScheduledTask -TaskName $WU_TaskName -CimSession $Session -ErrorAction 'SilentlyContinue'

            if ($Task) {

                $Task | Select-Object `
                    @{l='ComputerName';e={$_.PSComputerName}}, `
                    State, `
                    @{l='LastRunTime';e={($_ | Get-ScheduledTaskInfo).LastRunTime}}, `
                    @{l='Parameters';e={($_.Actions.Arguments -split ".ps1' ")[1].TrimEnd("`" > $WU_LogFileName 2>&1")}}
            }
            else {Write-Warning "[$($Session.ComputerName)] $Command - No task named $WU_TaskName."}
        }
    }

    end {Get-CimSession -Name "$WU_TaskName*" | Remove-CimSession}
}
Set-Alias -Name gzt -Value Get-zWUTask

function New-zWUTask {

    <#
    .NOTES
        ######################
         mail@nimbus117.co.uk
        ######################  
    .SYNOPSIS
        Creates a new windows update task.
    .DESCRIPTION
        Copies the zWUScript.ps1 script from this module to the remote or local computer and creates a scheduled task to run it. The task is created without a trigger. By default when the task is run the script will search for, download and install all software updates but will not reboot the computer if required.
    .PARAMETER AcceptEula
        Accept update EULA if needed.
    .PARAMETER AutoSelect
        Only include updates that are flagged to be automatically selected by Windows Update.
    .PARAMETER ComputerName
        Specifies the computers on which the command runs.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER DownloadOnly
        Download updates but do not install them.
    .PARAMETER ExcludeKB
        Exclude updates by KB number.
    .PARAMETER ExcludeOptional
        Exclude updates that are considered optional.
    .PARAMETER IncludeKB
        Include updates by KB number.
    .PARAMETER Port
        Specifies the network port on the remote computer that is used for this command. To connect to a remote computer, the remote computer must be listening on the port that the connection uses. The default ports are 5985, which is the WinRM port for HTTP, and 5986, which is the WinRM port for HTTPS.
    .PARAMETER PSSessionOption
        Specifies advanced options for the session. Enter a SessionOption object, such as one that you create by using the New-PSSessionOption cmdlet, or a hash table in which the keys are session option names and the values are session option values.
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
    .PARAMETER ThrottleLimit
        Specifies the maximum number of concurrent connections that can be established to run this command.
    .PARAMETER UseSSL
        Indicates that this cmdlet uses the Secure Sockets Layer (SSL) protocol to establish a connection to the remote computer. By default, SSL is not used.
    .PARAMETER UpdateType
        Specify which update types to search for, such as CriticalUpdates or SecurityUpdates. Possible values are 'Application', 'CriticalUpdates', 'Definitions', 'FeaturePacks', 'SecurityUpdates', 'ServicePacks', 'Tools', 'UpdateRollups', 'Updates'. The default is all software updates.
    .EXAMPLE
        PS C:\>New-zWUTask -ComputerName SRV01 -UpdateType CriticalUpdates,SecurityUpdates -Reboot | Start-zWUTask
        ComputerName TaskName
        ------------ --------
        SRV05        zWindowsUpdate
        This example shows how to create a windows update task on the remote computer SRV01 and start it. The task will search for, download and install security and critical updates then reboot the computer if needed.
    .EXAMPLE
        PS C:\>$Computers = (Get-ADComputer -Filter "name -like 'srv*'").Name
        PS C:\>$cred = Get-Credential

        PS C:\>New-zWUTask -ComputerName $Computers -Credential $cred -AutoSelect -SearchOnly

        ComputerName TaskName
        ------------ --------
        SRV05        zWindowsUpdate
        SRV01        zWindowsUpdate
        SRV02        zWindowsUpdate
        SRV03        zWindowsUpdate
        SRV04        zWindowsUpdate

        In this example tasks are created on multiple computers and are set to search for updates only.
        The first command uses the Get-ADComputer cmdlet to gather a list of computers and saves them in the variable $Computers.
        The Second command gets a credential object and saves it to the variable $cred
        The last command creates the tasks on the computers specified in the $Computers variable and uses the credentials specified in the $cred variable to authenticate the remote session.
    .EXAMPLE
        PS C:\>$Computers = 'srv01', 'srv02', 'srv03'
        PS C:\>New-zWUTask $Computers -AutoSelect -Reboot
        
        PS C:\>$Trigger = New-ScheduledTaskTrigger -At 03:00 -Weekly -DaysOfWeek Wednesday
        
        PS C:\>Set-ScheduledTask -TaskName zWindowsUpdate -Trigger $Trigger -CimSession $Computers

        In the above example a windows update task is created on the computers srv01, srv02 and srv03 and set to reboot the computer automatically if required. The builtin ScheduledTask cmdlets are then used to create and apply a trigger to the tasks so they run on a schedule. In this case every Wednesday at 3:00am.

    .EXAMPLE
        PS C:\>New-zWUTask $Computers -Confirm:$false -AutoSelect -ExcludeKB KB2267602,KB890830 -SearchOnly
        PS C:\>Start-zWUTask $Computers -Confirm:$false | Wait-zWUTask -Delay 30
    .LINK
        about_zWindowsUpdate
        Get-zWULog
        Get-zWUTask
        Remove-zWUTask
        Start-zWUTask
        Stop-zWUTask
        Wait-zWUTask
    #>

    [cmdletbinding(SupportsShouldProcess = $true,ConfirmImpact = 'High', DefaultParameterSetName = 'Install')]

    param(

        [parameter(ParameterSetName = 'DownloadOnly')]
        [parameter(ParameterSetName = 'Install')]
        [switch]$AcceptEula,

        [switch]$AutoSelect,

        [parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias('Name', 'PSComputerName')]
        [string[]]$ComputerName,

        [PSCredential][System.Management.Automation.CredentialAttribute()]$Credential,

        [parameter(ParameterSetName = 'DownloadOnly')]
        [switch]$DownloadOnly,

        [ValidateScript({$_ -match 'kb[0-9]{6,}'})]
        [string[]]$ExcludeKB,

        [switch]$ExcludeOptional,

        [ValidateScript({$_ -match 'kb[0-9]{6,}'})]
        [string[]]$IncludeKB,
        
        [ValidateRange(1, 65535)]
        [int]$Port,

        [System.Management.Automation.Remoting.PSSessionOption]$PSSessionOption,

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

        [uint16]$ThrottleLimit,
        
        [parameter(Position=1)]
        [ValidateSet('Application', 'CriticalUpdates', 'Definitions', 'FeaturePacks', 'SecurityUpdates', 'ServicePacks', 'Tools', 'UpdateRollups', 'Updates')]
        [ValidateNotNullOrEmpty()]
        [String[]]$UpdateType,

        [switch]$UseSSL
    )
    
    begin {

        $Command = $MyInvocation.MyCommand.Name

        if (($SmtpFrom -or $SmtpTo -or $SmtpServer) -and -not ($SmtpFrom -and $SmtpTo -and $SmtpServer)) {throw "$Command : Provide all -Smtp* parameters"}

        $ScriptFilePath = Join-Path -Path $WU_TaskWorkingDirectory -ChildPath $WU_ScriptFileName

        $ModulePath = (Get-Module $MyInvocation.MyCommand.ModuleName).ModuleBase

        $UpdateScript = Get-Content "$ModulePath\$WU_ScriptFileName"

        $Argument = "-NoProfile -ExecutionPolicy Bypass -Command `"& '$ScriptFilePath'"

        switch ($true) {

            $AcceptEula {$Argument += ' -AcceptEula'}

            $AutoSelect {$Argument += ' -AutoSelect'}

            $DownloadOnly {$Argument += ' -DownloadOnly'}

            ($ExcludeKB -as [bool]) {$Argument += ' -ExcludeKB ' ; $ExcludeKB | ForEach-Object {$Argument += "$_,"} ; $Argument = $Argument.TrimEnd(',')}

            $ExcludeOptional {$Argument += ' -ExcludeOptional'}

            ($IncludeKB -as [bool]) {$Argument += ' -IncludeKB ' ; $IncludeKB | ForEach-Object {$Argument += "$_,"} ; $Argument = $Argument.TrimEnd(',')}

            $Reboot {$Argument += ' -Reboot'}

            $SearchOnly {$Argument += ' -SearchOnly'}
    
            ($Service -as [bool]) {$Argument += " -Service $Service"}

            ($SmtpFrom -as [bool]) {$Argument += " -SmtpFrom $($SmtpFrom.Address)"}

            ($SmtpTo -as [bool]) {$Argument += " -SmtpTo $($SmtpTo.Address)"}

            ($SmtpServer -as [bool]) {$Argument += " -SmtpServer $SmtpServer"}

            ($UpdateType.Count -gt 0) {$Argument += ' -UpdateType ' ; $UpdateType | ForEach-Object {$Argument += "$_,"} ; $Argument = $Argument.TrimEnd(',')}
        }

        $Argument += "`" > $WU_LogFileName 2>&1"

        $sb = {

            $Task = Get-ScheduledTask -TaskName $using:WU_TaskName -ErrorAction 'SilentlyContinue'

            if ($Task.State -ne 'Running') {
        
                if (-not(Test-Path $using:WU_TaskWorkingDirectory -PathType Container)) {mkdir $using:WU_TaskWorkingDirectory -Force | Out-Null}

                $using:UpdateScript | Out-File $using:ScriptFilePath -Force

                $Action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument $Using:Argument -WorkingDirectory $using:WU_TaskWorkingDirectory

                Register-ScheduledTask -Action $Action -User 'System' -TaskName $using:WU_TaskName -Description $using:WU_TaskDescription -RunLevel Highest -Force
            }

            else {Write-Warning "[$env:COMPUTERNAME] $using:Command - Task is running."}
        }
    }

    process {$ComputerNames += $ComputerName}

    end {

        if ($PSCmdlet.ShouldProcess($ComputerNames,'Create new windows update task')) {

            $Invoke_Params = @{ScriptBlock = $sb ; ComputerName = $ComputerNames}
    
            if ($Credential) {$Invoke_Params += @{Credential = $Credential}}

            if ($ThrottleLimit) {$Invoke_Params += @{ThrottleLimit = $ThrottleLimit}}

            if ($Port) {$Invoke_Params += @{Port = $Port}}

            if ($UseSSL) {$Invoke_Params += @{UseSSL = $UseSSL}}

            if ($PSSessionOption) {$Invoke_Params += @{SessionOption = $PSSessionOption}}

            Invoke-Command @Invoke_Params | Select-Object @{l='ComputerName';e={$_.PSComputerName}}, TaskName
        }
    }
}
Set-Alias -Name nzt -Value New-zWUTask

function Remove-zWUTask {

    <#
    .NOTES
        ######################
         mail@nimbus117.co.uk
        ######################  
    .SYNOPSIS
        Removes a windows update task.
    .DESCRIPTION
        Removes the scheduled task and deletes the task working directory.
    .PARAMETER ComputerName
        Specifies the computers on which the command runs.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER Port
        Specifies the network port on the remote computer that is used for this command. To connect to a remote computer, the remote computer must be listening on the port that the connection uses. The default ports are 5985, which is the WinRM port for HTTP, and 5986, which is the WinRM port for HTTPS.
    .PARAMETER PSSessionOption
        Specifies advanced options for the session. Enter a SessionOption object, such as one that you create by using the New-PSSessionOption cmdlet, or a hash table in which the keys are session option names and the values are session option values.
    .PARAMETER ThrottleLimit
        Specifies the maximum number of concurrent connections that can be established to run this command.
    .PARAMETER UseSSL
        Indicates that this cmdlet uses the Secure Sockets Layer (SSL) protocol to establish a connection to the remote computer. By default, SSL is not used.
    .EXAMPLE
        PS C:\>Remove-zWUTask SRV01
    .EXAMPLE
        PS C:\>Remove-zWUTask -ComputerName (Get-ADComputer -Filter "name -like 'srv*'").Name -Confirm:$false
    .LINK
        about_zWindowsUpdate
        Get-zWULog
        Get-zWUTask
        New-zWUTask
        Start-zWUTask
        Stop-zWUTask
        Wait-zWUTask
    #>

    [cmdletbinding(SupportsShouldProcess = $true,ConfirmImpact = 'High')]

    param(
        
        [parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias('Name', 'PSComputerName')]
        [string[]]$ComputerName,

        [PSCredential][System.Management.Automation.CredentialAttribute()]$Credential,

        [ValidateRange(1, 65535)]
        [int]$Port,

        [System.Management.Automation.Remoting.PSSessionOption]$PSSessionOption,

        [uint16]$ThrottleLimit,
        
        [switch]$UseSSL
    )

    begin {
        
        $Command = $MyInvocation.MyCommand.Name

        $sb = {

            $Task = Get-ScheduledTask -TaskName $using:WU_TaskName -ErrorAction 'SilentlyContinue'

            if ($Task) {

                if ($Task.State -ne 'Running') {

                    Remove-Item $Task.Actions.WorkingDirectory -Recurse -Force -Confirm:$false

                    $Task | Unregister-ScheduledTask -Confirm:$false
                }

                else {Write-Warning "[$env:COMPUTERNAME] $using:Command - Task is running."}
            }

            else {Write-Warning "[$env:COMPUTERNAME] $using:Command - No task named $using:WU_TaskName."}
        }
    }

    process {$ComputerNames += $ComputerName}

    end {

        if ($PSCmdlet.ShouldProcess($ComputerNames,'Remove windows update task')) {

            $Invoke_Params = @{ScriptBlock = $sb ; ComputerName = $ComputerNames}
    
            if ($Credential) {$Invoke_Params += @{Credential = $Credential}}

            if ($ThrottleLimit) {$Invoke_Params += @{ThrottleLimit = $ThrottleLimit}}

            if ($Port) {$Invoke_Params += @{Port = $Port}}

            if ($UseSSL) {$Invoke_Params += @{UseSSL = $UseSSL}}

            if ($PSSessionOption) {$Invoke_Params += @{SessionOption = $PSSessionOption}}

            Invoke-Command @Invoke_Params
        }
    }
}
Set-Alias -Name rzt -Value Remove-zWUTask

function Start-zWUTask {

    <#
    .NOTES
        ######################
         mail@nimbus117.co.uk
        ######################  
    .SYNOPSIS
        Start a windows update task.
    .DESCRIPTION
        Start a windows update task.
    .PARAMETER CimSessionOption
        Sets advanced options for the new CIM session. Enter the name of a CimSessionOption object created by using the New-CimSessionOption cmdlet.
    .PARAMETER ComputerName
        Specifies the computers on which the command runs.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER Port
        Specifies the network port on the remote computer that is used for this connection. To connect to a remote computer, the remote computer must be listening on the port that the connection uses. The default ports are 5985 (the WinRM port for HTTP) and 5986 (the WinRM port for HTTPS).
    .EXAMPLE
        Start-zWUTask 192.168.0.236 -Credential $cred
    .EXAMPLE
        New-zWUTask 'srv01', 'srv02' -Confirm:$false | Start-zWUTask -Confirm:$false
    .LINK
        about_zWindowsUpdate
        Get-zWULog
        Get-zWUTask
        New-zWUTask
        Remove-zWUTask
        Stop-zWUTask
        Wait-zWUTask
    #>
    
    [cmdletbinding(SupportsShouldProcess = $true,ConfirmImpact = 'High')]
        
    param(

        [Microsoft.Management.Infrastructure.Options.WSManSessionOptions]$CimSessionOption,
        
        [parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias('Name', 'PSComputerName')]
        [string[]]$ComputerName,

        [PSCredential][System.Management.Automation.CredentialAttribute()]$Credential,

        [ValidateRange(1, 65535)]
        [int]$Port
    )

    begin {$Command = $MyInvocation.MyCommand.Name}
    
    process {

        if ($PSCmdlet.ShouldProcess($ComputerName,'Start windows update task')) {

            $Cim_Params = @{ComputerName = $ComputerName ; Name = ("$WU_TaskName-" + [guid]::NewGuid().Guid)}
    
            if ($Credential) {$Cim_Params += @{Credential = $Credential}}

            if ($Port) {$Cim_Params += @{Port = $Port}}

            if ($CimSessionOption) {$Cim_Params += @{SessionOption = $CimSessionOption}}

            $CimSession = New-CimSession @Cim_Params

            foreach ($Session in $CimSession) {

                $Task = Get-ScheduledTask -TaskName $WU_TaskName -CimSession $Session -ErrorAction 'SilentlyContinue'

                if ($Task) {

                    if ($Task.State -ne 'Running') {

                        $Task | Start-ScheduledTask | Out-Null

                        $Task | Get-ScheduledTask | Select-Object @{l='ComputerName';e={$_.PSComputerName}}, State
                    }

                    else {Write-Warning "[$($Session.ComputerName)] $Command - Task is already running."}
                }
                else {Write-Warning "[$($Session.ComputerName)] $Command - No task named $WU_TaskName."}
            }
        }
    }

    end {Get-CimSession -Name "$WU_TaskName*" | Remove-CimSession}
}
Set-Alias -Name szt -Value Start-zWUTask

function Stop-zWUTask {

    <#
    .NOTES
        ######################
         mail@nimbus117.co.uk
        ######################  
    .SYNOPSIS
        Stop a windows update task.
    .DESCRIPTION
        Stop a windows update task.
    .PARAMETER CimSessionOption
        Sets advanced options for the new CIM session. Enter the name of a CimSessionOption object created by using the New-CimSessionOption cmdlet.
    .PARAMETER ComputerName
        Specifies the computers on which the command runs.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER Port
        Specifies the network port on the remote computer that is used for this connection. To connect to a remote computer, the remote computer must be listening on the port that the connection uses. The default ports are 5985 (the WinRM port for HTTP) and 5986 (the WinRM port for HTTPS).
    .EXAMPLE
        Stop-zWUTask -ComputerName 192.168.0.236 -Credential $cred
    .EXAMPLE
        Stop-zWUtask $Computers -Confirm:$false
    .LINK
        about_zWindowsUpdate
        Get-zWULog
        Get-zWUTask
        New-zWUTask
        Remove-zWUTask
        Start-zWUTask
        Wait-zWUTask
    #>

    [cmdletbinding(SupportsShouldProcess = $true,ConfirmImpact = 'High')]

    param(
        
        [Microsoft.Management.Infrastructure.Options.WSManSessionOptions]$CimSessionOption,

        [parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias('Name', 'PSComputerName')]
        [string[]]$ComputerName,

        [PSCredential][System.Management.Automation.CredentialAttribute()]$Credential,

        [ValidateRange(1, 65535)]
        [int]$Port
    )

    begin {$Command = $MyInvocation.MyCommand.Name}
    
    process {

        if ($PSCmdlet.ShouldProcess($ComputerName,'Stop windows update task')) {

            $Cim_Params = @{ComputerName = $ComputerName ; Name = ("$WU_TaskName-" + [guid]::NewGuid().Guid)}
    
            if ($Credential) {$Cim_Params += @{Credential = $Credential}}

            if ($Port) {$Cim_Params += @{Port = $Port}}

            if ($CimSessionOption) {$Cim_Params += @{SessionOption = $CimSessionOption}}

            $CimSession = New-CimSession @Cim_Params

            foreach ($Session in $CimSession) {

                $Task = Get-ScheduledTask -TaskName $WU_TaskName -CimSession $Session -ErrorAction 'SilentlyContinue'

                if ($Task) {

                    if ($Task.State -eq 'Running') {

                        $Task | Stop-ScheduledTask | Out-Null

                        $Task | Get-ScheduledTask | Select-Object @{l='ComputerName';e={$_.PSComputerName}}, State
                    }

                    else {Write-Warning "[$($Session.ComputerName)] $Command - Task is not running."}
                }
                else {Write-Warning "[$($Session.ComputerName)] $Command - No task named $WU_TaskName."}
            }
        }
    }

    end {Get-CimSession -Name "$WU_TaskName*" | Remove-CimSession}
}
Set-Alias -Name spzt -Value Stop-zWUTask

function Wait-zWUTask {

    <#
    .NOTES
        ######################
         mail@nimbus117.co.uk
        ######################  
    .SYNOPSIS
        Waits for a windows update task to finish.
    .DESCRIPTION
        Checks the state of the windows update tasks on the specified computers and waits until they are all complete before continuing the pipeline.
    .PARAMETER CimSessionOption
            Sets advanced options for the new CIM session. Enter the name of a CimSessionOption object created by using the New-CimSessionOption cmdlet.
    .PARAMETER ComputerName
        Specifies the computers on which the command runs.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER Delay
        The interval between checking the state of the task in seconds. The default is 60 seconds.
    .PARAMETER Port
        Specifies the network port on the remote computer that is used for this connection. To connect to a remote computer, the remote computer must be listening on the port that the connection uses. The default ports are 5985 (the WinRM port for HTTP) and 5986 (the WinRM port for HTTPS).
    .PARAMETER Silent
        Hide the progress bar.
    .EXAMPLE
        PS C:\>$Computers = (Get-ADComputer -Filter "name -like 'srv*'").Name

        PS C:\>Wait-zWUTask -ComputerName $Computers

        ComputerName State
        ------------ -----
        SRV01        Ready
        SRV02        Ready
        SRV03        Ready
        SRV04        Ready

    .EXAMPLE
        New-zWUTask $Computers -SearchOnly | Start-zWUTask | Wait-zWUTask -Delay 30 | Get-zWULog -Full | Out-GridView
    .LINK
        about_zWindowsUpdate
        Get-zWULog
        Get-zWUTask
        New-zWUTask
        Remove-zWUTask
        Start-zWUTask
        Stop-zWUTask
    #>

    [cmdletbinding()]

    param(

        [Microsoft.Management.Infrastructure.Options.WSManSessionOptions]$CimSessionOption,

        [parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias('Name', 'PSComputerName')]
        [string[]]$ComputerName,

        [PSCredential][System.Management.Automation.CredentialAttribute()]$Credential,

        [parameter(Position=1)]
        [ValidateRange(10,300)]
        [uint32]$Delay = 60,

        [ValidateRange(1, 65535)]
        [int]$Port,

        [switch]$Silent
    )

    begin {$ComputerNames = @()}

    process {$ComputerNames += $ComputerName}

    end {

        $TotalCount = ($ComputerNames | Measure-Object).Count

        $RunningCount = $TotalCount

        $Cim_Params = @{ComputerName = $ComputerNames ; Name = ("$WU_TaskName-" + [guid]::NewGuid().Guid)}
    
        if ($Credential) {$Cim_Params += @{Credential = $Credential}}

        if ($Port) {$Cim_Params += @{Port = $Port}}

        if ($CimSessionOption) {$Cim_Params += @{SessionOption = $CimSessionOption}}

        $CimSession = New-CimSession @Cim_Params

        if ($CimSession) {

            $Waiting = $true

            while ($Waiting) {

                if (-not $Silent) {
            
                    Write-Progress `
                        -Activity 'Wait-zWUTask' -CurrentOperation 'Checking task state' `
                        -Status "$($TotalCount - $RunningCount) of $TotalCount complete" `
                        -PercentComplete ((($TotalCount - $RunningCount) / $TotalCount) * 100)
                }
            
                $Tasks = Get-ScheduledTask -TaskName $WU_TaskName -CimSession $CimSession

                if ($Tasks.State -contains 'Running') {
            
                    $RunningCount = ($Tasks | Where-Object {$_.State -eq 'Running'} | Measure-Object).Count

                    if (-not $Silent) {
                
                        Write-Progress `
                            -Activity 'Wait-zWUTask' -CurrentOperation "Waiting $Delay seconds" `
                            -Status "$($TotalCount - $RunningCount) of $TotalCount complete" `
                            -PercentComplete ((($TotalCount - $RunningCount) / $TotalCount) * 100)
                    }

                    Start-Sleep $Delay
                }

                else {$Waiting = $false}
            }

            if (-not $Silent) {Write-Progress -Activity 'Wait-zWUTask' -Completed}

            $Tasks | Select-Object @{l='ComputerName';e={$_.PSComputerName}}, @{l='State';e={$_.State.ToString()}} | 
        
            Sort-Object ComputerName

            Get-CimSession -Name "$WU_TaskName*" | Remove-CimSession
        }
    }
}
Set-Alias -Name wzt -Value Wait-zWUTask

Export-ModuleMember -Function * -Alias *