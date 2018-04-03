# zWindowsUpdate

The idea behind the module was to have a way to manually run Windows Update on groups of servers in a controlled fashion.
The module consists of 2 parts, the zWUScript.ps1 script and the &ast;-zWU&ast; functions.
The script does the actual work of installing updates and can be used on its own without the functions.
The functions use PSSessions and CimSessions to create and control scheduled tasks that run the script.

### Example

Below is an example of how to update a handful of remote computers.
In this case the tasks will automatically select which updates to download and install.

```PowerShell
    $comp = 'SRV01', 'SRV02', 'SRV03', 'SRV04', 'SRV05', 'SRV06'
    
    New-zWUTask -ComputerName $comp -AutoSelect
    Start-zWUTask -ComputerName $comp

    # or using the pipeline

    New-zWUTask -ComputerName $comp -AutoSelect | Start-zWUTask
```

You can use the `Wait-zWUTask` function to show a progress bar and wait until all tasks are complete.

```PowerShell
    New-zWUTask -ComputerName $comp -AutoSelect | Start-zWUTask | Wait-zWUtask
```

Then use the `Get-zWULog` function to review the latest log entry from each task.

```PowerShell
    Get-zWULog -ComputerName $comp

    ComputerName Timestamp           Level   Message
    ------------ ---------           -----   -------
    SRV06        29/07/2017 04:38:40 Warning Finished - Reboot required - 24 of 24 update(s) installed
    SRV02        29/07/2017 03:20:55 Warning Finished - Reboot required - 24 of 24 update(s) installed
    SRV01        29/07/2017 03:14:16 Warning Finished - Reboot required - 24 of 24 update(s) installed
    SRV04        29/07/2017 03:20:55 Warning Finished - Reboot required - 24 of 24 update(s) installed
    SRV03        29/07/2017 03:10:19 Info    Finished - No reboot required - 1 of 1 update(s) installed
    SRV05        29/07/2017 03:10:17 Info    Finished - No reboot required - 1 of 1 update(s) installed
```

Rolling it all together.

```PowerShell
    New-zWUTask -ComputerName $comp -AutoSelect | Start-zWUTask | Wait-zWUtask | Get-zWULog

    # or the shorthand way also suppressing the prompts for confirmation

    nzt $comp -con:0 -au | szt -con:0 | wzt | gzl
```

If a reboot is required to finish installing updates you can use the `Restart-Computer` Cmdlet.

```PowerShell
    Restart-Computer -ComputerName SRV01,SRV02,SRV04,SRV06 -Force -Wait
```

Alternatively you can set a task to reboot automatically after updates are installed.

```PowerShell
    New-zWUTask -ComputerName $comp -Confirm:$false -AutoSelect -Reboot | 
    Start-zWUTask -Confirm:$false
```

### More Examples

```PowerShell
    # Use the Get-ADComputer and Out-GridView Cmdlets to select which computers to update
    $comp = (Get-ADComputer -Filter "name -like 'SRV*'").Name | Out-GridView -PassThru

    # The -Service parameter can be useful for bypassing WSUS
    New-zWUTask -ComputerName $comp -Service WindowsUpdate

    # Filter by update type and exclude a given KB number
    New-zWUTask $comp -UpdateType CriticalUpdates,SecurityUpdates,Definitions -ExcludeKB KB2267602

    # Use the -SearchOnly parameter to see what updates are needed
    New-zWUTask -ComputerName $comp -Confirm:$false -SearchOnly

    # Use the -Full parameter to view the full log for a task
    Get-zWULog 10.10.10.10 -Credential $cred -Full

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

    # When viewing full logs from multiple computers the filtering capabilities of Out-GridView can be helpful
    Get-zWULog $comp -Full | Out-GridView

    # Use Get-zWULog and Out-Gridview to select which computers to restart
    $Restart = (gzl $comp | ogv -pas).ComputerName
    Restart-Computer -ComputerName $Restart -Force -Wait

    # Remove the task and script files
    Remove-zWUTask -ComputerName $comp
```

### Installation

The module is available from the [PowerShell Gallery](https://www.powershellgallery.com/packages/zWindowsUpdate "zWindowsUpdate") or you can download and extract the zip file from [here](https://github.com/nimbus117/zWindowsUpdate/archive/master.zip "master.zip").

```PowerShell
    Install-Module -Name zWindowsUpdate -Scope CurrentUser

    # or

    Start-BitsTransfer https://github.com/nimbus117/zWindowsUpdate/archive/master.zip
    Expand-Archive .\master.zip .
    Import-Module .\zWindowsUpdate-master\zWindowsUpdate.psd1
```

Run `help about_zWindowsUpdate` and `help <Function-Name> -Full` to see more examples and a description of the available parameters.