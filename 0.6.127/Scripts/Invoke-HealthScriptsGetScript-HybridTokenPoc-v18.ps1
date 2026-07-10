<#
Hybrid POC v17: HealthScripts GetScript through IME AgentCommon with user WAM token + optional SYSTEM host. Adds tuple-result diagnostics, traffic gateway default, and stricter GetScript session shape.

This is read only. It only asks for GetScript. It does not send PolicyResult and it does not upload remediation output.

Why this exists:
  The normal downloader WAM and MDM cert flow works for app workloads.
  Raw GetScript HTTP kept failing because HealthScripts uses the IME AgentCommon path.
  This version uses the working downloader WAM token, injects it into AgentCommon as IClientTokenManager,
  and lets AgentCommon/ScriptPlugIn build and send the HealthScripts GetScript request.
#>

[CmdletBinding()]
param(
    [string]$HealthScriptId,
    [int]$SessionId = -999,
    [string]$UserId,
    [string]$ImePath = "C:\Program Files (x86)\Microsoft Intune Management Extension",
    [string]$HealthScriptsLog = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\HealthScripts.log",
    [string]$MdmCertThumbprint,
    [string]$SideCarEndpoint,
    [switch]$PreferDirectEndpoint,
    [switch]$SilentOnly,
    [switch]$NoStaRelaunch,
    [switch]$SkipPolicyProxy,
    [switch]$RunAsSystem,
    [switch]$SystemChild,
    [string]$AccessTokenFile,
    [switch]$WaitAtEnd,
    [string]$OutputFolder = (Join-Path $env:TEMP "HealthScripts-AgentCommon-HybridToken-Poc")
)

$ErrorActionPreference = "Stop"

# AgentCommon and ScriptPlugIn are x86. WAM also behaves better from STA.
if ([Environment]::Is64BitProcess -or ((-not $NoStaRelaunch) -and [System.Threading.Thread]::CurrentThread.GetApartmentState() -ne [System.Threading.ApartmentState]::STA)) {
    $ps32 = Join-Path $env:WINDIR 'SysWOW64\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $ps32)) { throw "32 bit PowerShell not found: $ps32" }

    $argList = New-Object System.Collections.Generic.List[string]
    $argList.Add('-NoProfile')
    $argList.Add('-STA')
    $argList.Add('-ExecutionPolicy')
    $argList.Add('Bypass')
    $argList.Add('-File')
    $argList.Add($PSCommandPath)
    $argList.Add('-NoStaRelaunch')

    foreach ($kvp in $PSBoundParameters.GetEnumerator()) {
        if ($kvp.Key -eq 'NoStaRelaunch') { continue }
        $value = $kvp.Value
        if ($value -is [switch]) {
            if ($value.IsPresent) { $argList.Add("-$($kvp.Key)") }
            continue
        }
        if ($null -ne $value) {
            $argList.Add("-$($kvp.Key)")
            $argList.Add([string]$value)
        }
    }

    Write-Host "[POC] Relaunching in 32 bit STA Windows PowerShell in the same console..."
    & $ps32 @($argList.ToArray())
    $childExitCode = $LASTEXITCODE
    Write-Host "[POC] 32 bit child finished with exit code $childExitCode"
    if ($WaitAtEnd) { [void](Read-Host 'Press Enter to close') }
    exit $childExitCode
}

$script:SideCarClientId = "fc0f3af4-6835-4174-b806-f7db311fd2f3"
$script:SideCarResource = "26a4ae64-5862-427f-a9b0-044e62572a4f"
$script:MdmCertThumbprint = $MdmCertThumbprint
$script:HealthScriptsLog = $HealthScriptsLog
$script:SideCarEndpoint = $SideCarEndpoint
$script:SilentOnly = $SilentOnly

function Write-Step {
    param([string]$Message)
    Write-Host "[POC] $Message"
}

try {
    if (-not (Test-Path -LiteralPath $OutputFolder)) {
        $null = New-Item -ItemType Directory -Path $OutputFolder -Force
    }
    $script:TranscriptPath = Join-Path $OutputFolder ("hybrid_poc_transcript_{0}.txt" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    Start-Transcript -Path $script:TranscriptPath -Force | Out-Null
    Write-Step "Transcript: $script:TranscriptPath"
}
catch {
    Write-Host "[POC] Could not start transcript: $($_.Exception.Message)"
}

trap {
    Write-Host "[POC] FATAL: $($_.Exception.Message)" -ForegroundColor Red
    try {
        if ($script:TranscriptPath) { Write-Host "[POC] Transcript: $script:TranscriptPath" }
        Stop-Transcript | Out-Null
    } catch { }
    if ($WaitAtEnd) { [void](Read-Host 'Press Enter to close') }
    break
}

function New-FolderIfMissing {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        $null = New-Item -ItemType Directory -Path $Path -Force
    }
}

function Test-HSIsSystem {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return ($id.User.Value -eq 'S-1-5-18')
    }
    catch { return $false }
}

function Test-HSIsAdmin {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { return $false }
}

function Start-HSSystemChild {
    param(
        [string]$TokenFile,
        [int]$SessionId,
        [string]$UserId,
        [string]$ResolvedEndpoint,
        [string]$CertThumbprint,
        [string]$AgentImePath,
        [string]$LogPath,
        [string]$OutFolder,
        [string]$PolicyId,
        [switch]$SkipProxy
    )

    if (-not (Test-HSIsAdmin)) {
        throw 'Run elevated. Creating the SYSTEM scheduled task requires admin rights.'
    }

    $ps32 = Join-Path $env:WINDIR 'SysWOW64\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $ps32)) { throw "32 bit PowerShell not found: $ps32" }

    $taskName = 'HealthScriptsGetScriptHybrid-' + ([Guid]::NewGuid().ToString('N'))
    $argList = New-Object System.Collections.Generic.List[string]
    $argList.Add('-NoProfile')
    $argList.Add('-STA')
    $argList.Add('-ExecutionPolicy')
    $argList.Add('Bypass')
    $argList.Add('-File')
    $argList.Add($PSCommandPath)
    $argList.Add('-NoStaRelaunch')
    $argList.Add('-SystemChild')
    $argList.Add('-AccessTokenFile')
    $argList.Add($TokenFile)
    $argList.Add('-SessionId')
    $argList.Add([string]$SessionId)
    $argList.Add('-UserId')
    $argList.Add($UserId)
    $argList.Add('-ImePath')
    $argList.Add($AgentImePath)
    $argList.Add('-HealthScriptsLog')
    $argList.Add($LogPath)
    $argList.Add('-MdmCertThumbprint')
    $argList.Add($CertThumbprint)
    $argList.Add('-SideCarEndpoint')
    $argList.Add($ResolvedEndpoint)
    $argList.Add('-OutputFolder')
    $argList.Add($OutFolder)

    if ($PolicyId) {
        $argList.Add('-HealthScriptId')
        $argList.Add($PolicyId)
    }
    if ($SkipProxy) { $argList.Add('-SkipPolicyProxy') }

    $quotedArgs = ($argList.ToArray() | ForEach-Object {
        if ($_ -match '[\s"'']') { '"' + ($_ -replace '"','\"') + '"' } else { $_ }
    }) -join ' '

    $systemRunInfo = [ordered]@{
        TaskName = $taskName
        Script = $PSCommandPath
        PowerShell = $ps32
        Arguments = $quotedArgs
        TokenFile = $TokenFile
        SessionId = $SessionId
        UserId = $UserId
        Endpoint = $ResolvedEndpoint
        Started = (Get-Date).ToString('o')
    }
    $systemRunInfoPath = Join-Path $OutFolder 'system_child_launch.json'
    $systemRunInfo | ConvertTo-Json -Depth 10 | Set-Content -Path $systemRunInfoPath -Encoding UTF8
    Write-Step "SYSTEM child launch info: $systemRunInfoPath"

    $action = New-ScheduledTaskAction -Execute $ps32 -Argument $quotedArgs
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(3)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

    try {
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
        Start-ScheduledTask -TaskName $taskName
        Write-Step "Started SYSTEM task: $taskName"

        $deadline = (Get-Date).AddMinutes(10)
        do {
            Start-Sleep -Seconds 2
            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if (-not $task) { break }
            $info = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
            Write-Host ("[POC] SYSTEM task state: {0}; LastTaskResult: {1}" -f $task.State, $info.LastTaskResult)
        } while ($task.State -eq 'Running' -and (Get-Date) -lt $deadline)

        $info = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
        if ($info) {
            Write-Step "SYSTEM task completed. LastTaskResult: $($info.LastTaskResult)"
        }
    }
    finally {
        try { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch { }
    }

    Write-Step "Output folder: $OutFolder"
    Get-ChildItem -LiteralPath $OutFolder -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 12 FullName,LastWriteTime,Length |
        Format-Table -AutoSize
}

function Get-IntuneManagementExtensionVersion {
    $paths = @(
        "C:\Program Files (x86)\Microsoft Intune Management Extension\Microsoft.Management.Services.IntuneWindowsAgent.exe",
        "C:\Program Files\Microsoft Intune Management Extension\Microsoft.Management.Services.IntuneWindowsAgent.exe"
    )

    foreach ($path in $paths) {
        if (Test-Path -LiteralPath $path) {
            try {
                $item = Get-Item -LiteralPath $path
                if ($item.VersionInfo.ProductVersion) { return $item.VersionInfo.ProductVersion }
                if ($item.VersionInfo.FileVersion) { return $item.VersionInfo.FileVersion }
            }
            catch { }
        }
    }

    return "1.91.102.0"
}

function Get-WindowsSkuValue {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        return [string]$os.OperatingSystemSKU
    }
    catch {
        return ""
    }
}

function Get-DotNetReleaseValue {
    try {
        $key = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction Stop
        if ($key.Release) { return [string]$key.Release }
    }
    catch { }

    return ""
}

function New-SideCarClientInfoJson {
    param([string]$SideCarAgentVersion)

    $osVersion = [Environment]::OSVersion.Version

    $extendedInventoryMap = [ordered]@{
        OperatingSystemRevisionNumber = if ($osVersion.Revision -ge 0) { [string]$osVersion.Revision } else { "" }
        SKU                           = Get-WindowsSkuValue
        DotNetFrameworkReleaseValue   = Get-DotNetReleaseValue
    }

    $clientInfo = [ordered]@{
        DeviceName                    = [Environment]::MachineName
        OperatingSystemVersion        = "{0}.{1}.{2}" -f $osVersion.Major, $osVersion.Minor, $osVersion.Build
        SideCarAgentVersion           = $SideCarAgentVersion
        Win10SMode                    = $false
        UnlockWin10SModeTenantId      = $null
        UnlockWin10SModeDeviceId      = $null
        ChannelUriInformation         = $null
        AgentExecutionHistory         = [ordered]@{
            LastAgentExecutionStartTime = $null
            LastAgentExecutionEndTime   = $null
            AgentCrashCount             = $null
        }
        AgentExecutionStartTime       = $null
        AgentExecutionEndTime         = $null
        AgentCrashSeen                = $false
        ExtendedInventoryMap          = $extendedInventoryMap
    }

    return ($clientInfo | ConvertTo-Json -Depth 20 -Compress)
}


function Get-WindowsRuntimeBridgePathCandidates {
    $candidates = New-Object System.Collections.Generic.List[string]

    if ($env:WINDIR) {
        foreach ($frameworkRoot in @(
            (Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319"),
            (Join-Path $env:WINDIR "Microsoft.NET\Framework\v4.0.30319")
        )) {
            if ([string]::IsNullOrWhiteSpace($frameworkRoot)) { continue }

            $path = Join-Path $frameworkRoot "System.Runtime.WindowsRuntime.dll"
            if (-not $candidates.Contains($path)) {
                $candidates.Add($path)
            }
        }
    }

    foreach ($asm in [AppDomain]::CurrentDomain.GetAssemblies()) {
        try {
            if ($asm.GetName().Name -eq "System.Runtime.WindowsRuntime" -and -not [string]::IsNullOrWhiteSpace($asm.Location)) {
                if (-not $candidates.Contains($asm.Location)) {
                    $candidates.Add($asm.Location)
                }
            }
        }
        catch { }
    }

    return $candidates.ToArray()
}


$script:WamProviderUrl = 'https://login.microsoft.com'
$script:WamAuthority = 'https://login.microsoftonline.com/common'
$script:WamProvider = $null
$script:WamProviderAuthority = $null
$script:WamWebAccount = $null
$script:WamUserId = $null
$script:WamAsTaskMethod = $null
$script:WamWinRTRuntimePath = $null
$script:WamDesktopInteropReady = $false
$script:WamTProvider = $null
$script:WamTTokenResult = $null
$script:WamTTokenResultAsyncOperationGuid = $null
$script:WamWinRTInitialized = $false

function Write-TestLog {
    param(
        [ValidateSet('INFO','VERB','WARN','ERR')]
        [string]$Level = 'INFO',

        [string]$Category = 'WAM',

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Step "[$Level][$Category] $Message"
}

function Initialize-WinRT {
    if ($script:WamWinRTInitialized) { return }

    $clrDir = [Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
    $rtPath = Join-Path $clrDir 'System.Runtime.WindowsRuntime.dll'

    if (-not (Test-Path -LiteralPath $rtPath)) {
        $rtPath = Get-ChildItem 'C:\Windows\Microsoft.NET' -Recurse -Filter 'System.Runtime.WindowsRuntime.dll' -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending |
            Select-Object -First 1 -ExpandProperty FullName
    }

    if (-not $rtPath) {
        throw 'Cannot locate System.Runtime.WindowsRuntime.dll.'
    }

    $asm = [Reflection.Assembly]::LoadFrom($rtPath)
    $script:WamWinRTRuntimePath = $rtPath
    Write-TestLog VERB WAM "Loaded: $rtPath"

    $extType = $null

    foreach ($typeName in @('System.WindowsRuntimeSystemExtensions','System.Runtime.WindowsRuntime.WindowsRuntimeSystemExtensions')) {
        $extType = $asm.GetType($typeName, $false)
        if ($null -ne $extType) { break }
    }

    if ($null -eq $extType) {
        $extType = $asm.GetTypes() |
            Where-Object { $_.FullName -like '*WindowsRuntimeSystemExtensions' } |
            Select-Object -First 1
    }

    if ($null -eq $extType) {
        throw 'WindowsRuntimeSystemExtensions not found.'
    }

    $bf = [Reflection.BindingFlags]'Public,Static'
    $script:WamAsTaskMethod = $extType.GetMethods($bf) |
        Where-Object {
            $_.Name -eq 'AsTask' -and
            $_.IsGenericMethod -and
            $_.GetGenericArguments().Count -eq 1 -and
            $_.GetParameters().Count -eq 1
        } |
        Select-Object -First 1

    if ($null -eq $script:WamAsTaskMethod) {
        throw "AsTask<T> overload not found on $($extType.FullName)."
    }

    $null = [Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager, Windows.Security.Authentication.Web.Core, ContentType=WindowsRuntime]
    $null = [Windows.Security.Authentication.Web.Core.WebTokenRequest, Windows.Security.Authentication.Web.Core, ContentType=WindowsRuntime]
    $null = [Windows.Security.Authentication.Web.Core.WebTokenRequestStatus, Windows.Security.Authentication.Web.Core, ContentType=WindowsRuntime]
    $null = [Windows.Security.Credentials.WebAccountProvider, Windows.Security.Credentials, ContentType=WindowsRuntime]
    $null = [Windows.Security.Credentials.WebAccount, Windows.Security.Credentials, ContentType=WindowsRuntime]

    $script:WamTProvider = [Windows.Security.Credentials.WebAccountProvider, Windows.Security.Credentials, ContentType=WindowsRuntime]
    $script:WamTTokenResult = [Windows.Security.Authentication.Web.Core.WebTokenRequestResult, Windows.Security.Authentication.Web.Core, ContentType=WindowsRuntime]

    try {
        $closedAsTask = $script:WamAsTaskMethod.MakeGenericMethod($script:WamTTokenResult)
        $script:WamTTokenResultAsyncOperationGuid = $closedAsTask.GetParameters()[0].ParameterType.GUID
        Write-TestLog VERB WAM "IAsyncOperation<WebTokenRequestResult> IID: $script:WamTTokenResultAsyncOperationGuid"
    }
    catch {
        Write-TestLog WARN WAM "Could not resolve IAsyncOperation<WebTokenRequestResult> IID: $($_.Exception.Message)"
    }

    $script:WamWinRTInitialized = $true
    Write-TestLog VERB WAM 'WinRT types loaded.'
}

function Invoke-WinRTAsync {
    param(
        [Parameter(Mandatory = $true)] $AsyncOp,
        [Parameter(Mandatory = $true)] [Type]$ResultType
    )

    if ($null -eq $AsyncOp) {
        throw 'WinRT async operation was null.'
    }

    if ($null -eq $script:WamAsTaskMethod) {
        Initialize-WinRT
    }

    $task = $script:WamAsTaskMethod.MakeGenericMethod($ResultType).Invoke($null, @($AsyncOp))
    return $task.GetAwaiter().GetResult()
}

function Initialize-WamDesktopInterop {
    if ($script:WamDesktopInteropReady) { return $true }

    $existingHelperType = 'HealthScriptsGetScriptPoc.WAM.WebAuthenticationCoreManagerDesktop' -as [type]
    if ($null -ne $existingHelperType) {
        $script:WamDesktopInteropReady = $true
        return $true
    }

    $source = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.WindowsRuntime;

namespace HealthScriptsGetScriptPoc.WAM
{
    [ComImport]
    [Guid("F4B8E804-811E-4436-B69C-44CB67B72084")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IWebAuthenticationCoreManagerInterop
    {
        void GetIids(out uint iidCount, out IntPtr iids);
        void GetRuntimeClassName(out IntPtr className);
        void GetTrustLevel(out int trustLevel);

        [PreserveSig]
        int RequestTokenForWindowAsync(
            IntPtr appWindow,
            [MarshalAs(UnmanagedType.IInspectable)] object request,
            [In] ref Guid riid,
            out IntPtr asyncInfo);

        [PreserveSig]
        int RequestTokenWithWebAccountForWindowAsync(
            IntPtr appWindow,
            [MarshalAs(UnmanagedType.IInspectable)] object request,
            [MarshalAs(UnmanagedType.IInspectable)] object webAccount,
            [In] ref Guid riid,
            out IntPtr asyncInfo);
    }

    public static class WebAuthenticationCoreManagerDesktop
    {
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        public static IntPtr GetOwnerWindow()
        {
            IntPtr hwnd = GetConsoleWindow();
            if (hwnd == IntPtr.Zero) hwnd = GetForegroundWindow();
            return hwnd;
        }

        public static bool TrySetStringStringMap(object map, string key, string value, out string details)
        {
            details = "not attempted";
            if (map == null)
            {
                details = "map is null";
                return false;
            }

            try
            {
                var dict = map as IDictionary<string, string>;
                if (dict != null)
                {
                    dict[key] = value;
                    details = "IDictionary<string,string>";
                    return true;
                }
            }
            catch (Exception ex)
            {
                details = "IDictionary<string,string>: " + ex.Message;
            }

            try
            {
                object[] args = new object[] { key, value };
                map.GetType().InvokeMember("Insert", System.Reflection.BindingFlags.InvokeMethod, null, map, args);
                details = "InvokeMember Insert";
                return true;
            }
            catch (Exception ex)
            {
                details = details + " | Insert: " + ex.Message;
            }

            return false;
        }

        public static object RequestTokenForWindowAsync(Type managerType, IntPtr hwnd, object request, Guid asyncOperationGuid)
        {
            object factory = WindowsRuntimeMarshal.GetActivationFactory(managerType);
            var interop = (IWebAuthenticationCoreManagerInterop)factory;
            IntPtr asyncInfo;
            int hr = interop.RequestTokenForWindowAsync(hwnd, request, ref asyncOperationGuid, out asyncInfo);
            if (hr < 0) Marshal.ThrowExceptionForHR(hr);
            return Marshal.GetObjectForIUnknown(asyncInfo);
        }

        public static object RequestTokenWithWebAccountForWindowAsync(Type managerType, IntPtr hwnd, object request, object webAccount, Guid asyncOperationGuid)
        {
            object factory = WindowsRuntimeMarshal.GetActivationFactory(managerType);
            var interop = (IWebAuthenticationCoreManagerInterop)factory;
            IntPtr asyncInfo;
            int hr = interop.RequestTokenWithWebAccountForWindowAsync(hwnd, request, webAccount, ref asyncOperationGuid, out asyncInfo);
            if (hr < 0) Marshal.ThrowExceptionForHR(hr);
            return Marshal.GetObjectForIUnknown(asyncInfo);
        }
    }
}
'@

    try {
        Add-Type -TypeDefinition $source -Language CSharp -ReferencedAssemblies $script:WamWinRTRuntimePath -ErrorAction Stop
        $script:WamDesktopInteropReady = $true
        Write-TestLog VERB WAM 'Desktop WAM interop helper loaded.'
        return $true
    }
    catch {
        Write-TestLog WARN WAM "Desktop WAM interop helper could not be loaded: $($_.Exception.Message)"
        return $false
    }
}

function Get-WamProvider {
    if ($null -ne $script:WamProvider) {
        return $script:WamProvider
    }

    Initialize-WinRT

    Write-TestLog INFO WAM "Locating AAD WebAccountProvider: $script:WamProviderUrl"

    $authorityCandidates = @($script:WamAuthority, 'organizations', 'common', '') | Select-Object -Unique

    foreach ($candidate in $authorityCandidates) {
        try {
            if ([string]::IsNullOrWhiteSpace($candidate)) {
                Write-TestLog VERB WAM 'Trying provider lookup without authority.'
                $provider = Invoke-WinRTAsync `
                    -AsyncOp ([Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager]::FindAccountProviderAsync($script:WamProviderUrl)) `
                    -ResultType $script:WamTProvider
            }
            else {
                Write-TestLog VERB WAM "Trying provider lookup with authority: $candidate"
                $provider = Invoke-WinRTAsync `
                    -AsyncOp ([Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager]::FindAccountProviderAsync($script:WamProviderUrl, $candidate)) `
                    -ResultType $script:WamTProvider
            }

            if ($null -ne $provider) {
                $script:WamProvider = $provider
                $script:WamProviderAuthority = $candidate
                break
            }
        }
        catch {
            Write-TestLog VERB WAM "Provider lookup failed for authority '$candidate': $($_.Exception.Message)"
        }
    }

    if ($null -eq $script:WamProvider) {
        throw 'WAM provider not found. Is this device Entra joined or signed in with a work account?'
    }

    Write-TestLog VERB WAM "Provider: $($script:WamProvider.DisplayName) Authority: $($script:WamProvider.Authority)"
    return $script:WamProvider
}

function Set-WamStringMapValue {
    param(
        [Parameter(Mandatory = $true)] $Map,
        [Parameter(Mandatory = $true)] [string]$Key,
        [Parameter(Mandatory = $true)] [string]$Value
    )

    $errors = New-Object 'System.Collections.Generic.List[string]'

    if ($null -eq $Map) {
        return [PSCustomObject]@{ Success = $false; Details = 'map is null' }
    }

    $mapType = $Map.GetType().FullName

    try {
        if (Initialize-WamDesktopInterop) {
            $details = ''
            if ([HealthScriptsGetScriptPoc.WAM.WebAuthenticationCoreManagerDesktop]::TrySetStringStringMap($Map, $Key, $Value, [ref]$details)) {
                return [PSCustomObject]@{ Success = $true; Details = "Desktop helper $details on $mapType" }
            }
            $errors.Add("Desktop helper: $details")
        }
    }
    catch {
        $errors.Add("Desktop helper: $($_.Exception.Message)")
    }

    try {
        if ($Map -is [System.Collections.IDictionary]) {
            $Map[$Key] = $Value
            return [PSCustomObject]@{ Success = $true; Details = "IDictionary on $mapType" }
        }
    }
    catch { $errors.Add("IDictionary: $($_.Exception.Message)") }

    try {
        $Map[$Key] = $Value
        return [PSCustomObject]@{ Success = $true; Details = "indexer on $mapType" }
    }
    catch { $errors.Add("indexer: $($_.Exception.Message)") }

    try {
        $null = $Map.Insert($Key, $Value)
        return [PSCustomObject]@{ Success = $true; Details = "Insert() on $mapType" }
    }
    catch { $errors.Add("Insert: $($_.Exception.Message)") }

    try {
        $null = $Map.Add($Key, $Value)
        return [PSCustomObject]@{ Success = $true; Details = "Add() on $mapType" }
    }
    catch { $errors.Add("Add: $($_.Exception.Message)") }

    return [PSCustomObject]@{ Success = $false; Details = (($errors | Where-Object { $_ }) -join ' | ') }
}

function Set-WamRequestResource {
    param(
        [Parameter(Mandatory = $true)] $Request,
        [Parameter(Mandatory = $true)] [string]$Resource
    )

    $attempts = New-Object 'System.Collections.Generic.List[string]'

    foreach ($propertyName in @('AppProperties', 'Properties')) {
        try {
            $map = $Request.$propertyName
            $result = Set-WamStringMapValue -Map $map -Key 'resource' -Value $Resource

            if ($result.Success) {
                Write-TestLog VERB WAM "Set WAM resource via WebTokenRequest.$propertyName ($($result.Details))."
                return $true
            }

            $attempts.Add("$propertyName => $($result.Details)")
        }
        catch {
            $attempts.Add("$propertyName => $($_.Exception.Message)")
        }
    }

    Write-TestLog WARN WAM "Could not set WAM resource in property bags. $($attempts -join ' || ')"
    return $false
}

function New-WamTokenRequest {
    param(
        [Parameter(Mandatory = $true)] $Provider,
        [Parameter(Mandatory = $true)] [string]$ClientId,
        [Parameter(Mandatory = $true)] [string]$Resource
    )

    try {
        $req = [Windows.Security.Authentication.Web.Core.WebTokenRequest]::new($Provider, '', $ClientId)
    }
    catch {
        throw "Could not create WebTokenRequest with provider, empty scope and client ID. $($_.Exception.Message)"
    }

    if (Set-WamRequestResource -Request $req -Resource $Resource) {
        return $req
    }

    Write-TestLog WARN WAM 'Falling back to WebTokenRequest scope because the resource property bag is not writable.'

    try {
        return [Windows.Security.Authentication.Web.Core.WebTokenRequest]::new($Provider, $Resource, $ClientId)
    }
    catch {
        throw "Could not create fallback WebTokenRequest with resource as scope. $($_.Exception.Message)"
    }
}

function Get-WamFirstTokenResponse {
    param(
        [Parameter(Mandatory = $true)] $Result,
        [Parameter(Mandatory = $true)] [string]$Phase
    )

    if ($null -eq $Result.ResponseData) {
        throw "WAM token request returned Success but ResponseData was null. Phase: $Phase"
    }

    $data = $Result.ResponseData

    try {
        if ([int]$data.Count -lt 1) {
            throw "WAM token request returned Success but ResponseData.Count was 0. Phase: $Phase"
        }
    }
    catch { }

    try {
        $first = $data[0]
        if ($null -ne $first) {
            return $first
        }
    }
    catch { }

    try {
        $first = $data.Item(0)
        if ($null -ne $first) {
            return $first
        }
    }
    catch { }

    throw "WAM token request returned Success but the first token response could not be read. Phase: $Phase"
}

function Invoke-WamInteractiveTokenRequest {
    param(
        [Parameter(Mandatory = $true)] $Request,
        $WebAccount
    )

    if ($null -eq $script:WamTTokenResultAsyncOperationGuid) {
        throw 'Cannot call desktop WAM interop because the IAsyncOperation<WebTokenRequestResult> IID was not resolved.'
    }

    if (-not (Initialize-WamDesktopInterop)) {
        throw 'Cannot call desktop WAM interop because the helper could not be loaded.'
    }

    $managerType = [Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager, Windows.Security.Authentication.Web.Core, ContentType=WindowsRuntime]
    $hwnd = [HealthScriptsGetScriptPoc.WAM.WebAuthenticationCoreManagerDesktop]::GetOwnerWindow()

    Write-TestLog VERB WAM "Calling desktop WAM interop with HWND: $hwnd"

    if ($null -ne $WebAccount) {
        $asyncOp = [HealthScriptsGetScriptPoc.WAM.WebAuthenticationCoreManagerDesktop]::RequestTokenWithWebAccountForWindowAsync(
            $managerType,
            $hwnd,
            $Request,
            $WebAccount,
            $script:WamTTokenResultAsyncOperationGuid
        )
    }
    else {
        $asyncOp = [HealthScriptsGetScriptPoc.WAM.WebAuthenticationCoreManagerDesktop]::RequestTokenForWindowAsync(
            $managerType,
            $hwnd,
            $Request,
            $script:WamTTokenResultAsyncOperationGuid
        )
    }

    return Invoke-WinRTAsync -AsyncOp $asyncOp -ResultType $script:WamTTokenResult
}

function Get-WamToken {
    param(
        [Parameter(Mandatory = $true)] [string]$ClientId,
        [Parameter(Mandatory = $true)] [string]$Resource,
        [string]$Phase = 'AcquireToken',
        [switch]$Silent
    )

    Initialize-WinRT

    $provider = Get-WamProvider
    $corrId = [guid]::NewGuid().ToString()

    Write-TestLog INFO Identity "Requesting WAM token. ClientId: $ClientId"
    Write-TestLog INFO Identity "Resource: $Resource"
    Write-TestLog INFO Identity "Correlation ID: $corrId"

    $req = New-WamTokenRequest -Provider $provider -ClientId $ClientId -Resource $Resource

    try {
        if ($Silent -and ($null -ne $script:WamWebAccount)) {
            Write-TestLog VERB WAM 'Calling GetTokenSilentlyAsync with cached WebAccount.'
            $wamResult = Invoke-WinRTAsync `
                -AsyncOp ([Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager]::GetTokenSilentlyAsync($req, $script:WamWebAccount)) `
                -ResultType $script:WamTTokenResult
        }
        elseif ($Silent) {
            Write-TestLog VERB WAM 'Calling GetTokenSilentlyAsync without WebAccount.'
            $wamResult = Invoke-WinRTAsync `
                -AsyncOp ([Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager]::GetTokenSilentlyAsync($req)) `
                -ResultType $script:WamTTokenResult
        }
        else {
            Write-TestLog VERB WAM 'Trying silent WAM preflight first.'

            if ($null -ne $script:WamWebAccount) {
                $wamResult = Invoke-WinRTAsync `
                    -AsyncOp ([Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager]::GetTokenSilentlyAsync($req, $script:WamWebAccount)) `
                    -ResultType $script:WamTTokenResult
            }
            else {
                $wamResult = Invoke-WinRTAsync `
                    -AsyncOp ([Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager]::GetTokenSilentlyAsync($req)) `
                    -ResultType $script:WamTTokenResult
            }

            $successStatusForFallback = [Windows.Security.Authentication.Web.Core.WebTokenRequestStatus]::Success
            if ($wamResult.ResponseStatus -ne $successStatusForFallback) {
                Write-TestLog WARN WAM "Silent preflight returned $($wamResult.ResponseStatus). Switching to desktop interactive WAM."
                $wamResult = Invoke-WamInteractiveTokenRequest -Request $req -WebAccount $script:WamWebAccount
            }
        }
    }
    catch {
        Write-TestLog ERR Identity "WAM call threw: $($_.Exception.Message)"
        throw
    }

    $successStatus = [Windows.Security.Authentication.Web.Core.WebTokenRequestStatus]::Success

    if ($wamResult.ResponseStatus -ne $successStatus) {
        $errCode = ''
        $errMsg = ''

        if ($null -ne $wamResult.ResponseError) {
            try { $errCode = $wamResult.ResponseError.ErrorCode } catch { }
            try { $errMsg = $wamResult.ResponseError.ErrorMessage } catch { }
        }

        Write-TestLog ERR Identity "WAM token request FAILED. Status: $($wamResult.ResponseStatus) Code: $errCode $errMsg"
        throw "WAM token request failed: $($wamResult.ResponseStatus)"
    }

    $tokenResp = Get-WamFirstTokenResponse -Result $wamResult -Phase $Phase

    if ($null -eq $script:WamWebAccount -and $null -ne $tokenResp.WebAccount) {
        $script:WamWebAccount = $tokenResp.WebAccount

        try {
            $aid = $script:WamWebAccount.Id
            $shortId = $aid.Substring(0, [Math]::Min(6, $aid.Length))
            Write-TestLog INFO Identity "Cached WebAccount ID: $shortId..."
        }
        catch { }
    }

    if ($null -ne $tokenResp.WebAccount) {
        try {
            $script:WamUserId = $tokenResp.WebAccount.UserName
        }
        catch { }
    }

    Write-TestLog INFO Identity 'WAM authentication succeeded.'
    if ($script:WamUserId) {
        Write-TestLog INFO Identity "User: $script:WamUserId"
    }

    return [PSCustomObject]@{
        AccessToken = $tokenResp.Token
        AcquiredAt = [datetime]::UtcNow
        ClientId = $ClientId
        Resource = $Resource
    }
}

function Get-SideCarWamToken {
    Write-Step "Requesting SideCar WAM token using known working WAM helper. ClientId: $script:SideCarClientId Resource: $script:SideCarResource"

    $tokenResult = Get-WamToken `
        -ClientId $script:SideCarClientId `
        -Resource $script:SideCarResource `
        -Phase 'AcquireSideCarToken' `
        -Silent:$SilentOnly

    if ($tokenResult -and -not [string]::IsNullOrWhiteSpace($tokenResult.AccessToken)) {
        Write-Step 'SideCar WAM token acquired.'
        return $tokenResult.AccessToken
    }

    throw 'SideCar WAM returned no token.'
}

function Get-AccountIdFromIntuneMdmCert {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    $extension = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq "1.2.840.113556.5.6" } | Select-Object -First 1

    if (-not $extension) {
        return [guid]::Empty
    }

    [byte[]]$raw = $extension.RawData

    if ($raw.Length -eq 16) {
        return [guid]::new($raw)
    }

    if ($raw.Length -eq 18 -and $raw[0] -eq 0x04 -and $raw[1] -eq 0x10) {
        [byte[]]$guidBytes = $raw[2..17]
        return [guid]::new($guidBytes)
    }

    return [guid]::Empty
}

function Normalize-CertThumbprint {
    param([string]$Thumbprint)

    if ([string]::IsNullOrWhiteSpace($Thumbprint)) { return $null }

    return ($Thumbprint -replace '[^A-Fa-f0-9]', '').ToUpperInvariant()
}

function Get-LatestMdmCertThumbprintFromHealthScriptsLog {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return $null
    }

    try {
        $content = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        $matches = [regex]::Matches($content, 'Scheduler Set MdmDeviceCertificate\s*:\s*([A-Fa-f0-9]{40})')

        if ($matches.Count -gt 0) {
            return (Normalize-CertThumbprint $matches[$matches.Count - 1].Groups[1].Value)
        }
    }
    catch { }

    return $null
}

function Get-EnrollmentCertThumbprintHints {
    $thumbprints = New-Object System.Collections.Generic.List[string]
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Enrollments',
        'HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts'
    )

    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }

        foreach ($item in Get-ChildItem -LiteralPath $root -Recurse -ErrorAction SilentlyContinue) {
            try {
                $props = Get-ItemProperty -LiteralPath $item.PSPath -ErrorAction Stop

                foreach ($name in @('SslClientCertReference', 'DMClientCertReference', 'ClientCertReference', 'CertificateThumbprint')) {
                    if (-not ($props.PSObject.Properties.Name -contains $name)) { continue }

                    $value = [string]$props.$name
                    if ([string]::IsNullOrWhiteSpace($value)) { continue }

                    foreach ($m in [regex]::Matches($value, '[A-Fa-f0-9]{40}')) {
                        $thumb = Normalize-CertThumbprint $m.Value
                        if ($thumb -and -not $thumbprints.Contains($thumb)) {
                            $thumbprints.Add($thumb)
                        }
                    }
                }
            }
            catch { }
        }
    }

    return $thumbprints.ToArray()
}

function Get-CertificateByThumbprintFromStore {
    param(
        [System.Security.Cryptography.X509Certificates.StoreLocation]$Location,
        [string]$StorePath,
        [string]$Thumbprint
    )

    $normalized = Normalize-CertThumbprint $Thumbprint
    if (-not $normalized) { return $null }

    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', $Location)
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)

    try {
        $cert = $store.Certificates |
            Where-Object { (Normalize-CertThumbprint $_.Thumbprint) -eq $normalized } |
            Sort-Object NotAfter -Descending |
            Select-Object -First 1

        if (-not $cert) { return $null }

        return Convert-CertificateToMdmInfo -Certificate $cert -StorePath $StorePath -AllowMissingIntuneOid
    }
    finally {
        $store.Close()
    }
}

function Convert-CertificateToMdmInfo {
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory = $true)]
        [string]$StorePath,

        [switch]$AllowMissingIntuneOid
    )

    if (-not $Certificate.HasPrivateKey) {
        throw "Certificate $($Certificate.Thumbprint) was found in $StorePath but has no private key."
    }

    $match = [regex]::Match($Certificate.Subject, 'CN=([\da-fA-F-]{36})')
    if (-not $match.Success) {
        throw "Could not parse DeviceId from certificate subject: $($Certificate.Subject)"
    }

    $deviceId = [guid]::Parse($match.Groups[1].Value)
    $accountId = Get-AccountIdFromIntuneMdmCert -Certificate $Certificate

    if ($accountId -eq [guid]::Empty -and -not $AllowMissingIntuneOid) {
        throw "Certificate $($Certificate.Thumbprint) does not contain Intune AccountId OID 1.2.840.113556.5.6."
    }

    $certificateBlob = [Convert]::ToBase64String($Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))

    return [pscustomobject]@{
        Certificate     = $Certificate
        StorePath       = $StorePath
        DeviceId        = $deviceId
        AccountId       = $accountId
        CertificateBlob = $certificateBlob
    }
}

function Find-IntuneMdmCertificateInStore {
    param(
        [System.Security.Cryptography.X509Certificates.StoreLocation]$Location,
        [string]$StorePath
    )

    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', $Location)
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)

    try {
        $candidates = @($store.Certificates |
            Where-Object {
                $hasIntuneOid = @($_.Extensions | Where-Object { $_.Oid -and $_.Oid.Value -eq '1.2.840.113556.5.6' }).Count -gt 0
                $issuerLooksRight = $_.Issuer -like '*Microsoft Intune MDM Device CA*'
                $subjectLooksRight = $_.Subject -match 'CN=[\da-fA-F-]{36}'

                $_.HasPrivateKey -and $subjectLooksRight -and ($issuerLooksRight -or $hasIntuneOid)
            } |
            Sort-Object NotAfter -Descending)

        foreach ($cert in $candidates) {
            try {
                return Convert-CertificateToMdmInfo -Certificate $cert -StorePath $StorePath -AllowMissingIntuneOid
            }
            catch {
                Write-Step "Skipping certificate $($cert.Thumbprint) from $StorePath`: $($_.Exception.Message)"
            }
        }

        return $null
    }
    finally {
        $store.Close()
    }
}

function Get-IntuneMdmCertificateInfo {
    $thumbprintCandidates = New-Object System.Collections.Generic.List[string]

    $explicitThumbprint = Normalize-CertThumbprint $script:MdmCertThumbprint
    if ($explicitThumbprint) { $thumbprintCandidates.Add($explicitThumbprint) }

    $logThumbprint = Get-LatestMdmCertThumbprintFromHealthScriptsLog -Path $script:HealthScriptsLog
    if ($logThumbprint -and -not $thumbprintCandidates.Contains($logThumbprint)) { $thumbprintCandidates.Add($logThumbprint) }

    foreach ($thumb in Get-EnrollmentCertThumbprintHints) {
        if ($thumb -and -not $thumbprintCandidates.Contains($thumb)) { $thumbprintCandidates.Add($thumb) }
    }

    foreach ($thumb in $thumbprintCandidates) {
        Write-Step "Trying MDM certificate thumbprint hint: $thumb"

        $lmByThumb = Get-CertificateByThumbprintFromStore -Location LocalMachine -StorePath 'LocalMachine\My' -Thumbprint $thumb
        if ($lmByThumb) { return $lmByThumb }

        $cuByThumb = Get-CertificateByThumbprintFromStore -Location CurrentUser -StorePath 'CurrentUser\My' -Thumbprint $thumb
        if ($cuByThumb) { return $cuByThumb }
    }

    Write-Step 'No thumbprint hint matched, falling back to certificate issuer/OID scan.'

    $lm = Find-IntuneMdmCertificateInStore -Location LocalMachine -StorePath 'LocalMachine\My'
    if ($lm) { return $lm }

    $cu = Find-IntuneMdmCertificateInStore -Location CurrentUser -StorePath 'CurrentUser\My'
    if ($cu) { return $cu }

    throw "No valid Intune MDM certificate found. Tried explicit thumbprint, HealthScripts.log thumbprint, enrollment registry hints, LocalMachine\My scan, and CurrentUser\My scan."
}

function Get-IntuneLocationServiceBaseUrls {
    $urls = New-Object System.Collections.Generic.List[string]
    $root = "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts"

    if (Test-Path -LiteralPath $root) {
        foreach ($account in Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue) {
            $addrInfo = Join-Path $account.PSPath "Protected\AddrInfo"
            if (-not (Test-Path -LiteralPath $addrInfo)) { continue }

            try {
                $addr = (Get-ItemProperty -LiteralPath $addrInfo -Name Addr -ErrorAction Stop).Addr
                if ([string]::IsNullOrWhiteSpace($addr)) { continue }
                if ($addr -like "*checkin.dm.microsoft.com*") { continue }

                $uri = [Uri]$addr
                $base = "$($uri.Scheme)://$($uri.Host)"

                if (-not ($urls -contains $base)) {
                    $urls.Add($base)
                }
            }
            catch { }
        }
    }

    if ($urls.Count -eq 0) {
        $urls.Add("https://manage.microsoft.com")
    }

    return $urls.ToArray()
}

function Get-SideCarGatewayEndpoint {
    param(
        [Parameter(Mandatory = $true)]$CertificateInfo
    )

    if (-not [string]::IsNullOrWhiteSpace($script:SideCarEndpoint)) {
        return $script:SideCarEndpoint.TrimEnd("/")
    }

    $baseUrls = Get-IntuneLocationServiceBaseUrls

    foreach ($baseUrl in $baseUrls) {
        $uri = $baseUrl.TrimEnd("/") + "/RestUserAuthLocationService/RestUserAuthLocationService/Certificate/ServiceAddresses"
        Write-Step "Querying discovery endpoint: $uri"

        try {
            $headers = @{ "client-request-id" = [guid]::NewGuid().ToString() }
            $response = Invoke-RestMethod -Method Get -Uri $uri -Certificate $CertificateInfo.Certificate -Headers $headers -TimeoutSec 30

            foreach ($item in @($response)) {
                $isPrimary = $false
                try { $isPrimary = [bool]$item.IsPrimary } catch { }
                if (-not $isPrimary) { continue }

                foreach ($service in @($item.Services)) {
                    if ($service.ServiceName -eq "SideCarGatewayService" -and -not [string]::IsNullOrWhiteSpace($service.Url)) {
                        Write-Step "Found SideCarGatewayService URL: $($service.Url)"
                        return $service.Url.TrimEnd("/")
                    }
                }
            }
        }
        catch {
            Write-Step "Discovery request failed for $baseUrl`: $($_.Exception.Message)"
        }
    }

    throw "No valid SideCarGatewayService URL could be discovered."
}

function Read-WebExceptionResponse {
    param($ErrorRecord)

    $response = $null
    $body = $null
    $statusCode = $null
    $statusDescription = $null

    try { $response = $ErrorRecord.Exception.Response } catch { }

    if ($response) {
        try { $statusCode = [int]$response.StatusCode } catch { }
        try { $statusDescription = [string]$response.StatusDescription } catch { }

        try {
            $stream = $response.GetResponseStream()
            if ($stream) {
                $reader = New-Object System.IO.StreamReader($stream)
                $body = $reader.ReadToEnd()
                $reader.Dispose()
                $stream.Dispose()
            }
        }
        catch { }
    }

    return [pscustomobject]@{
        StatusCode        = $statusCode
        StatusDescription = $statusDescription
        Body              = $body
    }
}

function Invoke-SideCarGetScript {
    param(
        [Parameter(Mandatory = $true)][string]$Endpoint,
        [string]$Token,
        [Parameter(Mandatory = $true)]$CertificateInfo,
        [Parameter(Mandatory = $true)][string]$PayloadMode,
        [Parameter(Mandatory = $true)][string]$AuthHeaderMode,
        [Parameter(Mandatory = $true)][string]$ODataKeySyntax
    )

    $sessionId = [guid]::NewGuid().ToString()

    if ($ODataKeySyntax -eq "Guid") {
        $uri = $Endpoint.TrimEnd("/") + "/SideCarGatewaySessions(guid'$sessionId')?api-version=1.5"
    }
    else {
        # This matches the AgentCommon/downloader SendSideCarWorkloadRequestAsync URL shape.
        $uri = $Endpoint.TrimEnd("/") + "/SideCarGatewaySessions('$sessionId')?api-version=1.5"
    }

    $agentVersion = Get-IntuneManagementExtensionVersion
    $requestPayload = if ($PayloadMode -eq "Array") { "[]" } else { "" }

    $bodyObject = [ordered]@{
        Key                     = $sessionId
        SessionId               = $sessionId
        RequestContentType      = "GetScript"
        RequestPayload          = $requestPayload
        ResponseContentType     = $null
        ClientInfo              = New-SideCarClientInfoJson -SideCarAgentVersion $agentVersion
        ResponsePayload         = $null
        EnabledFlights          = $null
        CheckinIntervalMinutes  = $null
        GenericWorkloadRequests = $null
        GenericWorkloadResponse = $null
        CheckinReason           = $script:CheckinReason
        CheckinReasonPayload    = $null
    }

    $body = $bodyObject | ConvertTo-Json -Depth 30 -Compress

    $safeName = "${PayloadMode}_${AuthHeaderMode}_${ODataKeySyntax}"
    $requestPath = Join-Path $OutputFolder "getscript_request_$safeName.json"
    $body | Set-Content -LiteralPath $requestPath -Encoding UTF8

    $headers = @{
        "client-request-id"     = [guid]::NewGuid().ToString()
        Prefer                  = "return-content"
        "Request-Attempt-Count" = "1"
        "Scenario-Type"         = "Windows-GetScript"
    }

    if (-not [string]::IsNullOrWhiteSpace($Token)) {
        $headers.Authorization = "Bearer $Token"
    }

    if ($AuthHeaderMode -eq "DeviceHeaders") {
        $headers.AccountId = $CertificateInfo.AccountId.ToString()
        $headers.DeviceId  = $CertificateInfo.DeviceId.ToString()
    }

    Write-Step "PUT $uri"
    Write-Step "PayloadMode: $PayloadMode"
    Write-Step "AuthHeaderMode: $AuthHeaderMode"
    Write-Step "ODataKeySyntax: $ODataKeySyntax"
    Write-Step "Bearer token supplied: $(-not [string]::IsNullOrWhiteSpace($Token))"
    Write-Step "Scenario-Type: Windows-GetScript"

    try {
        $response = Invoke-WebRequest `
            -Method Put `
            -Uri $uri `
            -Certificate $CertificateInfo.Certificate `
            -Headers $headers `
            -ContentType "application/json; charset=utf-8" `
            -Body $body `
            -UseBasicParsing `
            -TimeoutSec 120

        $responsePath = Join-Path $OutputFolder "getscript_response_$safeName.json"
        $response.Content | Set-Content -LiteralPath $responsePath -Encoding UTF8

        $sideCarResponse = $response.Content | ConvertFrom-Json

        return [pscustomobject]@{
            Success         = $true
            PayloadMode     = $PayloadMode
            AuthHeaderMode  = $AuthHeaderMode
            ODataKeySyntax  = $ODataKeySyntax
            SessionId       = $sessionId
            Uri             = $uri
            HttpStatusCode  = [int]$response.StatusCode
            RawResponsePath = $responsePath
            RequestPath     = $requestPath
            Response        = $sideCarResponse
            ErrorBodyPath   = $null
            Error           = $null
        }
    }
    catch {
        $errorInfo = Read-WebExceptionResponse -ErrorRecord $_
        $errorBodyPath = Join-Path $OutputFolder "getscript_error_$safeName.txt"

        $text = @"
URI: $uri
PayloadMode: $PayloadMode
AuthHeaderMode: $AuthHeaderMode
ODataKeySyntax: $ODataKeySyntax
StatusCode: $($errorInfo.StatusCode)
StatusDescription: $($errorInfo.StatusDescription)
Exception: $($_.Exception.Message)

Response body:
$($errorInfo.Body)
"@
        $text | Set-Content -LiteralPath $errorBodyPath -Encoding UTF8

        return [pscustomobject]@{
            Success         = $false
            PayloadMode     = $PayloadMode
            AuthHeaderMode  = $AuthHeaderMode
            ODataKeySyntax  = $ODataKeySyntax
            SessionId       = $sessionId
            Uri             = $uri
            HttpStatusCode  = $errorInfo.StatusCode
            RawResponsePath = $null
            RequestPath     = $requestPath
            Response        = $null
            ErrorBodyPath   = $errorBodyPath
            Error           = $_.Exception.Message
            ErrorBody       = $errorInfo.Body
        }
    }
}

function ConvertFrom-ResponsePayload {
    param($SideCarResponse)

    if (-not $SideCarResponse.ResponsePayload) {
        return @()
    }

    $payloadText = [string]$SideCarResponse.ResponsePayload
    if ([string]::IsNullOrWhiteSpace($payloadText)) {
        return @()
    }

    try {
        $parsed = $payloadText | ConvertFrom-Json
        return @($parsed)
    }
    catch {
        Write-Step "ResponsePayload was present, but was not valid JSON: $($_.Exception.Message)"
        return @()
    }
}


function Add-HSAssemblyResolver {
    param([string]$Folder)

    $script:HSResolveFolder = $Folder
    [AppDomain]::CurrentDomain.add_AssemblyResolve({
        param($sender, $eventArgs)
        $name = New-Object System.Reflection.AssemblyName($eventArgs.Name)
        $candidate = Join-Path $script:HSResolveFolder ($name.Name + '.dll')
        if (Test-Path -LiteralPath $candidate) {
            try { return [System.Reflection.Assembly]::LoadFrom($candidate) } catch { return $null }
        }
        return $null
    })
}

function Get-HSType {
    param(
        [Parameter(Mandatory = $true)][System.Reflection.Assembly]$Assembly,
        [Parameter(Mandatory = $true)][string]$TypeName
    )
    $t = $Assembly.GetType($TypeName, $false)
    if (-not $t) { throw "Type not found: $TypeName" }
    return $t
}

function Get-HSStaticPropertyValue {
    param([type]$Type, [string]$Name)
    $prop = $Type.GetProperty($Name, [System.Reflection.BindingFlags]'Public,NonPublic,Static')
    if (-not $prop) { throw "Static property not found: $($Type.FullName).$Name" }
    return $prop.GetValue($null, $null)
}

function Set-HSStaticPropertyValue {
    param([type]$Type, [string]$Name, $Value)
    $prop = $Type.GetProperty($Name, [System.Reflection.BindingFlags]'Public,NonPublic,Static')
    if (-not $prop) { throw "Static property not found: $($Type.FullName).$Name" }
    $prop.SetValue($null, $Value, $null)
}

function Set-HSInstancePropertyValueIfPresent {
    param($Object, [string]$Name, $Value)
    if (-not $Object) { return $false }
    $prop = $Object.GetType().GetProperty($Name, [System.Reflection.BindingFlags]'Public,NonPublic,Instance')
    if (-not $prop -or -not $prop.CanWrite) { return $false }
    $prop.SetValue($Object, $Value, $null)
    return $true
}

function Set-HSInstancePropertyValueStrict {
    param($Object, [string]$Name, $Value)
    $prop = $Object.GetType().GetProperty($Name, [System.Reflection.BindingFlags]'Public,NonPublic,Instance')
    if (-not $prop) { throw "Property not found: $($Object.GetType().FullName).$Name" }
    if (-not $prop.CanWrite) { throw "Property is not writable: $($Object.GetType().FullName).$Name" }
    $prop.SetValue($Object, $Value, $null)
}

function Invoke-HSTaskResult {
    param($Task)
    if (-not $Task) { return $null }
    $Task.Wait()
    $prop = $Task.GetType().GetProperty('Result')
    if ($prop) { return $prop.GetValue($Task, $null) }
    return $null
}

function Get-HSInnerExceptionText {
    param([System.Exception]$Exception)
    $items = New-Object System.Collections.Generic.List[string]
    $e = $Exception
    while ($e) {
        [void]$items.Add(($e.GetType().FullName + ': ' + $e.Message))
        if ($e -is [System.Reflection.TargetInvocationException] -and $e.InnerException) { $e = $e.InnerException }
        elseif ($e.InnerException) { $e = $e.InnerException }
        else { $e = $null }
    }
    return ($items -join [Environment]::NewLine)
}

function Get-HSLatestSessionFromLog {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject]@{ SessionId = 0; UserId = '00000000-0000-0000-0000-000000000000'; Source = 'default, log missing' }
    }

    $content = Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($content)) {
        return [pscustomobject]@{ SessionId = 0; UserId = '00000000-0000-0000-0000-000000000000'; Source = 'default, empty log' }
    }

    $matches = [regex]::Matches($content, 'Processing user session\s+(?<sid>-?\d+),\s+userId:\s+(?<uid>[0-9a-fA-F-]{36})')
    for ($i = $matches.Count - 1; $i -ge 0; $i--) {
        $sid = [int]$matches[$i].Groups['sid'].Value
        $uid = $matches[$i].Groups['uid'].Value
        if ($uid -and $uid -ne '00000000-0000-0000-0000-000000000000') {
            return [pscustomobject]@{ SessionId = $sid; UserId = $uid; Source = 'latest non-empty HealthScripts.log session' }
        }
    }

    if ($matches.Count -gt 0) {
        $last = $matches[$matches.Count - 1]
        return [pscustomobject]@{ SessionId = [int]$last.Groups['sid'].Value; UserId = $last.Groups['uid'].Value; Source = 'latest HealthScripts.log session' }
    }

    return [pscustomobject]@{ SessionId = 0; UserId = '00000000-0000-0000-0000-000000000000'; Source = 'default, no session lines found' }
}

function Get-HSDirectSideCarEndpointFromLog {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $content = Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue
    $matches = [regex]::Matches($content, 'https://agents\.[^/]+/SideCar/StatelessSideCarGatewayService')
    if ($matches.Count -eq 0) { return $null }
    return $matches[$matches.Count - 1].Value.TrimEnd('/')
}

function Initialize-HSAgentCommonEnvironment {
    param(
        [System.Reflection.Assembly]$AgentAssembly,
        $CertificateInfo,
        [string]$ResolvedSideCarEndpoint
    )

    $envModeType = Get-HSType -Assembly $AgentAssembly -TypeName 'Microsoft.Management.Services.IntuneWindowsAgent.AgentCommon.EnvironmentMode'

    $envInfo = Get-HSStaticPropertyValue -Type $envModeType -Name 'CurrentEnvironmentInfo'
    if (-not $envInfo) {
        $prodEnvType = Get-HSType -Assembly $AgentAssembly -TypeName 'Microsoft.Management.Services.IntuneWindowsAgent.AgentCommon.ProdEnvironmentInfo'
        $envInfo = [Activator]::CreateInstance($prodEnvType)
        Set-HSStaticPropertyValue -Type $envModeType -Name 'CurrentEnvironmentInfo' -Value $envInfo
        Write-Step 'Initialized EnvironmentMode.CurrentEnvironmentInfo with ProdEnvironmentInfo'
    }

    try {
        $environmentType = Get-HSType -Assembly $AgentAssembly -TypeName 'Microsoft.Management.Services.IntuneWindowsAgent.AgentCommon.EnvironmentType'
        $prodValue = [Enum]::Parse($environmentType, 'Prod')
        Set-HSStaticPropertyValue -Type $envModeType -Name 'CurrentEnvironment' -Value $prodValue
        Write-Step 'Set EnvironmentMode.CurrentEnvironment to Prod'
    } catch {
        Write-Step "Could not set CurrentEnvironment enum, continuing: $($_.Exception.Message)"
    }

    if ($CertificateInfo.DeviceId -and $CertificateInfo.DeviceId -ne [Guid]::Empty) {
        Set-HSStaticPropertyValue -Type $envModeType -Name 'DeviceId' -Value ([guid]$CertificateInfo.DeviceId)
        Write-Step "Set EnvironmentMode.DeviceId: $($CertificateInfo.DeviceId)"
    }

    if ($CertificateInfo.AccountId -and $CertificateInfo.AccountId -ne [Guid]::Empty) {
        try {
            Set-HSStaticPropertyValue -Type $envModeType -Name 'AccountId' -Value ([guid]$CertificateInfo.AccountId)
            Write-Step "Set EnvironmentMode.AccountId: $($CertificateInfo.AccountId)"
        } catch {
            Write-Step "Could not set EnvironmentMode.AccountId, continuing: $($_.Exception.Message)"
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($ResolvedSideCarEndpoint)) {
        [void](Set-HSInstancePropertyValueIfPresent -Object $envInfo -Name 'SideCarGatewayServiceUrl' -Value $ResolvedSideCarEndpoint)
        [void](Set-HSInstancePropertyValueIfPresent -Object $envInfo -Name 'LastServiceEnpointURLUpdateTime' -Value ([DateTime]::UtcNow))
        Write-Step "Set EnvironmentInfo.SideCarGatewayServiceUrl: $ResolvedSideCarEndpoint"
    }

    return $envInfo
}

function Add-HSStaticTokenManagerType {
    param([string]$AgentCommonPath)

    $existing = 'HealthScriptsGetScriptPoc.AgentCommonProxy.StaticTokenManager' -as [type]
    if ($existing) { return $existing }

    $agentAssembly = [System.Reflection.Assembly]::LoadFrom($AgentCommonPath)
    $iface = $agentAssembly.GetType('Microsoft.Management.Services.IntuneWindowsAgent.AgentCommon.IClientTokenManager', $true)

    function Get-HSCSharpTypeName {
        param([Type]$Type)

        if ($Type -eq [string]) { return 'string' }
        if ($Type -eq [int]) { return 'int' }
        if ($Type -eq [bool]) { return 'bool' }
        if ($Type -eq [void]) { return 'void' }
        if ($Type -eq [datetime]) { return 'System.DateTime' }
        if ($Type -eq [timespan]) { return 'System.TimeSpan' }
        if ($Type -eq [guid]) { return 'System.Guid' }

        if ($Type.IsGenericType) {
            $genericName = $Type.GetGenericTypeDefinition().FullName -replace '`.*$', ''
            $genericArgs = ($Type.GetGenericArguments() | ForEach-Object { Get-HSCSharpTypeName -Type $_ }) -join ', '
            return "$genericName<$genericArgs>"
        }

        return $Type.FullName
    }

    $props = @($iface.GetProperties([System.Reflection.BindingFlags]'Public,Instance'))
    $propLines = foreach ($p in $props) {
        $typeName = Get-HSCSharpTypeName -Type $p.PropertyType
        "        public $typeName $($p.Name) { get; set; }"
    }

    function Get-HSPropertyInitializerExpression {
        param(
            [Parameter(Mandatory = $true)]
            [System.Reflection.PropertyInfo]$Property
        )

        $name = $Property.Name
        $type = $Property.PropertyType
        $typeFullName = $type.FullName

        # Known properties that must receive the real values.
        if ($name -eq 'Token' -and $type -eq [string]) { return 'token' }
        if ($name -eq 'MdmDeviceCertificate' -and $type.FullName -eq 'System.Security.Cryptography.X509Certificates.X509Certificate2') { return 'cert' }
        if ($name -eq 'TokenRenewalAdvanceInterval' -and $type -eq [timespan]) { return 'TimeSpan.FromMinutes(10)' }

        # Known string properties in the IME token manager.
        if ($type -eq [string]) {
            switch ($name) {
                'DeviceCheckInAppId' { return 'deviceCheckInAppId' }
                'ClientId' { return 'deviceCheckInAppId' }
                'TestClientId' { return 'deviceCheckInAppId' }
                'ResourceId' { return '"26a4ae64-5862-427f-a9b0-044e62572a4f"' }
                'ProviderResourceId' { return '"26a4ae64-5862-427f-a9b0-044e62572a4f"' }
                'DeviceAADAuthTokenResourceId' { return '"26a4ae64-5862-427f-a9b0-044e62572a4f"' }
                'IntuneBitLockerWindowsResourceId' { return '"26a4ae64-5862-427f-a9b0-044e62572a4f"' }
                'ProviderId' { return '"https://login.microsoft.com"' }
                'RedirectUri' { return '"ms-appx-web://Microsoft.AAD.BrokerPlugin/" + deviceCheckInAppId' }
                'ADALAuthority' { return '"https://login.microsoftonline.com/common"' }
                'Authority' { return '"https://login.microsoftonline.com/common"' }
                'DeviceAADAuthTokenAuthority' { return '"https://login.microsoftonline.com/common"' }
                'RotateBitLockerKeysAuthority' { return '"https://login.microsoftonline.com/common"' }
                default { return 'String.Empty' }
            }
        }

        # Known non-string properties.
        if ($name -eq 'UserId' -and $type -eq [guid]) { return 'parsedUserId' }
        if ($name -eq 'UserClaim' -and $type.FullName -eq 'System.Security.Claims.Claim') { return 'new Claim("oid", parsedUserId.ToString())' }
        if ($type -eq [guid]) { return 'Guid.Empty' }
        if ($type -eq [bool]) { return 'false' }
        if ($type -eq [int]) { return '0' }
        if ($type -eq [long]) { return '0L' }
        if ($type -eq [datetime]) { return 'DateTime.MinValue' }
        if ($type -eq [timespan]) { return 'TimeSpan.Zero' }
        if ($type.FullName -eq 'System.Security.Claims.Claim') { return 'new Claim("upn", upn)' }

        # Nullable<T> defaults.
        if ($type.IsGenericType -and $type.GetGenericTypeDefinition().FullName -eq 'System.Nullable`1') {
            return ('default({0})' -f (Get-HSCSharpTypeName -Type $type))
        }

        # Enum defaults.
        if ($type.IsEnum) {
            return ('default({0})' -f (Get-HSCSharpTypeName -Type $type))
        }

        # Reference type default. This keeps the generated wrapper compiling when the interface gains a new object property.
        if (-not $type.IsValueType) { return 'null' }

        return ('default({0})' -f (Get-HSCSharpTypeName -Type $type))
    }

    $assignments = New-Object System.Collections.Generic.List[string]
    $assignments.Add('            _token = token;')

    foreach ($p in $props) {
        if (-not $p.CanWrite) { continue }
        $expr = Get-HSPropertyInitializerExpression -Property $p
        if (-not [string]::IsNullOrWhiteSpace($expr)) {
            $assignments.Add(('            {0} = {1};' -f $p.Name, $expr))
        }
    }

    $methods = @($iface.GetMethods([System.Reflection.BindingFlags]'Public,Instance') | Where-Object { -not $_.IsSpecialName })
    $ifaceDump = New-Object System.Collections.Generic.List[string]
    foreach ($p in $props) { $ifaceDump.Add(("PROPERTY {0} {1}" -f $p.PropertyType.FullName, $p.Name)) }
    foreach ($m in $methods) {
        $paramDump = ($m.GetParameters() | ForEach-Object { "$($_.ParameterType.FullName) $($_.Name)" }) -join ', '
        $ifaceDump.Add(("METHOD {0} {1}({2})" -f $m.ReturnType.FullName, $m.Name, $paramDump))
    }
    $ifaceDumpPath = Join-Path $script:OutputFolder 'iclienttokenmanager_interface_members.txt'
    $ifaceDump | Set-Content -Path $ifaceDumpPath -Encoding UTF8
    Write-Step "Dumped IClientTokenManager interface members: $ifaceDumpPath"

    $methodLines = foreach ($m in $methods) {
        $returnType = Get-HSCSharpTypeName -Type $m.ReturnType
        $paramList = @()
        foreach ($p in $m.GetParameters()) {
            $paramList += "$(Get-HSCSharpTypeName -Type $p.ParameterType) $($p.Name)"
        }
        $params = $paramList -join ', '

        $isTaskOfString = $false
        if ($m.ReturnType.IsGenericType) {
            $genericDef = $m.ReturnType.GetGenericTypeDefinition()
            $genericArgs = @($m.ReturnType.GetGenericArguments())
            if ($genericDef.FullName -eq 'System.Threading.Tasks.Task`1' -and $genericArgs.Count -eq 1 -and $genericArgs[0].FullName -eq 'System.String') {
                $isTaskOfString = $true
            }
        }

        if ($isTaskOfString) {
@"
        public $returnType $($m.Name)($params)
        {
            return Task.FromResult(_token);
        }
"@
        }
        elseif ($m.ReturnType.FullName -eq 'System.String') {
@"
        public string $($m.Name)($params)
        {
            return _token;
        }
"@
        }
        elseif ($m.ReturnType.FullName -eq 'System.Threading.Tasks.Task') {
@"
        public $returnType $($m.Name)($params)
        {
            return Task.FromResult(0);
        }
"@
        }
        else {
            throw "Unsupported IClientTokenManager method return type for $($m.Name): $($m.ReturnType.FullName)"
        }
    }

    $source = @"
using System;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using System.Security.Claims;
using Microsoft.Management.Services.IntuneWindowsAgent.AgentCommon;

namespace HealthScriptsGetScriptPoc.AgentCommonProxy
{
    public sealed class StaticTokenManager : IClientTokenManager
    {
        private readonly string _token;
$($propLines -join "`r`n")

        public StaticTokenManager(string token, X509Certificate2 cert, string deviceCheckInAppId, string userId, string upn)
        {
            Guid parsedUserId = Guid.Empty;
            if (!String.IsNullOrWhiteSpace(userId)) { Guid.TryParse(userId, out parsedUserId); }
            if (upn == null) { upn = String.Empty; }
$($assignments -join "`r`n")
        }

$($methodLines -join "`r`n")
    }
}
"@

    $generatedPath = Join-Path $script:OutputFolder 'generated_StaticTokenManager.cs'
    $source | Set-Content -Path $generatedPath -Encoding UTF8
    Write-Step "Generated StaticTokenManager source: $generatedPath"

    Add-Type -TypeDefinition $source -Language CSharp -ReferencedAssemblies @($AgentCommonPath, 'System.dll', 'System.Core.dll') -ErrorAction Stop
    return ('HealthScriptsGetScriptPoc.AgentCommonProxy.StaticTokenManager' -as [type])
}

function New-HSStaticTokenManager {
    param(
        [string]$AccessToken,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$AgentCommonPath,
        [string]$UserId,
        [string]$Upn
    )
    $type = Add-HSStaticTokenManagerType -AgentCommonPath $AgentCommonPath
    return [Activator]::CreateInstance($type, @($AccessToken, $Certificate, $script:SideCarClientId, $UserId, $Upn))
}

function Set-HSTokenManagerOnObject {
    param($Object, $TokenManager)
    if (-not $Object) { return $false }
    $prop = $Object.GetType().GetProperty('TokenManager', [System.Reflection.BindingFlags]'Public,NonPublic,Instance')
    if (-not $prop -or -not $prop.CanWrite) { return $false }
    $prop.SetValue($Object, $TokenManager, $null)
    return $true
}

function Convert-HSJwtPayload {
    param([string]$Token)
    try {
        $parts = $Token.Split('.')
        if ($parts.Count -lt 2) { return $null }
        $payload = $parts[1].Replace('-', '+').Replace('_', '/')
        switch ($payload.Length % 4) {
            2 { $payload += '==' }
            3 { $payload += '=' }
        }
        $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
        return $json | ConvertFrom-Json
    } catch { return $null }
}

function New-HSHealthScriptsGatewaySession {
    param([System.Reflection.Assembly]$AgentAssembly)

    $sessionType = Get-HSType -Assembly $AgentAssembly -TypeName 'Microsoft.Management.Services.IntuneWindowsAgent.AgentCommon.SideCarGatewaySession'
    $session = [Activator]::CreateInstance($sessionType)
    $key = [Guid]::NewGuid()

    Set-HSInstancePropertyValueStrict -Object $session -Name 'Key' -Value $key
    try { Set-HSInstancePropertyValueStrict -Object $session -Name 'SessionId' -Value $key } catch { }
    Set-HSInstancePropertyValueStrict -Object $session -Name 'RequestContentType' -Value 'GetScript'

    $agentInfoType = Get-HSType -Assembly $AgentAssembly -TypeName 'Microsoft.Management.Services.IntuneWindowsAgent.AgentCommon.AgentInfoRetriever'
    $agentInfo = [Activator]::CreateInstance($agentInfoType)
    $workloadType = Get-HSType -Assembly $AgentAssembly -TypeName 'Microsoft.Management.Services.IntuneWindowsAgent.AgentCommon.SideCarWorkload'
    $workload7 = [Enum]::ToObject($workloadType, 7)
    $workloadName = $workload7.ToString()
    Write-Step "SideCarWorkload value 7 resolves to: $workloadName"

    $clientInfoMethod = $agentInfoType.GetMethods([System.Reflection.BindingFlags]'Public,NonPublic,Instance') |
        Where-Object { $_.Name -eq 'GetClientInfoJsonString' -and $_.GetParameters().Count -eq 1 } |
        Select-Object -First 1
    if (-not $clientInfoMethod) { throw 'AgentInfoRetriever.GetClientInfoJsonString(...) not found.' }

    $clientInfoParamType = $clientInfoMethod.GetParameters()[0].ParameterType
    $clientInfoArg = $workloadName
    if ($clientInfoParamType.IsEnum) {
        $clientInfoArg = $workload7
        Write-Step "Calling GetClientInfoJsonString with enum argument: $workload7"
    }
    else {
        Write-Step "Calling GetClientInfoJsonString with string argument: $workloadName"
    }

    $clientInfo = $clientInfoMethod.Invoke($agentInfo, @($clientInfoArg))
    Set-HSInstancePropertyValueStrict -Object $session -Name 'ClientInfo' -Value $clientInfo

    # Real HealthScripts GetScript response echoes RequestPayload as an empty string.
    # Keep the same shape instead of leaving it null.
    [void](Set-HSInstancePropertyValueIfPresent -Object $session -Name 'RequestPayload' -Value '')
    [void](Set-HSInstancePropertyValueIfPresent -Object $session -Name 'CheckinReason' -Value 'OnDemand')
    [void](Set-HSInstancePropertyValueIfPresent -Object $session -Name 'CheckinReasonPayload' -Value '{"NotificationID":"00000000-0000-0000-0000-000000000000","NotificationIntent":""}')

    return $session
}

function Invoke-HSControllerPutDirect {
    param(
        $Controller,
        [System.Reflection.Assembly]$AgentAssembly,
        [int]$SessionId,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$Label,
        [switch]$UseCertOverload
    )

    $session = New-HSHealthScriptsGatewaySession -AgentAssembly $AgentAssembly
    $sessionType = $session.GetType()

    $putCandidates = $Controller.GetType().GetMethods([System.Reflection.BindingFlags]'Public,NonPublic,Instance') |
        Where-Object { $_.Name -eq 'Put' -and $_.GetParameters().Count -eq 3 }

    if ($UseCertOverload) {
        $put = $putCandidates | Where-Object { $_.GetParameters()[2].ParameterType.FullName -eq 'System.Security.Cryptography.X509Certificates.X509Certificate2' } | Select-Object -First 1
    } else {
        $put = $putCandidates | Where-Object { $_.GetParameters()[2].ParameterType.FullName -ne 'System.Security.Cryptography.X509Certificates.X509Certificate2' } | Select-Object -First 1
    }

    if (-not $put) { throw "Could not find IntuneController.Put overload for $Label" }
    if ($put.IsGenericMethodDefinition) { $put = $put.MakeGenericMethod($sessionType) }

    Write-Step "Direct Put test [$Label] with SideCar session key: $($session.Key)"

    try {
        $third = if ($UseCertOverload) { $Certificate } else { $null }
        $task = $put.Invoke($Controller, @($session, $SessionId, $third))
        $result = Invoke-HSTaskResult -Task $task
        $len = if ($null -eq $result) { 0 } else { $result.Length }
        Write-Step "Direct Put [$Label] completed. Result length: $len"
        return $result
    } catch {
        $text = Get-HSInnerExceptionText -Exception $_.Exception
        $path = Join-Path $script:OutputFolder "direct_put_error_$Label.txt"
        $text | Out-File -Encoding UTF8 $path
        Write-Step "Direct Put [$Label] failed. Details saved to: $path"
        Write-Host $text
        return $null
    }
}



function Convert-HSBase64ToUtf8Text {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    try {
        $bytes = [Convert]::FromBase64String($Value)
        return [Text.Encoding]::UTF8.GetString($bytes)
    }
    catch {
        return $null
    }
}

function Save-HSBase64Bytes {
    param(
        [string]$Value,
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }

    try {
        $bytes = [Convert]::FromBase64String($Value)
        [IO.File]::WriteAllBytes($Path, $bytes)
        return $true
    }
    catch {
        return $false
    }
}

function Try-DecodeHSSignedCmsInfo {
    param(
        [string]$Base64Signature,
        [string]$OutputFolder
    )

    if ([string]::IsNullOrWhiteSpace($Base64Signature)) { return }

    New-FolderIfMissing -Path $OutputFolder

    $p7b = Join-Path $OutputFolder 'content_signature.p7b'
    [void](Save-HSBase64Bytes -Value $Base64Signature -Path $p7b)

    try {
        Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
        $bytes = [Convert]::FromBase64String($Base64Signature)
        $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
        $cms.Decode($bytes)

        $certs = @()
        foreach ($cert in $cms.Certificates) {
            $certs += [pscustomobject]@{
                Subject    = $cert.Subject
                Issuer     = $cert.Issuer
                Thumbprint = $cert.Thumbprint
                NotBefore  = $cert.NotBefore
                NotAfter   = $cert.NotAfter
            }
        }

        $certs | ConvertTo-Json -Depth 10 | Out-File -Encoding UTF8 (Join-Path $OutputFolder 'content_signature_certificates.json')
    }
    catch {
        $_.Exception.ToString() | Out-File -Encoding UTF8 (Join-Path $OutputFolder 'content_signature_parse_error.txt')
    }
}

function Try-DecryptHSEncryptedPolicyBody {
    param(
        [string]$EncryptedPolicyBody,
        [string]$OutputFolder
    )

    if ([string]::IsNullOrWhiteSpace($EncryptedPolicyBody)) { return }

    New-FolderIfMissing -Path $OutputFolder

    $encryptedBin = Join-Path $OutputFolder 'encrypted_policy_body.bin'
    [void](Save-HSBase64Bytes -Value $EncryptedPolicyBody -Path $encryptedBin)

    try {
        Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
        $bytes = [Convert]::FromBase64String($EncryptedPolicyBody)
        $cms = New-Object System.Security.Cryptography.Pkcs.EnvelopedCms
        $cms.Decode($bytes)

        try {
            $cms.Decrypt()
        }
        catch {
            if ($script:CurrentMdmCert) {
                $certs = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
                [void]$certs.Add($script:CurrentMdmCert)
                $recipient = $null
                if ($cms.RecipientInfos.Count -gt 0) { $recipient = $cms.RecipientInfos[0] }
                if ($recipient) {
                    $cms.Decrypt($recipient, $certs)
                }
                else {
                    throw
                }
            }
            else {
                throw
            }
        }

        $decoded = [Text.Encoding]::UTF8.GetString($cms.ContentInfo.Content)
        $decoded | Out-File -Encoding UTF8 (Join-Path $OutputFolder 'encrypted_policy_body.decrypted.ps1')
        return $true
    }
    catch {
        $_.Exception.ToString() | Out-File -Encoding UTF8 (Join-Path $OutputFolder 'encrypted_policy_body_decrypt_error.txt')
        return $false
    }
}

function Export-HSDecodedPolicyItems {
    param(
        [object[]]$Items,
        [string]$Label
    )

    if (-not $Items -or @($Items).Count -eq 0) { return $null }

    $exportRoot = Join-Path $script:OutputFolder ("DecodedScripts_{0}" -f $Label)
    New-FolderIfMissing -Path $exportRoot

    $manifest = New-Object System.Collections.Generic.List[object]

    foreach ($item in @($Items)) {
        $policyIdForExport = $null
        foreach ($name in @('PolicyId','Id')) {
            if ($item.PSObject.Properties.Name -contains $name -and $item.$name) {
                $policyIdForExport = [string]$item.$name
                break
            }
        }
        if (-not $policyIdForExport) { $policyIdForExport = [Guid]::NewGuid().ToString() }

        $ver = '0'
        foreach ($name in @('InternalVersion','Version')) {
            if ($item.PSObject.Properties.Name -contains $name -and $item.$name -ne $null) {
                $ver = [string]$item.$name
                break
            }
        }

        $dir = Join-Path $exportRoot ("{0}_{1}" -f $policyIdForExport, $ver)
        New-FolderIfMissing -Path $dir

        $item | ConvertTo-Json -Depth 40 | Out-File -Encoding UTF8 (Join-Path $dir 'policy.raw.json')

        $detectPath = $null
        $remediatePath = $null
        $encryptedPath = $null
        $signaturePath = $null

        foreach ($candidate in @(
            @{ Prop = 'PolicyBody'; File = 'detect.ps1' },
            @{ Prop = 'DetectionScript'; File = 'detect.ps1' },
            @{ Prop = 'RemediationScript'; File = 'remediate.ps1' },
            @{ Prop = 'RemediationScriptBody'; File = 'remediate.ps1' }
        )) {
            $propName = $candidate.Prop
            if ($item.PSObject.Properties.Name -contains $propName -and -not [string]::IsNullOrWhiteSpace([string]$item.$propName)) {
                $target = Join-Path $dir $candidate.File
                $decoded = Convert-HSBase64ToUtf8Text -Value ([string]$item.$propName)
                if ($decoded -ne $null) {
                    $decoded | Out-File -Encoding UTF8 $target
                    if ($candidate.File -eq 'detect.ps1') { $detectPath = $target }
                    if ($candidate.File -eq 'remediate.ps1') { $remediatePath = $target }
                }
                else {
                    [string]$item.$propName | Out-File -Encoding UTF8 ($target + '.raw.txt')
                }
            }
        }

        if ($item.PSObject.Properties.Name -contains 'EncryptedPolicyBody' -and -not [string]::IsNullOrWhiteSpace([string]$item.EncryptedPolicyBody)) {
            [void](Try-DecryptHSEncryptedPolicyBody -EncryptedPolicyBody ([string]$item.EncryptedPolicyBody) -OutputFolder $dir)
            $encryptedPath = Join-Path $dir 'encrypted_policy_body.bin'
        }

        if ($item.PSObject.Properties.Name -contains 'ContentSignature' -and -not [string]::IsNullOrWhiteSpace([string]$item.ContentSignature)) {
            Try-DecodeHSSignedCmsInfo -Base64Signature ([string]$item.ContentSignature) -OutputFolder $dir
            $signaturePath = Join-Path $dir 'content_signature.p7b'
        }

        if ($item.PSObject.Properties.Name -contains 'PolicyScriptParameters' -and $null -ne $item.PolicyScriptParameters) {
            [string]$item.PolicyScriptParameters | Out-File -Encoding UTF8 (Join-Path $dir 'script_parameters.txt')
        }

        $clean = [ordered]@{
            PolicyId              = $policyIdForExport
            Version               = $ver
            AccountId             = if ($item.PSObject.Properties.Name -contains 'AccountId') { $item.AccountId } else { $null }
            PolicyType            = if ($item.PSObject.Properties.Name -contains 'PolicyType') { $item.PolicyType } else { $null }
            PolicyHash            = if ($item.PSObject.Properties.Name -contains 'PolicyHash') { $item.PolicyHash } else { $null }
            TargetType            = if ($item.PSObject.Properties.Name -contains 'TargetType') { $item.TargetType } else { $null }
            RunAsAccount          = if ($item.PSObject.Properties.Name -contains 'RunAsAccount') { $item.RunAsAccount } else { $null }
            HasDetectScript       = [bool]$detectPath
            HasRemediationScript  = [bool]$remediatePath
            HasEncryptedBody      = [bool]$encryptedPath
            HasContentSignature   = [bool]$signaturePath
            DetectScriptPath      = $detectPath
            RemediationScriptPath = $remediatePath
            EncryptedPolicyPath   = $encryptedPath
            ContentSignaturePath  = $signaturePath
            ExportFolder          = $dir
        }

        $clean | ConvertTo-Json -Depth 20 | Out-File -Encoding UTF8 (Join-Path $dir 'manifest.json')
        $manifest.Add([pscustomobject]$clean)
    }

    $manifestPath = Join-Path $exportRoot 'decoded_manifest.json'
    $manifestCsv = Join-Path $exportRoot 'decoded_manifest.csv'
    $manifest | ConvertTo-Json -Depth 20 | Out-File -Encoding UTF8 $manifestPath
    $manifest | Export-Csv -NoTypeInformation -Encoding UTF8 $manifestCsv

    Write-Step "[$Label] Decoded scripts exported to: $exportRoot"
    Write-Step "[$Label] Decoded manifest: $manifestPath"

    return $exportRoot
}


function Save-HSGetScriptRawResponse {
    param(
        [string]$RawResponse,
        [string]$Label
    )

    if ([string]::IsNullOrWhiteSpace($RawResponse)) {
        Write-Step "[$Label] Raw response was empty."
        return $false
    }

    $rawPath = Join-Path $script:OutputFolder ("getscript_raw_{0}.json" -f $Label)
    $RawResponse | Out-File -Encoding UTF8 $rawPath
    Write-Step "[$Label] Raw response saved to: $rawPath"

    try {
        $sideCarResponse = $RawResponse | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Write-Step "[$Label] Raw response was not JSON: $($_.Exception.Message)"
        return $false
    }

    $responsePath = Join-Path $script:OutputFolder ("getscript_sidecar_{0}.json" -f $Label)
    $sideCarResponse | ConvertTo-Json -Depth 30 | Out-File -Encoding UTF8 $responsePath

    $items = ConvertFrom-ResponsePayload -SideCarResponse $sideCarResponse
    $itemsPath = Join-Path $script:OutputFolder ("getscript_policies_{0}.json" -f $Label)
    $items | ConvertTo-Json -Depth 30 | Out-File -Encoding UTF8 $itemsPath
    Write-Step "[$Label] ResponsePayload item count: $(@($items).Count)"
    Write-Step "[$Label] Parsed policies saved to: $itemsPath"

    if (@($items).Count -gt 0) {
        [void](Export-HSDecodedPolicyItems -Items @($items) -Label $Label)

        $exportRoot = Join-Path $script:OutputFolder ("ExtractedScripts_{0}" -f $Label)
        New-FolderIfMissing -Path $exportRoot

        foreach ($item in $items) {
            $policyIdForExport = $null
            foreach ($name in @('PolicyId','Id')) {
                if ($item.PSObject.Properties.Name -contains $name -and $item.$name) { $policyIdForExport = [string]$item.$name; break }
            }
            if (-not $policyIdForExport) { $policyIdForExport = [Guid]::NewGuid().ToString() }

            $ver = '0'
            foreach ($name in @('InternalVersion','Version')) {
                if ($item.PSObject.Properties.Name -contains $name -and $item.$name -ne $null) { $ver = [string]$item.$name; break }
            }

            $dir = Join-Path $exportRoot ("{0}_{1}" -f $policyIdForExport, $ver)
            New-FolderIfMissing -Path $dir
            $item | ConvertTo-Json -Depth 30 | Out-File -Encoding UTF8 (Join-Path $dir 'policy.json')

            foreach ($candidate in @(
                @{ Prop = 'PolicyBody'; File = 'detect.ps1' },
                @{ Prop = 'DetectionScript'; File = 'detect.ps1' },
                @{ Prop = 'RemediationScript'; File = 'remediate.ps1' },
                @{ Prop = 'RemediationScriptBody'; File = 'remediate.ps1' }
            )) {
                $propName = $candidate.Prop
                if ($item.PSObject.Properties.Name -contains $propName -and -not [string]::IsNullOrWhiteSpace([string]$item.$propName)) {
                    $value = [string]$item.$propName
                    $target = Join-Path $dir $candidate.File
                    try {
                        $decoded = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($value))
                        $decoded | Out-File -Encoding UTF8 $target
                    }
                    catch {
                        $value | Out-File -Encoding UTF8 ($target + '.raw.txt')
                    }
                }
            }
        }

        Write-Step "[$Label] Extracted script output: $exportRoot"
        return $true
    }

    return $false
}

function Invoke-HSControllerPutWithTupleDirect {
    param(
        $Controller,
        [System.Reflection.Assembly]$AgentAssembly,
        [int]$SessionId,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$Label,
        [switch]$UseCertOverload
    )

    $session = New-HSHealthScriptsGatewaySession -AgentAssembly $AgentAssembly
    $sessionType = $session.GetType()

    $putCandidates = $Controller.GetType().GetMethods([System.Reflection.BindingFlags]'Public,NonPublic,Instance') |
        Where-Object { $_.Name -eq 'PutWithTupleResult' }

    $methodDump = Join-Path $script:OutputFolder ("putwithtuple_methods_{0}.txt" -f $Label)
    $putCandidates | ForEach-Object {
        $p = ($_.GetParameters() | ForEach-Object { "$($_.ParameterType.FullName) $($_.Name)" }) -join ', '
        "$($_.Name)($p) -> $($_.ReturnType.FullName) Generic=$($_.IsGenericMethodDefinition)"
    } | Out-File -Encoding UTF8 $methodDump

    if ($UseCertOverload) {
        $put = $putCandidates | Where-Object { $_.GetParameters().Count -eq 3 -and $_.GetParameters()[2].ParameterType.FullName -eq 'System.Security.Cryptography.X509Certificates.X509Certificate2' } | Select-Object -First 1
    }
    else {
        $put = $putCandidates | Where-Object { $_.GetParameters().Count -eq 3 -and $_.GetParameters()[2].ParameterType.FullName -ne 'System.Security.Cryptography.X509Certificates.X509Certificate2' } | Select-Object -First 1
    }

    if (-not $put) {
        Write-Step "PutWithTupleResult overload not found for $Label. Method dump: $methodDump"
        return $null
    }

    if ($put.IsGenericMethodDefinition) { $put = $put.MakeGenericMethod($sessionType) }

    Write-Step "PutWithTupleResult test [$Label] with SideCar session key: $($session.Key)"

    try {
        $third = if ($UseCertOverload) { $Certificate } else { $null }
        $task = $put.Invoke($Controller, @($session, $SessionId, $third))
        $tuple = Invoke-HSTaskResult -Task $task

        $success = $null
        $body = $null
        if ($tuple) {
            $successProp = $tuple.GetType().GetProperty('Item1')
            $bodyProp = $tuple.GetType().GetProperty('Item2')
            if ($successProp) { $success = $successProp.GetValue($tuple, $null) }
            if ($bodyProp) { $body = [string]$bodyProp.GetValue($tuple, $null) }
        }

        $len = if ($null -eq $body) { 0 } else { $body.Length }
        Write-Step "PutWithTupleResult [$Label] completed. Success=$success BodyLength=$len"

        $out = [ordered]@{
            Label = $Label
            Success = $success
            BodyLength = $len
            Body = $body
        }
        $outPath = Join-Path $script:OutputFolder ("putwithtuple_result_{0}.json" -f $Label)
        $out | ConvertTo-Json -Depth 10 | Out-File -Encoding UTF8 $outPath
        Write-Step "PutWithTupleResult [$Label] details saved to: $outPath"

        if ($body) {
            [void](Save-HSGetScriptRawResponse -RawResponse $body -Label ("PutWithTuple_{0}" -f $Label))
        }

        return $out
    }
    catch {
        $text = Get-HSInnerExceptionText -Exception $_.Exception
        $path = Join-Path $script:OutputFolder "putwithtuple_error_$Label.txt"
        $text | Out-File -Encoding UTF8 $path
        Write-Step "PutWithTupleResult [$Label] failed. Details saved to: $path"
        Write-Host $text
        return $null
    }
}

function Convert-HSPoliciesToSimpleObjects {
    param($Policies)
    $items = @()
    foreach ($p in $Policies) {
        $obj = [ordered]@{}
        foreach ($prop in $p.GetType().GetProperties([System.Reflection.BindingFlags]'Public,Instance')) {
            try {
                $val = $prop.GetValue($p, $null)
                if ($null -eq $val) { $obj[$prop.Name] = $null }
                elseif ($val -is [string] -or $val.GetType().IsPrimitive -or $val -is [Guid] -or $val -is [DateTime]) { $obj[$prop.Name] = $val.ToString() }
                else { $obj[$prop.Name] = $val.ToString() }
            } catch { }
        }
        $items += [pscustomobject]$obj
    }
    return $items
}


New-FolderIfMissing -Path $OutputFolder
$script:OutputFolder = $OutputFolder

Write-Step "Hybrid AgentCommon GetScript POC v18 starting."
Write-Step "This will acquire a SideCar WAM token with the downloader style helper, then inject that token into AgentCommon. With -RunAsSystem it does the AgentCommon call as SYSTEM so IME can add the user token like the real service."

Write-Step "Finding Intune MDM device certificate"
$certInfo = Get-IntuneMdmCertificateInfo
$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]$certInfo.Certificate
$script:CurrentMdmCert = $cert
Write-Step "Using certificate from $($certInfo.StorePath)"
Write-Step "Thumbprint: $($cert.Thumbprint)"
Write-Step "DeviceId: $($certInfo.DeviceId)"
Write-Step "AccountId: $($certInfo.AccountId)"

$sessionInfo = Get-HSLatestSessionFromLog -Path $HealthScriptsLog
if ($SessionId -eq -999) { $SessionId = [int]$sessionInfo.SessionId }
if ([string]::IsNullOrWhiteSpace($UserId)) { $UserId = [string]$sessionInfo.UserId }
Write-Step "Using SessionId: $SessionId"
Write-Step "Using UserId: $UserId"
Write-Step "Session source: $($sessionInfo.Source)"

$logEndpoint = Get-HSDirectSideCarEndpointFromLog -Path $HealthScriptsLog
$discoveredEndpoint = $null
if (-not [string]::IsNullOrWhiteSpace($SideCarEndpoint)) {
    $resolvedEndpoint = $SideCarEndpoint.TrimEnd('/')
    Write-Step "Using explicit SideCar endpoint: $resolvedEndpoint"
}
elseif ($PreferDirectEndpoint -and -not [string]::IsNullOrWhiteSpace($logEndpoint)) {
    $resolvedEndpoint = $logEndpoint.TrimEnd('/')
    Write-Step "Using direct SideCar endpoint from HealthScripts.log because -PreferDirectEndpoint was supplied: $resolvedEndpoint"
}
else {
    try { $discoveredEndpoint = Get-SideCarGatewayEndpoint -CertificateInfo $certInfo } catch { Write-Step "LocationService discovery failed: $($_.Exception.Message)" }
    if (-not [string]::IsNullOrWhiteSpace($discoveredEndpoint)) {
        $resolvedEndpoint = $discoveredEndpoint.TrimEnd('/')
        Write-Step "Using discovered TrafficGateway SideCar endpoint by default: $resolvedEndpoint"
    }
    elseif (-not [string]::IsNullOrWhiteSpace($logEndpoint)) {
        $resolvedEndpoint = $logEndpoint.TrimEnd('/')
        Write-Step "Falling back to direct SideCar endpoint from HealthScripts.log: $resolvedEndpoint"
    }
    else {
        throw 'Could not resolve SideCar endpoint from LocationService or HealthScripts.log.'
    }
}

$sideCarToken = $null
$tokenPayload = $null

if ($AccessTokenFile) {
    Write-Step "Reading existing SideCar token from: $AccessTokenFile"
    if (-not (Test-Path -LiteralPath $AccessTokenFile)) { throw "AccessTokenFile not found: $AccessTokenFile" }
    $tokenFileObject = Get-Content -LiteralPath $AccessTokenFile -Raw | ConvertFrom-Json
    $sideCarToken = [string]$tokenFileObject.Token
    if (-not [string]::IsNullOrWhiteSpace($tokenFileObject.Upn)) { $script:WamUserId = [string]$tokenFileObject.Upn }
}
else {
    Write-Step "Requesting SideCar WAM token with the known working downloader/compliance helper."
    $sideCarToken = Get-SideCarWamToken
}

if ([string]::IsNullOrWhiteSpace($sideCarToken)) { throw 'SideCar WAM token was empty.' }

$tokenPayload = Convert-HSJwtPayload -Token $sideCarToken
if ($tokenPayload) {
    $tokenPath = Join-Path $OutputFolder 'sidecar_wam_token_payload.json'
    $tokenPayload | ConvertTo-Json -Depth 20 | Out-File -Encoding UTF8 $tokenPath
    Write-Step "Saved SideCar token payload to: $tokenPath"
    try { Write-Step "Token aud: $($tokenPayload.aud)" } catch { }
    try { Write-Step "Token appid: $($tokenPayload.appid)" } catch { }
    try { Write-Step "Token upn/preferred_username: $($tokenPayload.upn) $($tokenPayload.preferred_username)" } catch { }
    if (-not $script:WamUserId) {
        if ($tokenPayload.upn) { $script:WamUserId = [string]$tokenPayload.upn }
        elseif ($tokenPayload.unique_name) { $script:WamUserId = [string]$tokenPayload.unique_name }
        elseif ($tokenPayload.preferred_username) { $script:WamUserId = [string]$tokenPayload.preferred_username }
    }
}

if ($RunAsSystem -and -not $SystemChild) {
    Write-Step "RunAsSystem was supplied. The user WAM token is acquired. Relaunching the AgentCommon part as SYSTEM so PrepareTokenAndCert can query the user token for session $SessionId."

    # Keep the temporary token bridge under ProgramData so SYSTEM can read it,
    # but keep all downloaded/decoded HealthScripts in the caller supplied OutputFolder.
    $programDataOut = Join-Path $env:ProgramData 'HealthScripts-AgentCommon-HybridToken-Poc'
    New-FolderIfMissing -Path $programDataOut
    New-FolderIfMissing -Path $OutputFolder

    $tokenBridgeFile = Join-Path $programDataOut ('sidecar_token_bridge_{0}.json' -f ([Guid]::NewGuid().ToString('N')))
    $bridge = [ordered]@{
        Token = $sideCarToken
        Upn = $script:WamUserId
        TokenAud = if ($tokenPayload) { $tokenPayload.aud } else { $null }
        TokenAppId = if ($tokenPayload) { $tokenPayload.appid } else { $null }
        Created = (Get-Date).ToString('o')
        OutputFolder = $OutputFolder
    }
    $bridge | ConvertTo-Json -Depth 10 | Set-Content -Path $tokenBridgeFile -Encoding UTF8
    Write-Step "Wrote temporary token bridge file for SYSTEM child: $tokenBridgeFile"
    Write-Step "SYSTEM child output folder: $OutputFolder"

    Start-HSSystemChild -TokenFile $tokenBridgeFile -SessionId $SessionId -UserId $UserId -ResolvedEndpoint $resolvedEndpoint -CertThumbprint $cert.Thumbprint -AgentImePath $ImePath -LogPath $HealthScriptsLog -OutFolder $OutputFolder -PolicyId $HealthScriptId -SkipProxy:$SkipPolicyProxy

    try { Remove-Item -LiteralPath $tokenBridgeFile -Force -ErrorAction SilentlyContinue } catch { }
    Write-Step "SYSTEM child completed. Token bridge file removed."
    return
}

$agentCommonPath = Join-Path $ImePath 'Microsoft.Management.Services.IntuneWindowsAgent.AgentCommon.dll'
$scriptPlugInPath = Join-Path $ImePath 'Microsoft.Management.Clients.IntuneManagementExtension.ScriptPlugIn.dll'
if (-not (Test-Path -LiteralPath $agentCommonPath)) { throw "AgentCommon not found: $agentCommonPath" }
if (-not (Test-Path -LiteralPath $scriptPlugInPath)) { throw "ScriptPlugIn not found: $scriptPlugInPath" }

Add-HSAssemblyResolver -Folder $ImePath

Write-Step "Loading AgentCommon: $agentCommonPath"
$agentAsm = [System.Reflection.Assembly]::LoadFrom($agentCommonPath)
Write-Step "Loading ScriptPlugIn: $scriptPlugInPath"
$scriptAsm = [System.Reflection.Assembly]::LoadFrom($scriptPlugInPath)

$envInfo = Initialize-HSAgentCommonEnvironment -AgentAssembly $agentAsm -CertificateInfo $certInfo -ResolvedSideCarEndpoint $resolvedEndpoint

$factoryType = Get-HSType -Assembly $agentAsm -TypeName 'Microsoft.Management.Services.IntuneWindowsAgent.AgentCommon.IntuneCommunicationManagerFactory'
$createMethod = $factoryType.GetMethods([System.Reflection.BindingFlags]'Public,NonPublic,Static') | Where-Object { $_.Name -eq 'Create' -and $_.GetParameters().Count -eq 1 } | Select-Object -First 1
if (-not $createMethod) { throw 'Could not find IntuneCommunicationManagerFactory.Create(EnvironmentInfo).' }

Write-Step "Creating IntuneController through IntuneCommunicationManagerFactory.Create"
$controller = $createMethod.Invoke($null, @($envInfo))
$service = $controller.GetType().GetProperty('Service').GetValue($controller, $null)
[void](Set-HSInstancePropertyValueIfPresent -Object $service -Name 'ServiceUri' -Value $resolvedEndpoint)
Write-Step "Set IntuneController.Service.ServiceUri: $resolvedEndpoint"

Write-Step "Creating static IClientTokenManager wrapper around the already acquired SideCar WAM token."
$staticTokenManager = New-HSStaticTokenManager -AccessToken $sideCarToken -Certificate $cert -AgentCommonPath $agentCommonPath -UserId $UserId -Upn $script:WamUserId

if (-not (Set-HSTokenManagerOnObject -Object $service -TokenManager $staticTokenManager)) {
    throw 'Could not replace IntuneController.Service.TokenManager.'
}
Write-Step "Injected static token manager into IntuneController.Service.TokenManager"

$discType = Get-HSType -Assembly $agentAsm -TypeName 'Microsoft.Management.Services.IntuneWindowsAgent.AgentCommon.DiscoveryService'
$discovery = [Activator]::CreateInstance($discType, @($envInfo))
try {
    if (Set-HSTokenManagerOnObject -Object $discovery -TokenManager $staticTokenManager) {
        Write-Step "Injected static token manager into DiscoveryService.TokenManager"
    }
} catch {
    Write-Step "DiscoveryService token manager injection skipped: $($_.Exception.Message)"
}

# Prefer tuple-result first. This is the path guarded by the HealthScripts EnablePutWithTupleResult flight for report upload,
# and it exposes the success flag/body instead of only returning an empty string.
$tupleCertResult = Invoke-HSControllerPutWithTupleDirect -Controller $controller -AgentAssembly $agentAsm -SessionId $SessionId -Certificate $cert -Label 'HybridCertOverload' -UseCertOverload
$tupleNullResult = Invoke-HSControllerPutWithTupleDirect -Controller $controller -AgentAssembly $agentAsm -SessionId $SessionId -Certificate $cert -Label 'HybridNullPolicyOverload'

# Keep this diagnostic because it does not swallow exceptions the way PolicyProxy does.
$directCertResult = Invoke-HSControllerPutDirect -Controller $controller -AgentAssembly $agentAsm -SessionId $SessionId -Certificate $cert -Label 'HybridCertOverload' -UseCertOverload
if ($directCertResult) {
    $directPath = Join-Path $OutputFolder 'direct_put_hybrid_cert_result.json'
    $directCertResult | Out-File -Encoding UTF8 $directPath
    Write-Step "Direct cert overload result saved to: $directPath"
}

$directNullResult = Invoke-HSControllerPutDirect -Controller $controller -AgentAssembly $agentAsm -SessionId $SessionId -Certificate $cert -Label 'HybridNullPolicyOverload'
if ($directNullResult) {
    $directPath = Join-Path $OutputFolder 'direct_put_hybrid_nullpolicy_result.json'
    $directNullResult | Out-File -Encoding UTF8 $directPath
    Write-Step "Direct null policy overload result saved to: $directPath"
}

if ($SkipPolicyProxy) {
    Write-Step "SkipPolicyProxy was supplied. Stopping after direct Put diagnostics."
    return
}

$proxyType = Get-HSType -Assembly $scriptAsm -TypeName 'Microsoft.Management.Clients.IntuneManagementExtension.ScriptPlugIn.PolicyProxy'
$proxy = [Activator]::CreateInstance($proxyType)
$getAssigned = $proxyType.GetMethods([System.Reflection.BindingFlags]'Public,NonPublic,Instance') |
    Where-Object { $_.Name -eq 'GetAssignedPolicies' -and $_.GetParameters().Count -eq 5 } |
    Select-Object -First 1
if (-not $getAssigned) { throw 'PolicyProxy.GetAssignedPolicies with five parameters not found.' }

Write-Step "Calling PolicyProxy.GetAssignedPolicies through IME DLLs with injected token manager."
Write-Step "SessionId: $SessionId"
Write-Step "UserId: $UserId"

try {
    $userGuid = [Guid]::Parse($UserId)
    $policies = $getAssigned.Invoke($proxy, @($controller, $discovery, $SessionId, $userGuid, $null))
}
catch {
    $text = Get-HSInnerExceptionText -Exception $_.Exception
    $path = Join-Path $OutputFolder 'policyproxy_exception.txt'
    $text | Out-File -Encoding UTF8 $path
    Write-Step "PolicyProxy threw. Details saved to: $path"
    Write-Host $text
    return
}

if ($null -eq $policies) {
    Write-Step "GetAssignedPolicies returned null. PolicyProxy swallowed the real exception or no response body was produced."

    Write-Step "Running raw GetScript fallback with the same endpoint/token/cert so we capture the real HTTP status/body."
    try {
        $rawFallback = Invoke-SideCarGetScript -Endpoint $resolvedEndpoint -Token $sideCarToken -CertificateInfo $certInfo -PayloadMode 'EmptyString' -AuthHeaderMode 'DeviceHeaders' -ODataKeySyntax 'String'
        $rawFallback | ConvertTo-Json -Depth 20 | Out-File -Encoding UTF8 (Join-Path $OutputFolder 'raw_getscript_fallback_result.json')
        if ($rawFallback.Success -and $rawFallback.Response) {
            $fallbackItems = ConvertFrom-ResponsePayload -SideCarResponse $rawFallback.Response
            $fallbackItems | ConvertTo-Json -Depth 30 | Out-File -Encoding UTF8 (Join-Path $OutputFolder 'raw_getscript_fallback_policies.json')
            Write-Step "Raw fallback policy count: $(@($fallbackItems).Count)"
        }
        elseif ($rawFallback.ErrorBodyPath) {
            Write-Step "Raw fallback failed. Details: $($rawFallback.ErrorBodyPath)"
        }
    }
    catch {
        $text = Get-HSInnerExceptionText -Exception $_.Exception
        $path = Join-Path $OutputFolder 'raw_getscript_fallback_exception.txt'
        $text | Out-File -Encoding UTF8 $path
        Write-Step "Raw fallback threw. Details saved to: $path"
    }

    if (Test-Path -LiteralPath $HealthScriptsLog) {
        $tailPath = Join-Path $OutputFolder 'healthscripts_log_tail.txt'
        Get-Content -LiteralPath $HealthScriptsLog -Tail 200 | Out-File -Encoding UTF8 $tailPath
        Write-Step "Saved HealthScripts.log tail to: $tailPath"
    }
    return
}

$items = Convert-HSPoliciesToSimpleObjects -Policies $policies
$allPath = Join-Path $OutputFolder 'getscript_policies_all.json'
$items | ConvertTo-Json -Depth 20 | Out-File -Encoding UTF8 $allPath
Write-Step "Policy count: $(@($items).Count)"
Write-Step "Saved all policies to: $allPath"

if ($HealthScriptId) {
    $matches = $items | Where-Object { $_.PolicyId -eq $HealthScriptId -or $_.Id -eq $HealthScriptId }
    $matchPath = Join-Path $OutputFolder 'getscript_policies_match.json'
    $matches | ConvertTo-Json -Depth 20 | Out-File -Encoding UTF8 $matchPath
    Write-Step "Match count for $HealthScriptId : $(@($matches).Count)"
    Write-Step "Saved match to: $matchPath"
}

$items | Select-Object PolicyId, Id, PolicyType, AccountId, TargetType, RunAsAccount, InternalVersion | Format-Table -AutoSize


try {
    if ($script:TranscriptPath) {
        Write-Step "Transcript saved to: $script:TranscriptPath"
        Stop-Transcript | Out-Null
    }
} catch { }
if ($WaitAtEnd) { [void](Read-Host 'Press Enter to close') }
