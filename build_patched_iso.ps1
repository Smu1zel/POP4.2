# PowerShell script to copy ISO contents, patch boot.wim and install.wim, and rebuild a bootable UEFI/BIOS ISO

param(
    [Parameter(Mandatory=$false)]
    [string]$IsoDrive = "D:",
    
    [Parameter(Mandatory=$false)]
    [int]$Index = $null,
    
    [Parameter(Mandatory=$false)]
    [string]$WorkDir = $null,
    
    [Parameter(Mandatory=$false)]
    [string]$OscdimgPath = $null,
    
    [switch]$BootOnly
)

$ErrorActionPreference = "Stop"

if ([version](Get-CimInstance Win32_OperatingSystem).Version -lt [version]"6.2") {
    throw "At least Windows 8 (NT 6.2) is required to run this script."
}

# Resolve workDir (defaults to script directory, falling back to current working directory)
if ([string]::IsNullOrEmpty($WorkDir)) {
    $workDir = $PSScriptRoot
    if (-not $workDir) {
        $workDir = (Get-Location).Path
    }
} else {
    $workDir = $WorkDir
}

# Resolve oscdimgPath (checks ADK path, system PATH, then MiniTool fallback)
if ([string]::IsNullOrEmpty($OscdimgPath)) {
    $oscdimgPath = "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\oscdimg.exe"
    if (-not (Test-Path $oscdimgPath)) {
        $oscdimgCmd = Get-Command oscdimg -ErrorAction SilentlyContinue
        if ($oscdimgCmd) {
            $oscdimgPath = $oscdimgCmd.Source
        } else {
            $miniToolPath = "C:\Program Files\MiniTool Partition Wizard 13\oscdimg.exe"
            if (Test-Path $miniToolPath) {
                $oscdimgPath = $miniToolPath
            }
        }
    }
} else {
    $oscdimgPath = $OscdimgPath
}

if (-not (Test-Path $oscdimgPath)) {
    throw "Error: oscdimg.exe not found! Please install the Windows ADK or specify -OscdimgPath."
}

# Configuration Paths relative to workDir
$isoFilesDir = "$workDir\iso_files"
$localBootWim = "$workDir\boot.wim"
$localInstallWim = "$workDir\install.wim"
$mountDir = "$workDir\mount"
$patchedKernel = "$workDir\ntoskrnl.exe"
$outputIso = "$workDir\patched_install.iso"

Write-Host "======================================================="
Write-Host "STARTING PATCHED ISO BUILD PROCESS"
Write-Host "======================================================="
Write-Host "Source ISO Drive:   $IsoDrive"
Write-Host "Selected OS Index:  $(if ($BootOnly) { 'N/A (BootOnly)' } elseif ($Index) { $Index } else { 'All' })"
Write-Host "Boot Only Mode:     $BootOnly"
Write-Host "======================================================="

# Step 1: Clean up any stale mounts and registry locks
Write-Host "Cleaning up mount folders and registry locks..."
# Unload any dangling hives from previous failed/interrupted runs to release file locks
cmd.exe /c "reg unload HKLM\OfflineSystem >nul 2>nul"

dism /Cleanup-Mountpoints | Out-Null
if (Test-Path $mountDir) {
    # If the folder is still locked/mounted, try to force dismount it discarding changes
    dism /Unmount-Image /MountDir:$mountDir /Discard 2>&1 | Out-Null
    Remove-Item -Path $mountDir -Recurse -Force -ErrorAction SilentlyContinue
}
if (-not (Test-Path $mountDir)) {
    New-Item -Path $mountDir -ItemType Directory -Force | Out-Null
}

# Step 2: Copy ISO contents to workspace folder using multi-threaded Robocopy
$installImageExists = (Test-Path "$isoFilesDir\sources\install.wim") -or (Test-Path "$isoFilesDir\sources\install.esd")
if (-not (Test-Path $isoFilesDir) -or -not $installImageExists) {
    if (-not (Test-Path "$IsoDrive\sources")) {
        throw "Error: Could not find Windows ISO files on drive $IsoDrive. Please verify the drive letter!"
    }
    Write-Host "Copying files from mounted ISO ($IsoDrive) to local directory..."
    if (-not (Test-Path $isoFilesDir)) {
        New-Item -Path $isoFilesDir -ItemType Directory -Force | Out-Null
    }
    robocopy "$IsoDrive\" "$isoFilesDir\" /E /MT:8 /R:1 /W:1 | Out-Null
} else {
    Write-Host "Using existing ISO files directory."
}


# Helper function to apply patches to a mounted WIM folder
function Apply-PatchesToMount {
    param([string]$targetMountDir)
    
    # A. Inject patched kernel
    Write-Host "  Injecting patched ntoskrnl.exe..."
    if (-not (Test-Path $patchedKernel)) {
        throw "Error: Patched ntoskrnl.exe not found at $patchedKernel. Please compile it first!"
    }
    
    $targetKernelPath = "$targetMountDir\Windows\System32\ntoskrnl.exe"
    if (Test-Path $targetKernelPath) {
        Write-Host "  Taking ownership of original ntoskrnl.exe to allow overwriting..."
        takeown /f $targetKernelPath /a | Out-Null
        icacls $targetKernelPath /grant administrators:F | Out-Null
    }
    Copy-Item -Path $patchedKernel -Destination $targetKernelPath -Force
    Write-Host "  Successfully injected patched ntoskrnl.exe."

    # B. Inject replacement blobs from badblobs.txt
    $badBlobsPath = "$workDir\badblobs.txt"
    if (-not (Test-Path $badBlobsPath)) {
        throw "Error: badblobs.txt not found at $badBlobsPath. Please create it!"
    }
    if (Test-Path $badBlobsPath) {
        Write-Host "  Parsing badblobs.txt for replacement files..."
        $blobLines = Get-Content $badBlobsPath
        
        $sourceDir = "$workDir\source_23h2"
        if (-not (Test-Path $sourceDir)) {
            New-Item -ItemType Directory -Path $sourceDir | Out-Null
        }
        
        foreach ($line in $blobLines) {
            if ($line -match "^\s*-\s*([^\s(]+)(?:\s*\(([^)]+)\))?") {
                $blob = $Matches[1].Trim()
                $relPath = if ($Matches[2]) { $Matches[2].Trim() } else { $null }
                
                $sourceFile = "$sourceDir\$blob"
                if (-not (Test-Path $sourceFile)) {
                    $sourceFile = "$workDir\$blob" # Fallback to checking root directory
                }
                
                if (-not (Test-Path $sourceFile)) {
                    Write-Warning "  Replacement file '$blob' listed in badblobs.txt but not found in '$sourceDir' or root workspace. Skipping."
                    continue
                }
                
                if ($relPath) {
                    # Explicit path replacement
                    $targetPath = Join-Path -Path $targetMountDir -ChildPath $relPath
                    if (Test-Path $targetPath) {
                        Write-Host "    Replacing '$blob' (explicit path) at $targetPath..."
                        takeown /f $targetPath /a | Out-Null
                        icacls $targetPath /grant administrators:F | Out-Null
                        Copy-Item -Path $sourceFile -Destination $targetPath -Force
                        Write-Host "    Successfully replaced '$blob'."
                    } else {
                        Write-Warning "    Target path '$relPath' specified for '$blob' does not exist in this image index. Skipping."
                    }
                } else {
                    # Fallback to recursive search
                    Write-Host "  Searching for '$blob' inside mounted image..."
                    $targetFiles = Get-ChildItem -Path $targetMountDir -Filter $blob -Recurse -File -ErrorAction SilentlyContinue
                    
                    if ($targetFiles.Count -eq 0) {
                        Write-Host "    No instances of '$blob' found in mounted image."
                    } else {
                        foreach ($target in $targetFiles) {
                            Write-Host "    Replacing '$blob' at $($target.FullName)..."
                            takeown /f $target.FullName /a | Out-Null
                            icacls $target.FullName /grant administrators:F | Out-Null
                            Copy-Item -Path $sourceFile -Destination $target.FullName -Force
                            Write-Host "    Successfully replaced '$blob'."
                        }
                    }
                }
            }
        }
    }

    # C. Disable integrity checks in system hive
    Write-Host "  Modifying offline registry to disable integrity checks..."
    $systemHivePath = "$targetMountDir\Windows\System32\config\SYSTEM"
    
    reg load HKLM\OfflineSystem $systemHivePath | Out-Null
    try {
        $registryPath = "HKLM:\OfflineSystem\ControlSet001\Control"
        if (Test-Path $registryPath) {
            $options = (Get-ItemProperty -Path $registryPath -Name "SystemStartOptions" -ErrorAction SilentlyContinue).SystemStartOptions
            $newOptions = "DISABLE_INTEGRITY_CHECKS TESTSIGNING"
            Set-ItemProperty -Path $registryPath -Name "SystemStartOptions" -Value $newOptions
            Write-Host "  Updated SystemStartOptions to: $newOptions"
        }
    } finally {
        reg unload HKLM\OfflineSystem | Out-Null
    }
    
}

# =======================================================
# PART 1: PATCH BOOT.WIM (Index 2 for Setup Wizard)
# =======================================================
Write-Host "`n>>> STEP 3: Patching boot.wim (Setup Environment)..."
Copy-Item -Path "$isoFilesDir\sources\boot.wim" -Destination $localBootWim -Force
Set-ItemProperty -Path $localBootWim -Name IsReadOnly -Value $false

Write-Host "Mounting boot.wim (Index 2)..."
dism /Mount-Image /ImageFile:$localBootWim /Index:2 /MountDir:$mountDir
if ($LastExitCode -ne 0) {
    throw "Error: Failed to mount boot.wim Index 2. Verify DISM status!"
}

try {
    Apply-PatchesToMount -targetMountDir $mountDir
} catch {
    Write-Host "Error occurred while patching boot.wim: $_"
    dism /Unmount-Image /MountDir:$mountDir /Discard
    exit 1
}

Write-Host "Dismounting and committing boot.wim..."
dism /Unmount-Image /MountDir:$mountDir /Commit
Move-Item -Path $localBootWim -Destination "$isoFilesDir\sources\boot.wim" -Force
Write-Host "boot.wim patch complete."

if (-not $BootOnly) {
    # =======================================================
    # PART 2: PATCH INSTALL IMAGE (install.wim / install.esd)
    # =======================================================
    Write-Host "`n>>> STEP 4: Patching install image (Main OS Environment)..."
    $installImage = ""
    $isEsd = $false
    
    if (Test-Path "$isoFilesDir\sources\install.wim") {
        $installImage = "$isoFilesDir\sources\install.wim"
    } elseif (Test-Path "$isoFilesDir\sources\install.esd") {
        $installImage = "$isoFilesDir\sources\install.esd"
        $isEsd = $true
    } else {
        throw "Error: Could not locate install.wim or install.esd in sources directory!"
    }
    
    # Determine the indexes to patch by checking image info
    $info = & dism /Get-ImageInfo /ImageFile:$installImage
    $indexMatches = [regex]::Matches($info, "(?i)Index\s*:\s*(\d+)")
    
    if ($indexMatches.Count -eq 0) {
        throw "Error: Could not find any indexes in $installImage!"
    }
    
    $indexesToPatch = @()
    if ($Index) {
        # Verify the selected index exists in the image
        $found = $false
        foreach ($match in $indexMatches) {
            if ([int]$match.Groups[1].Value -eq $Index) {
                $found = $true
                break
            }
        }
        if (-not $found) {
            throw "Error: The specified Index $Index does not exist in $installImage!"
        }
        $indexesToPatch += $Index
    } else {
        # If no index is specified, target all of them
        foreach ($match in $indexMatches) {
            $indexesToPatch += [int]$match.Groups[1].Value
        }
        Write-Host "No specific Index specified. Targeting all indexes: ($($indexesToPatch -join ', '))"
    }
    
    # Clear any legacy local install.wim before starting
    if (Test-Path $localInstallWim) {
        Remove-Item -Path $localInstallWim -Force
    }
    
    if ($isEsd) {
        Write-Host "Detected install.esd. Exporting selected indexes to install.wim..."
        foreach ($idx in $indexesToPatch) {
            Write-Host "  Exporting index $idx..."
            # If we export multiple indexes to the same destination WIM, DISM appends them
            dism /Export-Image /SourceImageFile:$installImage /SourceIndex:$idx /DestinationImageFile:$localInstallWim /Compress:max
        }
        
        # After exporting, the local WIM will contain N indexes corresponding to our exported list (1, 2, ... N)
        $localIndexes = 1..($indexesToPatch.Count)
    } else {
        Write-Host "Copying install.wim to workspace..."
        Copy-Item -Path $installImage -Destination $localInstallWim -Force
        Set-ItemProperty -Path $localInstallWim -Name IsReadOnly -Value $false
        
        # We patch the copied indexes directly
        $localIndexes = $indexesToPatch
    }
    
    # Mount and patch each index in our list
    foreach ($idxToMount in $localIndexes) {
        $originalIndexInfo = if ($isEsd) { $indexesToPatch[$idxToMount - 1] } else { $idxToMount }
        Write-Host "`nMounting install.wim Index $idxToMount (Original Index: $originalIndexInfo)..."
        dism /Mount-Image /ImageFile:$localInstallWim /Index:$idxToMount /MountDir:$mountDir
        if ($LastExitCode -ne 0) {
            throw "Error: Failed to mount install.wim Index $idxToMount!"
        }
        
        try {
            Apply-PatchesToMount -targetMountDir $mountDir
        } catch {
            Write-Host "Error occurred while patching install.wim Index $($idxToMount): $_"
            dism /Unmount-Image /MountDir:$mountDir /Discard
            exit 1
        }
        
        Write-Host "Dismounting and committing install.wim Index $idxToMount..."
        dism /Unmount-Image /MountDir:$mountDir /Commit
    }
    
    # Replace original install image in the ISO folder
    if ($isEsd) {
        Write-Host "Removing original install.esd and replacing with patched install.wim..."
        Remove-Item -Path "$isoFilesDir\sources\install.esd" -Force
    }
    Move-Item -Path $localInstallWim -Destination "$isoFilesDir\sources\install.wim" -Force
    Write-Host "Install image patch complete."
} else {
    Write-Host "`n>>> STEP 4: Skipped (BootOnly mode - install image not modified)."
}

# =======================================================
# BCD PATCHES: Enable Testsigning & Legacy F8 Menu on ISO
# =======================================================
Write-Host "`n>>> STEP 4.5: Modifying ISO BCD stores..."
$bcdStores = @(
    "$isoFilesDir\boot\bcd",
    "$isoFilesDir\efi\microsoft\boot\bcd"
)

foreach ($bcd in $bcdStores) {
    if (Test-Path $bcd) {
        Write-Host "  Patching BCD at $bcd..."
        # Clear Read-Only attribute (copied from ISO)
        Set-ItemProperty -Path $bcd -Name IsReadOnly -Value $false
        # 1. Disable integrity checks for the loader
        & bcdedit /store $bcd /set "{default}" nointegritychecks Yes
        & bcdedit /store $bcd /set "{default}" testsigning Yes
        # 2. Enable legacy F8 boot menu and recovery options
        & bcdedit /store $bcd /set "{default}" recoveryenabled Yes
        & bcdedit /store $bcd /set "{default}" advancedoptions Yes
        & bcdedit /store $bcd /set "{default}" bootmenupolicy legacy
    }
}

# =======================================================
# PART 3: REBUILD THE ISO
# =======================================================
Write-Host "`n>>> STEP 5: Rebuilding bootable ISO..."
$etfsboot = "$isoFilesDir\boot\etfsboot.com"
$efisys = "$isoFilesDir\efi\microsoft\boot\efisys.bin"

$oscdimgArgs = @(
    "-m",
    "-o",
    "-u2",
    "-udfver102",
    "-bootdata:2#p0,e,b`"$etfsboot`"#pEF,e,b`"$efisys`"",
    "`"$isoFilesDir`"",
    "`"$outputIso`""
)

& $oscdimgPath $oscdimgArgs

# Clean up temporary folder
if (Test-Path $mountDir) {
    Remove-Item -Path $mountDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "`n======================================================="
Write-Host "SUCCESS: Patched ISO created successfully!"
Write-Host "Output File: $outputIso"
Write-Host "======================================================="
