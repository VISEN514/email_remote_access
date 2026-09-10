# Installs the popup's bundled tactical-theme fonts (assets/fonts/) for the
# current user. Free/open-license (SIL OFL) Google Fonts -- see
# assets/fonts/LICENSE.txt. Safe to re-run; installing an already-installed
# font is a no-op.

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$FontsDir = Join-Path $ProjectRoot "assets\fonts"

$shell = New-Object -ComObject Shell.Application
$fontsFolder = $shell.Namespace(0x14)

$files = Get-ChildItem (Join-Path $FontsDir "*.ttf")
foreach ($f in $files) {
    Write-Host "Installing $($f.Name)..."
    $fontsFolder.CopyHere($f.FullName, 0x10)
}

Start-Sleep -Seconds 2
Add-Type -AssemblyName System.Drawing
$installed = (New-Object System.Drawing.Text.InstalledFontCollection).Families | Select-Object -ExpandProperty Name
foreach ($name in @("Black Ops One", "Chakra Petch", "Titillium Web")) {
    if ($installed -contains $name) {
        Write-Host "OK: $name is installed"
    } else {
        Write-Warning "$name did not register -- try installing assets\fonts manually (right-click -> Install)"
    }
}
