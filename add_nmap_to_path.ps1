# PowerShell script to add nmap to PATH
# Run this as Administrator

# Common nmap installation paths
$nmapPaths = @(
    "C:\Program Files (x86)\Nmap",
    "C:\Program Files\Nmap",
    "C:\Nmap"
)

$nmapPath = $null

# Find nmap installation
foreach ($path in $nmapPaths) {
    if (Test-Path "$path\nmap.exe") {
        $nmapPath = $path
        Write-Host "Found nmap at: $nmapPath" -ForegroundColor Green
        break
    }
}

if (-not $nmapPath) {
    Write-Host "Nmap not found in common locations. Please enter the path manually:" -ForegroundColor Yellow
    $nmapPath = Read-Host "Enter nmap installation path"
    
    if (-not (Test-Path "$nmapPath\nmap.exe")) {
        Write-Host "Error: nmap.exe not found at that path!" -ForegroundColor Red
        exit
    }
}

# Get current PATH
$currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")

# Check if already in PATH
if ($currentPath -like "*$nmapPath*") {
    Write-Host "Nmap is already in PATH!" -ForegroundColor Yellow
} else {
    # Add to PATH
    [Environment]::SetEnvironmentVariable("Path", "$currentPath;$nmapPath", "Machine")
    Write-Host "Nmap added to PATH successfully!" -ForegroundColor Green
    Write-Host "Please restart your terminal/IDE for changes to take effect." -ForegroundColor Cyan
}

# Test nmap
Write-Host "`nTesting nmap..." -ForegroundColor Cyan
& "$nmapPath\nmap.exe" --version

