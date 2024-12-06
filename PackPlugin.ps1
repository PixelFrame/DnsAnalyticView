$BuildPath = Join-Path $PSScriptRoot $args[0]
$PackPath = Join-Path $BuildPath 'Pack'

mkdir $PackPath | Out-Null
Get-ChildItem -Path $BuildPath -Filter *.ptix | Remove-Item -Force
Get-ChildItem -Path $BuildPath -Exclude 'Pack','Microsoft.Performance.SDK.dll','System*','*.pdb' | Copy-Item -Destination $PackPath -Recurse -Force

Push-Location $PackPath
plugintool pack -s .\
Pop-Location

Get-ChildItem -Path $PackPath -Filter *.ptix | Move-Item -Destination $BuildPath -Force
Remove-Item -Path $PackPath -Recurse -Force
Write-Host "Pack completed"
