#Requires -Version 4.0

$tmpl = $PSScriptRoot | Join-Path -ChildPath 'index_template.html' | Get-Item | Get-Content -Raw

$PSScriptRoot | Join-Path -ChildPath 'Backends' | Get-ChildItem -Filter *.html | ForEach-Object {
    $provider = $_.BaseName
    $pin = $tmpl -creplace '@@CONTENT@@',(Get-Content $_.FullName -Raw)
    $pin | Set-Content -LiteralPath ($PSScriptRoot | Join-Path -ChildPath "index_$provider.html") -Force
}