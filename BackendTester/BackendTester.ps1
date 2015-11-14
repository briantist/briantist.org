#Requires -Version 4.0

function Join-Uri {
[CmdletBinding(DefaultParameterSetName='ByParam')]
param(
    [Parameter(
        Mandatory,
        Position=0,
        ParameterSetName='ByParam'
    )]
    [Parameter(
        Mandatory,
        ValueFromPipeline,
        ParameterSetName='ByPipeline'
    )]
    [uri]
    $Base ,

    [Parameter(
        Mandatory,
        Position=1,
        ParameterSetName='ByParam'
    )]
    [Parameter(
        Mandatory,
        Position=0,
        ParameterSetName='ByPipeline'
    )]
    [string]
    $Child
)

    Process {
        ("{0}/{1}" -f $Base.ToString().TrimEnd('/'),$Child.TrimStart('/')) -as [uri]
    }
}

function ConvertTo-CFAuth {
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [PSCredential]
    $Credential
)

    @{
        'X-Auth-Key' = $Credential.GetNetworkCredential().Password
        'X-Auth-Email' = $Credential.UserName
    }
}

function Invoke-CFRequest {
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [Uri]
    $Base ,

    [Parameter(Mandatory)]
    [PSCredential]
    $Credential ,

    [Hashtable]
    $Body ,

    [ValidateSet(
         'Get'
        ,'Post'
        ,'Put'
        ,'Patch'
        ,'Delete'
    )]
    [String]
    $Method = 'Get'
)


    $u = $Base

    $param = @{
        Uri = $u
        Method = $Method
        Headers = ConvertTo-CFAuth $Credential
    }

    if ($Body) {
        $param.Body = $Body
    }

    $r = Invoke-RestMethod @param -ErrorAction Stop

    if ($r.Success) {
        $r
    } else {
        throw $r
    }

}

function Get-CFZoneId {
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [Uri]
    $Base ,

    [Parameter(Mandatory)]
    [PSCredential]
    $Credential ,

    [String]
    $Name
)

    $param = @{
        Base = $Base | Join-Uri 'zones'
        Credential = $Credential
    }

    if ($Name) {
        $param.Body = @{
            name = $Name
        }
    }

    $r = Invoke-CFRequest @param
    $r.result.id
}

function Get-CFZoneDnsRecord {
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [Uri]
    $Base ,

    [Parameter(Mandatory)]
    [PSCredential]
    $Credential ,

    [Parameter(
        Mandatory,
        ValueFromPipeline
    )]
    [ValidatePattern('^[a-fA-F0-9]+$')]
    [String]
    $ZoneId ,

    [Parameter()]
    [ValidateSet(
         'A'
        ,'AAAA'
        ,'CNAME'
        ,'TXT'
        ,'SRV'
        ,'LOC'
        ,'MX'
        ,'NS'
        ,'SPF'
    )]
    [String]
    $Type ,

    [Parameter()]
    [String]
    $Name ,

    [Parameter()]
    [String]
    $Content
)

    Process {
        $param = @{
            Base = $Base | Join-Uri 'zones' | Join-Uri $ZoneId | Join-Uri 'dns_records'
            Credential = $Credential
        }

        $body = @{}

        if ($Type) {
            $body.type = $Type
        }
        if ($Name) {
            $body.name = $Name
        }
        if ($Content) {
            $body.content = $Content
        }

        if ($body.Keys.Count) {
            $param.Body = $body
        }

        $r = Invoke-CFRequest @param

        $r.result
    }
}

function Test-Backend {
[CmdletBinding()]
param(
    [Parameter(
        Mandatory,
        ValueFromPipelineByPropertyName
    )]
    [Alias('content')]
    [System.Net.IPAddress]
    $IPAddress ,

    [Parameter(
        Mandatory,
        ValueFromPipelineByPropertyName
    )]
    [Alias('name')]
    $HostName ,

    [Parameter(
        Mandatory
    )]
    [ValidateNotNullOrEmpty()]
    [String]
    $Expect ,

    [Parameter()]
    [uint16]
    $TimeoutSeconds = 5 ,

    [uint16]
    $RetryTimes = 0 ,

    [uint16]
    $RetryDelay = 5 ,

    [ScriptBlock]
    $FailureAction
)

    Process {
        $rc = 0
        $v = $false
        while ($rc -le $RetryTimes) {
            try {
                $r = Invoke-WebRequest -Uri "http://$IPAddress" -UseBasicParsing -DisableKeepAlive -TimeoutSec $TimeoutSeconds -Headers @{ Host = $HostName } -MaximumRedirection 0 -ErrorAction Ignore
                Write-Verbose -Message "Status: $($r.StatusCode)"
                $v = $r -and $r.StatusCode -eq 200 -and $r.Content -match ([RegEx]::Escape($Expect))
                if ($v) {
                    break
                }
            } catch {
                Write-Verbose -Message "Catch?"
                $_ | Out-String | Write-Verbose
            }
            if ($rc++ -lt $RetryTimes) {
                Write-Verbose -Message "Retrying; attempt $rc of $RetryTimes. Waiting $RetryDelay seconds..."
                Start-Sleep -Seconds $RetryDelay
            }
        }
        if ($FailureAction -and !$v) {
            & $FailureAction
        }
        $v
    }
}

function Remove-CFDnsRecord {
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [Uri]
    $Base ,

    [Parameter(Mandatory)]
    [PSCredential]
    $Credential ,

    [Parameter(
        Mandatory,
        ValueFromPipelineByPropertyName
    )]
    [Alias('zone_id')]
    [ValidatePattern('^[a-fA-F0-9]+$')]
    [String]
    $ZoneId ,

    [Parameter(
        Mandatory,
        ValueFromPipelineByPropertyName
    )]
    [Alias('id')]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[a-fA-F0-9]+$')]
    [String]
    $Identifier
)

    Process {
        $param = @{
            Base = $Base | Join-Uri 'zones' | Join-Uri $ZoneId | Join-Uri 'dns_records' | Join-Uri $Identifier
            Credential = $Credential
            Method = 'Delete'
        }

        if ($PSCmdlet.ShouldProcess($Base)) {
            Write-Verbose -Message "Deleting DNS record with ID '$Identifier' in Zone ID '$ZoneId'"
            $r = Invoke-CFRequest @param
            $r.result.id
        }
    }
}

function Add-CFDnsRecord {
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [Uri]
    $Base ,

    [Parameter(Mandatory)]
    [PSCredential]
    $Credential ,

    [Parameter(
        Mandatory,
        ValueFromPipeline,
        ValueFromPipelineByPropertyName
    )]
    [Alias('zone_id')]
    [ValidatePattern('^[a-fA-F0-9]+$')]
    [String]
    $ZoneId ,

    [Parameter(
        Mandatory
    )]
    [ValidateSet(
         'A'
        ,'AAAA'
        ,'CNAME'
        ,'TXT'
        ,'SRV'
        ,'LOC'
        ,'MX'
        ,'NS'
        ,'SPF'
    )]
    [String]
    $Type ,

    [Parameter(
        Mandatory
    )]
    [String]
    $Name ,

    [Parameter(
        Mandatory
    )]
    [String]
    $Content ,

    [uint32]
    $TTL
)

    Begin {
        $param = @{
            Base = $Base | Join-Uri 'zones' | Join-Uri $ZoneId | Join-Uri 'dns_records'
            Credential = $Credential
            Method = 'Post'
        }
    }

    Process {
        $body = @{
            type = $Type
            name = $Name
            content = $Content
        }
        if ($TTL) {
            $body.ttl = $TTL
        }
        $param.Body = $body

        if ($PSCmdlet.ShouldProcess($Name)) {
            Write-Verbose -Message "Adding DNS record parameters:"
            $param | Out-String | Write-Verbose

            $r = Invoke-CFRequest @param
            $rid = $r.result.id

            Write-Verbose -Message "Created record ID '$rid'. Enabling Proxy."

            $param.Base = $param.Base | Join-Uri $rid
            $param.Method = 'Patch'
            $param.Body.proxied = $true
            $r = Invoke-CFRequest @param
            $r.result
        }
    }
}


$PSDefaultParameterValues = @{
    "Get-CF*:Base" =  'https://api.cloudflare.com/client/v4'
}

$backends = Import-Clixml -Path ($PSScriptRoot | Join-Path -ChildPath 'backends.xml')

