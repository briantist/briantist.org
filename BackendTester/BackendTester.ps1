#Requires -Version 4.0

$PSDefaultParameterValues = @{
    "Get-CF*:Base" =  'https://api.cloudflare.com/client/v4'
}


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
    $Body
)


    $u = $Base

    $param = @{
        Uri = $u
        Method = 'Get'
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