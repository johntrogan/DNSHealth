function Read-AutoDiscoverRecord {
    <#
    .SYNOPSIS
    Check AutoDiscover DNS records for a domain

    .DESCRIPTION
    Resolves AutoDiscover DNS records (CNAME, A, and SRV) and validates the configuration.
    For Microsoft 365, the expected setup is a CNAME pointing to autodiscover.outlook.com.

    .PARAMETER Domain
    Domain to check AutoDiscover records for

    .PARAMETER ExpectedTarget
    Expected CNAME/SRV target to validate against. Defaults to autodiscover.outlook.com

    .EXAMPLE
    PS> Read-AutoDiscoverRecord -Domain example.com

    .EXAMPLE
    PS> Read-AutoDiscoverRecord -Domain example.com -ExpectedTarget 'autodiscover.custom.com'

    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter(Mandatory = $false)]
        [string]$ExpectedTarget = 'autodiscover.outlook.com'
    )

    $AutoDiscoverDomain = "autodiscover.$Domain"
    $SrvDomain = "_autodiscover._tcp.$Domain"

    $ValidationPasses = [System.Collections.Generic.List[string]]::new()
    $ValidationWarns = [System.Collections.Generic.List[string]]::new()
    $ValidationFails = [System.Collections.Generic.List[string]]::new()

    $CnameRecord = $null
    $ARecord = $null
    $SrvRecord = $null
    $RecordType = 'None'

    # Query autodiscover hostname - A query returns CNAME in chain if present
    $DnsResult = Resolve-DnsHttpsQuery -Domain $AutoDiscoverDomain
    if ($DnsResult.Answer) {
        $CnameRecord = ($DnsResult.Answer | Where-Object { $_.type -eq 5 }).data -replace '\.$'
        if ($CnameRecord) {
            $RecordType = 'CNAME'
            if ($CnameRecord -eq $ExpectedTarget) {
                $ValidationPasses.Add("AutoDiscover CNAME correctly points to $ExpectedTarget") | Out-Null
            } else {
                $ValidationWarns.Add("AutoDiscover CNAME points to $CnameRecord (expected $ExpectedTarget)") | Out-Null
            }
        } else {
            $ARecord = @(($DnsResult.Answer | Where-Object { $_.type -eq 1 }).data)
            if ($ARecord.Count -gt 0) {
                $RecordType = 'A'
                $ValidationWarns.Add("AutoDiscover is configured with an A record ($($ARecord -join ', ')) instead of the recommended CNAME to $ExpectedTarget") | Out-Null
            }
        }
    }

    # Check SRV record
    $SrvResult = Resolve-DnsHttpsQuery -Domain $SrvDomain -RecordType SRV
    if ($SrvResult.Answer) {
        $SrvData = ($SrvResult.Answer | Where-Object { $_.type -eq 33 }).data
        if ($SrvData) {
            # SRV data format: priority weight port target
            $SrvParts = $SrvData -split '\s+'
            $SrvTarget = if ($SrvParts.Count -ge 4) { $SrvParts[3] -replace '\.$' } else { $SrvData -replace '\.$' }
            $SrvRecord = $SrvTarget

            if ($RecordType -eq 'None') {
                $RecordType = 'SRV'
            }

            if ($SrvTarget -eq $ExpectedTarget) {
                $ValidationPasses.Add("AutoDiscover SRV record correctly points to $ExpectedTarget") | Out-Null
            } else {
                $ValidationWarns.Add("AutoDiscover SRV record points to $SrvTarget (expected $ExpectedTarget)") | Out-Null
            }
        }
    }

    # No records found at all
    if (-not $CnameRecord -and ($null -eq $ARecord -or $ARecord.Count -eq 0) -and -not $SrvRecord) {
        $ValidationFails.Add("No AutoDiscover DNS records found (checked CNAME, A, and SRV for $Domain)") | Out-Null
    }

    [PSCustomObject]@{
        Domain           = $AutoDiscoverDomain
        Record           = if ($CnameRecord) { $CnameRecord } elseif ($ARecord) { $ARecord -join ', ' } elseif ($SrvRecord) { $SrvRecord } else { $null }
        RecordType       = $RecordType
        CnameRecord      = $CnameRecord
        ARecord          = $ARecord
        SrvRecord        = $SrvRecord
        ExpectedTarget   = $ExpectedTarget
        ValidationPasses = @($ValidationPasses)
        ValidationWarns  = @($ValidationWarns)
        ValidationFails  = @($ValidationFails)
    }
}
