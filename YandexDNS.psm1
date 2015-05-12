$YandexDnsApiUrl = "https://pddimp.yandex.ru/api2/admin/dns/"
Function Get-YandexDNSRecord
{
    <#
    .Synopsis
     Queries Yandex DNS API for existing record
    .Description 
     The Get-YandexDNSRecord function uses Yandex DNS API to find existing DNS
     record
    .Example
     Get-YandexDNSRecord -Name my.example.com -Type A -Token ABCDABCDABCDABCDABCD
     Queries for record of 'A' type with name 'my' for domain 'example.com'
    .Parameter Name
     FQDN for quering
    .Parameter Type
     Type of DNS record
    .Parameter Token
     Yandex PDD token. See more at https://tech.yandex.ru/pdd/doc/concepts/access-docpage/#access-admin
    .Inputs
     [string]
    .Outputs
     [string]
    .Notes
     NAME: Get-YandexDNSRecord
     AUTHOR: Andrey Korotkov
     LASTEDIT: 21/04/2015
     KEYWORDS:
     .Link
      Http://github.com/user/potapum
    #Requires -Version 2.0
    #>
    [CmdletBinding()]
    param(
          #[Parameter(Mandatory = $true,Position = 0,valueFromPipeline = $true)]
          [string]$Name,
          [string]$Type,
          [string]$Token
    ) #end param

    ##Code
    $YandexDnsApiActionUrl = "list"

    $headers = @{}
    $headers.Add("PddToken",$Token)
    $SplittedName = $Name.Split(".")
    [string]$domain = $SplittedName[1..$SplittedName.Count] -join "."

    $postParams = @{domain=$domain}
    $uri = $YandexDnsApiUrl+$YandexDnsApiActionUrl


    $result = Invoke-WebRequest -Uri $uri -Method GET -Headers $headers -Body $postParams

    if ($result.content -match '\[.*\]') { $AllDNSRecords = $Matches[0] -Replace "\[{|}\]|\n","" }
    $DNSRecords = $AllDNSRecords -Split '\}, {' 

    $YandexDNSRecords = @()

    ForEach ($DNSRecord in $DNSRecords) {
        $content = ""
        $domain = ""
        $weight = ""
        $fqdn = ""
        $port = ""
        $priority = ""
        $ttl = ""
        $record_id = ""
        $subdomain = ""
        $recordtype = ""
        $DNSRecordParams = $DNSRecord -split ',\s'
        foreach ($DNSRecordParam in $DNSRecordParams) {
            $DNSRecordParamSplit = $DNSRecordParam.split(" ")
            [string]$DNSRecordParamName = $DNSRecordParamSplit[0] -replace ':|"',""
            [string]$DNSRecordParamValue = $DNSRecordParamSplit[1] -replace '"|\s',""
        
            switch ($DNSRecordParamName) {
                "content"{$content = $DNSRecordParamValue}
                "domain"{$domain = $DNSRecordParamValue}
                "weight"{$weight = $DNSRecordParamValue}
                "fqdn"{$fqdn = $DNSRecordParamValue}
                "port"{$port = $DNSRecordParamValue}
                "priority"{$priority = $DNSRecordParamValue}
                "ttl"{$ttl = $DNSRecordParamValue}
                "record_id"{$record_id = $DNSRecordParamValue}
                "subdomain"{$subdomain = $DNSRecordParamValue}
                "type"{$recordtype = $DNSRecordParamValue}  
            }
        }
        $YandexDNSRecords += New-DNSRecord -content $content -domain $domain -weight $weight -fqdn $fqdn -port $port -priority $priority -ttl $ttl -record_id $record_id -subdomain $subdomain -type $recordtype
   
    
    }
    
    foreach ($YandexDNSRecord in $YandexDNSRecords) {
        if (($YandexDNSRecord.FQDN -eq $Name) -and ($YandexDNSRecord.Type -eq $Type)) {
        #if ($YandexDNSRecord.FQDN -eq $Name) {
            return $YandexDNSRecord
        } 
    }

}
Function Set-YandexDNSRecord
{
    <#
    .Synopsis
     Updates Yandex DNS Record using API
    .Description 
     The New-YandexDNSRecord function uses Yandex DNS API to update DNS record
     record
    .Example
     Set-YandexDNSRecord -Domain example.com -Type A -Token ABCDABCDABCDABCDABCD -TTL 14400 -Subdomain my -Content 198.51.100.1
     Updates DNS record of 'A' type with name 'my' for domain 'example.com' and IP address 198.51.100.1 .
    .Example
     Set-YandexDNSRecord -Domain example.com -Type CNAME -Token ABCDABCDABCDABCDABCD -TTL 14400 -Subdomain my -Content notmy.example.org
     Updates DNS record of type CNAME with name my for domain example.com which points to notmy.example.org hostname.
    .Parameter Domain
     Domain in which record should be updated
    .Parameter Type
     Type of DNS record
    .Parameter Token
     Yandex PDD token. See more at https://tech.yandex.ru/pdd/doc/concepts/access-docpage/#access-admin
    .Parameter TTL
     Time to live prameter for DNS record
    .Parameter Subdomain
     Name of DNS record
    .Parameter Content
     Content which record will contain. May warry depends on record type
    .Inputs
     [string]
    .Outputs
     [string]
    .Notes
     NAME: Set-YandexDNSRecord
     AUTHOR: Andrey Korotkov
     LASTEDIT: 21/04/2015
     KEYWORDS:
     .Link
      Http://github.com/user/potapum
    #Requires -Version 2.0
    #>
    [CmdletBinding()]
    param(
          #[Parameter(Mandatory = $true,Position = 0,valueFromPipeline = $true)]
          [string]$Domain,
          [string]$Type,
          [string]$Token,
          [int]$TTL,
          [string]$Subdomain,
          [string]$Content
    ) #end param
    ##Code
    $YandexDnsApiActionUrl = "edit"

    $DNSRecord = Get-YandexDNSRecord -Name $($Subdomain+'.'+$Domain) -type $Type -Token $Token
    
    if ($DNSRecord -ne $null) {
        $headers = @{}
        $headers.Add("PddToken",$Token)
        $postParams = @{domain=$Domain;type=$Type;ttl=$TTL;subdomain=$Subdomain;content=$Content;record_id=$DNSRecord.RecordId}
        
        $uri = $YandexDnsApiUrl+$YandexDnsApiActionUrl

        $result = Invoke-WebRequest -Uri $uri -Method POST -Headers $headers -Body $postParams
        return $result.content
    }
    else{
        return "DNS Record not exist use New-YandexDNSRecord"
    }
}
Function New-YandexDNSRecord
{
    <#
    .Synopsis
     Creates new Yandex DNS Record using API
    .Description 
     The New-YandexDNSRecord function uses Yandex DNS API to create new DNS record
     record
    .Example
     New-YandexDNSRecord -Domain example.com -Type A -Token ABCDABCDABCDABCDABCD -TTL 14400 -Subdomain my -Content 198.51.100.1
     Creates new DNS record of 'A' type with name 'my' for domain 'example.com' and IP address 198.51.100.1 .
    .Example
     New-YandexDNSRecord -Domain example.com -Type CNAME -Token ABCDABCDABCDABCDABCD -TTL 14400 -Subdomain my -Content notmy.example.org
     Creates new DNS record of type CNAME with name my for domain example.com which points to notmy.example.org hostname.
    .Parameter Domain
     Domain in which record should be created
    .Parameter Type
     Type of DNS record
    .Parameter Token
     Yandex PDD token. See more at https://tech.yandex.ru/pdd/doc/concepts/access-docpage/#access-admin
    .Parameter TTL
     Time to live prameter for DNS record
    .Parameter Subdomain
     Name of DNS record
    .Parameter Content
     Content which record will contain. May warry depends on record type/
    .Inputs
     [string]
    .Outputs
     [string]
    .Notes
     NAME: New-YandexDNSRecord
     AUTHOR: Andrey Korotkov
     LASTEDIT: 21/04/2015
     KEYWORDS:
     .Link
      Http://github.com/user/potapum
    #Requires -Version 2.0
    #>
    [CmdletBinding()]
    param(
          #[Parameter(Mandatory = $true,Position = 0,valueFromPipeline = $true)]
          [string]$Domain,
          [string]$Type,
          [string]$Token,
          [int]$TTL,
          [string]$Subdomain,
          [string]$Content
    ) #end param
    ##Code
    $YandexDnsApiActionUrl = "add"
    
    $fqdn = $Subdomain+"."+$Domain
    $testrecord = Get-YandexDNSRecord -Name $fqdn -Token $Token -Type $Type
    $check = $testrecord -eq $null
     
    if ($check) {
        $headers = @{}
        $headers.Add("PddToken",$Token)
        $postParams = @{domain=$Domain;type=$Type;ttl=$TTL;subdomain=$Subdomain;content=$Content}
        
        $uri = $YandexDnsApiUrl+$YandexDnsApiActionUrl

        $result = Invoke-WebRequest -Uri $uri -Method POST -Headers $headers -Body $postParams
        return $result.content
    }
    else {
        return "Record already exists use Set-YandexDNSRecord"
    }
}
Function New-DNSRecord
{
    param 
    (
        [string]$content,
        [string]$domain,
        [int]$weight,
        [string]$fqdn,
        [int]$port,
        [int]$priority,
        [int]$ttl,
        [int]$record_id,
        [string]$subdomain,
        [string]$type
    )
    $dns_record = New-Object -TypeName PSObject
    $dns_record | Add-Member -MemberType NoteProperty -Name Content -Value $content
    $dns_record | Add-Member -MemberType NoteProperty -Name Domain -Value $domain
    $dns_record | Add-Member -MemberType NoteProperty -Name Weight -Value $weight
    $dns_record | Add-Member -MemberType NoteProperty -Name FQDN -Value $fqdn
    $dns_record | Add-Member -MemberType NoteProperty -Name Port -Value $port
    $dns_record | Add-Member -MemberType NoteProperty -Name Priority -Value $priority
    $dns_record | Add-Member -MemberType NoteProperty -Name TTL -Value $ttl
    $dns_record | Add-Member -MemberType NoteProperty -Name RecordID -Value $record_id
    $dns_record | Add-Member -MemberType NoteProperty -Name Subdomain -Value $subdomain
    $dns_record | Add-Member -MemberType NoteProperty -Name Type -Value $type

    $dns_record
}
