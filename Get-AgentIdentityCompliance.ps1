#Requires -Version 7.0
<#
.SYNOPSIS
    Assesses Microsoft Entra agent identities for missing owners and sponsors.
.DESCRIPTION
    Enumerates Microsoft Entra agent identities through Microsoft Graph v1.0
    and checks each identity's owner and sponsor relationships.

    An identity is marked compliant only when both relationships have at
    least one assigned object. This is the author's governance baseline;
    Microsoft requires a sponsor but considers owners optional.

    Produces a full CSV inventory, a noncompliant CSV report, and an offline
    HTML dashboard. Only GET requests are sent to Microsoft Graph; no agent
    identity assignments are changed.

    Requires Microsoft Graph app-only authentication. The sponsor listing
    API requires AgentIdentity.ReadWrite.All application permission, even
    though the script performs read-only operations. Other permissions
    used for owner and display-name retrieval are Application.Read.All,
    User.Read.All, and GroupMember.Read.All. Directory.Read.All may be
    needed for fallback lookups of other directory object types.

    See README.md for setup, examples, limitations, and Microsoft Learn links.
.PARAMETER TenantId
    Microsoft Entra tenant ID for certificate authentication.
.PARAMETER ClientId
    Application (client) ID for certificate authentication.
.PARAMETER CertificateThumbprint
    Thumbprint of a certificate with an accessible private key.
.PARAMETER ManagedIdentity
    Uses a system-assigned managed identity in a supported Azure host.
.PARAMETER OutputDirectory
    Directory for the generated CSV and HTML files. Defaults to the
    current working directory.
.EXAMPLE
    ./Get-AgentIdentityCompliance.ps1 -TenantId '<tenant-id>' `
        -ClientId '<application-client-id>' `
        -CertificateThumbprint '<certificate-thumbprint>' `
        -OutputDirectory './Reports'
.EXAMPLE
    ./Get-AgentIdentityCompliance.ps1 -ManagedIdentity -OutputDirectory './Reports'
.NOTES
    Provided as-is without warranty. I am not responsible for changes
    made by third parties or for outcomes resulting from those changes.
#>
[CmdletBinding(DefaultParameterSetName = 'Certificate')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Certificate')]
    [string]$TenantId,

    [Parameter(Mandatory, ParameterSetName = 'Certificate')]
    [string]$ClientId,

    [Parameter(Mandatory, ParameterSetName = 'Certificate')]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory, ParameterSetName = 'ManagedIdentity')]
    [switch]$ManagedIdentity,

    [Parameter()]
    [string]$OutputDirectory = (Get-Location).Path
)

$ErrorActionPreference = 'Stop'
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

$connected = $false
try {

if ($PSCmdlet.ParameterSetName -eq 'ManagedIdentity') {
    Connect-MgGraph -Identity -ContextScope Process -NoWelcome -ErrorAction Stop
}
else {
    Connect-MgGraph -TenantId $TenantId -ClientId $ClientId `
        -CertificateThumbprint $CertificateThumbprint -ContextScope Process -NoWelcome -ErrorAction Stop
}

$connected = $true

if ((Get-MgContext).AuthType -ne 'AppOnly') {
    throw 'App-only Microsoft Graph authentication is required to list agent identity sponsors.'
}

function Get-GraphCollection {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Uri)

    $results = [System.Collections.Generic.List[object]]::new()

    # Follow @odata.nextLink so more than 100 agent identities are assessed.
    while (-not [string]::IsNullOrWhiteSpace($Uri)) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $Uri `
            -OutputType PSObject -ErrorAction Stop

        if ($null -eq $page -or $null -eq $page.value) {
            throw "Unexpected response while reading Graph collection: $Uri"
        }

        foreach ($item in $page.value) {
            if ($null -ne $item) { $results.Add($item) }
        }
        $Uri = $page.'@odata.nextLink'
    }

    return $results.ToArray()
}

# Cache successful and failed lookups to avoid repeated calls for shared assignees.
$nameCache = @{}
function Resolve-RelationshipNames {
    param([object[]]$Items)

    foreach ($item in $Items) {
        $name = $item.displayName
        $id = [string]$item.id
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            $nameCache[$id] = $name
        }
        elseif ($nameCache.ContainsKey($id)) {
            $name = $nameCache[$id]
        }
        else {
            $type = $item.'@odata.type' -replace '^#microsoft\.graph\.', ''
            $collection = switch ($type) {
                'user'                   { 'users' }
                'agentUser'              { 'users' }
                'group'                  { 'groups' }
                'servicePrincipal'       { 'servicePrincipals' }
                'agentIdentity'          { 'servicePrincipals' }
                'agentIdentityBlueprint' { 'servicePrincipals' }
                default                  { 'directoryObjects' }
            }
            $permission = switch ($collection) {
                'users'             { 'User.Read.All' }
                'groups'            { 'GroupMember.Read.All' }
                'servicePrincipals' { 'Application.Read.All' }
                default             { 'Directory.Read.All' }
            }
            $uri = "https://graph.microsoft.com/v1.0/$collection/$id"
            if ($collection -ne 'directoryObjects') { $uri += '?$select=id,displayName' }
            try {
                $details = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject -ErrorAction Stop
                $name = $details.displayName
                if ([string]::IsNullOrWhiteSpace($name)) {
                    Write-Warning "No display name returned for $id. Check $permission application permission and admin consent."
                }
            }
            catch {
                Write-Warning "Display-name lookup failed for $id ($collection). Check $permission application permission and admin consent. Graph error: $($_.Exception.Message)"
            }
            $nameCache[$id] = $name
        }
        # Preserve the relationship even if name resolution fails.
        [pscustomobject]@{
            id = $id
            displayName = $name
        }
    }
}

$endpoint = 'https://graph.microsoft.com/v1.0/servicePrincipals/microsoft.graph.agentIdentity?$select=id,displayName,accountEnabled,createdDateTime,agentIdentityBlueprintId&$top=100'
$agents = @(Get-GraphCollection -Uri $endpoint)
$assessmentTimeUtc = (Get-Date).ToUniversalTime().ToString('o')
$report = [System.Collections.Generic.List[object]]::new()

foreach ($agent in $agents) {
    $id = $agent.id

    $ownersUri = 'https://graph.microsoft.com/v1.0/servicePrincipals/{0}/microsoft.graph.agentIdentity/owners?$select=id,displayName' -f $id
    $sponsorsUri = 'https://graph.microsoft.com/v1.0/servicePrincipals/{0}/microsoft.graph.agentIdentity/sponsors?$select=id,displayName' -f $id

    # A failed permission or API request must fail the assessment, not mark an
    # identity compliant or incorrectly classify its relationships as missing.
    $owners = @(Get-GraphCollection -Uri $ownersUri)
    $sponsors = @(Get-GraphCollection -Uri $sponsorsUri)

    $owners = @(Resolve-RelationshipNames -Items $owners)
    $sponsors = @(Resolve-RelationshipNames -Items $sponsors)

    $missingOwner = ($owners.Count -eq 0)
    $missingSponsor = ($sponsors.Count -eq 0)

    $finding = if ($missingOwner -and $missingSponsor) {
        'Missing owner and sponsor'
    }
    elseif ($missingOwner) {
        'Missing owner'
    }
    elseif ($missingSponsor) {
        'Missing sponsor'
    }
    else {
        'None'
    }

    $complianceStatus = if ($missingOwner -or $missingSponsor) { 'Noncompliant' } else { 'Compliant' }

    $riskLevel = if ($missingOwner -and $missingSponsor) { 'Risky' }
        elseif ($missingSponsor) { 'Partially risky' }
        elseif ($missingOwner) { 'Minor Risky' }
        else { 'Complete' }

    # Retain object IDs when Graph does not return readable names.
    $ownerNames = @($owners | ForEach-Object {
        if ([string]::IsNullOrWhiteSpace($_.displayName)) { '[Name unavailable]' }
        else { $_.displayName }
    })
    $sponsorNames = @($sponsors | ForEach-Object {
        if ([string]::IsNullOrWhiteSpace($_.displayName)) { '[Name unavailable]' }
        else { $_.displayName }
    })

    $color = switch ($riskLevel) {
        'Risky' { 'Red' }
        'Partially risky' { 'Yellow' }
        'Minor Risky' { 'Gray' }
        default { 'Green' }
    }
    Write-Host "`n[●] $complianceStatus | $riskLevel — $($agent.displayName) ($id)" -ForegroundColor $color
    Write-Host '  OWNERS:'
    if ($owners.Count -eq 0) { Write-Host '    None assigned' }
    foreach ($owner in $owners) {
        $name = if ([string]::IsNullOrWhiteSpace($owner.displayName)) { '[Name unavailable]' } else { $owner.displayName }
        Write-Host "    $name ($($owner.id))"
    }
    Write-Host '  SPONSORS:'
    if ($sponsors.Count -eq 0) { Write-Host '    None assigned' }
    foreach ($sponsor in $sponsors) {
        $name = if ([string]::IsNullOrWhiteSpace($sponsor.displayName)) { '[Name unavailable]' } else { $sponsor.displayName }
        Write-Host "    $name ($($sponsor.id))"
    }

    $report.Add([pscustomobject]@{
        AssessmentTimeUtc = $assessmentTimeUtc
        DisplayName       = $agent.displayName
        AgentObjectId     = $id
        BlueprintAppId    = $agent.agentIdentityBlueprintId
        AccountEnabled    = $agent.accountEnabled
        CreatedDateTime   = $agent.createdDateTime
        OwnerCount        = $owners.Count
        SponsorCount      = $sponsors.Count
        RiskLevel         = $riskLevel
        OwnerNames        = ($ownerNames -join ';')
        SponsorNames      = ($sponsorNames -join ';')
        OwnerIds          = ($owners.id -join ';')
        SponsorIds        = ($sponsors.id -join ';')
        MissingOwner      = $missingOwner
        MissingSponsor    = $missingSponsor
        ComplianceStatus  = $complianceStatus
        Finding           = $finding
    })
}

$all = @($report.ToArray())
$findings = @($all | Where-Object { $_.ComplianceStatus -eq 'Noncompliant' })

if (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) {
    $null = New-Item -ItemType Directory -Path $OutputDirectory -Force
}

$inventoryPath = Join-Path $OutputDirectory 'AgentIdentity-Inventory.csv'
$findingsPath = Join-Path $OutputDirectory 'AgentIdentity-Noncompliant.csv'

# Create both files even when the assessment finds no identities/findings.
# Using explicit CSV headers avoids misleading missing output files.
$columns = 'AssessmentTimeUtc','DisplayName','AgentObjectId','BlueprintAppId',
           'AccountEnabled','CreatedDateTime','OwnerCount','SponsorCount',
           'RiskLevel','OwnerNames','SponsorNames','OwnerIds','SponsorIds','MissingOwner','MissingSponsor',
           'ComplianceStatus','Finding'

foreach ($export in @(
    @{ Items = $all; Path = $inventoryPath },
    @{ Items = $findings; Path = $findingsPath }
)) {
    if ($export.Items.Count -gt 0) {
        $export.Items | Select-Object -Property $columns |
            Export-Csv -LiteralPath $export.Path -NoTypeInformation -Encoding utf8
    }
    else {
        # An empty CSV with only headers is valid evidence of no rows.
        '"' + ($columns -join '","') + '"' |
            Set-Content -LiteralPath $export.Path -Encoding utf8
    }
}

$missingBoth = @($all | Where-Object { $_.MissingOwner -and $_.MissingSponsor }).Count
$missingOwnerOnly = @($all | Where-Object { $_.MissingOwner -and -not $_.MissingSponsor }).Count
$missingSponsorOnly = @($all | Where-Object { -not $_.MissingOwner -and $_.MissingSponsor }).Count

Write-Host "`nMicrosoft Entra Agent Identity Governance Assessment"
Write-Host "Total assessed: $($all.Count)"
Write-Host "Compliant: $($all.Count - $findings.Count)"
Write-Host "Noncompliant: $($findings.Count)"
Write-Host "Missing owner only: $missingOwnerOnly"
Write-Host "Missing sponsor only: $missingSponsorOnly"
Write-Host "Missing both: $missingBoth"

Write-Host "[●] Risky (both missing): $missingBoth" -ForegroundColor Red
Write-Host "[●] Partially risky (sponsor missing): $missingSponsorOnly" -ForegroundColor Yellow
Write-Host "[●] Minor Risky (owner missing): $missingOwnerOnly" -ForegroundColor Gray
Write-Host "[●] Complete (both present): $($all.Count - $findings.Count)" -ForegroundColor Green
if ($all.Count -eq 0) { Write-Host 'No agent identities returned; no identities assessed.' }


# A self-contained, offline dashboard. Escape HTML characters in embedded data.
$dashboardData = [pscustomobject]@{
    assessedAt = $assessmentTimeUtc
    demo = $false
    items = @($all)
} | ConvertTo-Json -Depth 8 -EscapeHandling EscapeHtml -Compress
$dashboardTemplate = @'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Agent identity governance</title>
<style>
:root{color-scheme:light;--ink:#182737;--muted:#687888;--line:#e3e9ee;--green:#18836a;--yellow:#b7790c;--red:#ce454c}*{box-sizing:border-box}body{margin:0;background:#f3f6f8;color:var(--ink);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}header{background:#132b3b;color:white;padding:22px 32px;display:flex;align-items:center;gap:14px}header .logo{display:grid;place-items:center;width:36px;height:36px;background:#274758;border-radius:10px;font-size:22px;color:#83d8c4}header strong{font-size:16px;font-weight:600}header small{display:block;color:#a8becb;font-size:12px}header .tag{margin-left:auto;border:1px solid #506575;border-radius:6px;padding:4px 9px;font-size:11px;letter-spacing:.07em}main{max-width:1370px;margin:auto;padding:26px 32px}h1{font-size:26px;letter-spacing:-.7px;margin:0 0 4px;font-weight:650}.heading{display:flex;justify-content:space-between;align-items:center;margin-bottom:22px}.sub,.timestamp{color:var(--muted);font-size:12px}.timestamp{text-align:right}.overview{display:grid;grid-template-columns:1.3fr repeat(4,1fr);gap:14px;margin-bottom:22px}.card{background:white;border:1px solid var(--line);border-radius:12px;padding:20px;min-height:152px}.score{display:flex;gap:20px;align-items:center}.ring{width:104px;height:104px;flex-shrink:0;border-radius:50%;background:conic-gradient(var(--green) 0deg,#e8edf1 0deg);display:grid;place-items:center}.ring>div{width:84px;height:84px;border-radius:50%;background:white;display:flex;align-items:center;justify-content:center;font-size:25px;font-weight:700}.eyebrow{font-size:11px;font-weight:650;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}.big{font-size:36px;line-height:1.2;font-weight:650;letter-spacing:-1px;margin:12px 0 5px}.dot{width:8px;height:8px;background:currentColor;display:inline-block;border-radius:50%;margin-right:7px}.green{color:var(--green)}.yellow{color:var(--yellow)}.red{color:var(--red)}.card p{margin:0;color:var(--muted);font-size:12px}.card .eyebrow{display:flex;align-items:center}.bar{height:4px;display:flex;margin-top:12px;border-radius:4px;overflow:hidden;background:#edf1f4}.bar span{height:100%}.panel{background:white;border:1px solid var(--line);border-radius:12px;overflow:hidden}.panel-head{padding:20px 20px 14px;display:flex;align-items:center;gap:10px}.panel-head h2{font-size:16px;margin:0}.count{font-size:12px;color:var(--muted);background:#f0f4f6;border-radius:5px;padding:1px 7px}.tools{display:flex;gap:12px;justify-content:space-between;padding:0 20px 18px;flex-wrap:wrap}.filters{display:flex;gap:5px;flex-wrap:wrap}button,input{font:inherit}button{border:1px solid var(--line);background:white;border-radius:6px;padding:7px 12px;cursor:pointer;color:#536373;font-size:12px}button:hover{background:#f2f6f8}button[aria-pressed=true]{background:#193a4c;border-color:#193a4c;color:white}button:focus-visible,input:focus-visible{outline:3px solid #56afc3;outline-offset:2px}input{width:260px;border:1px solid var(--line);border-radius:6px;padding:8px 11px;font-size:12px}.scroll{overflow:auto}table{width:100%;border-collapse:collapse;text-align:left;white-space:normal}th{font-size:10px;letter-spacing:.08em;text-transform:uppercase;background:#f7f9fa;color:var(--muted);font-weight:650;padding:12px 20px;border-top:1px solid var(--line);border-bottom:1px solid var(--line)}td{padding:16px 20px;border-bottom:1px solid #edf1f4;vertical-align:top;font-size:12px}tbody tr:last-child td{border-bottom:0}tbody tr:hover{background:#fafcfd}.agent{font-weight:600;font-size:13px}.id{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;color:#84919d;font-size:10px;display:block;margin-top:4px;overflow-wrap:anywhere}.pill{display:inline-flex;align-items:center;border-radius:5px;font-size:11px;font-weight:600;padding:4px 8px;white-space:nowrap}.pill.green{background:#eaf5f0}.pill.red{background:#fceff0}.pill.yellow{background:#fff6e5}.pill.neutral{background:#edf1f4;color:#687888}.assignment{margin-bottom:5px}.missing{color:var(--muted);font-style:italic}.finding{color:var(--muted);font-size:11px;margin-top:5px}.foot{padding:13px 20px;border-top:1px solid var(--line);font-size:11px;color:var(--muted);display:flex;justify-content:space-between;gap:12px}.empty{text-align:center;padding:40px;color:var(--muted)}footer{font-size:11px;color:var(--muted);margin-top:14px;display:flex;justify-content:space-between;gap:16px}.demo{background:#fff5d9;padding:9px 32px;font-size:12px;color:#795b13;display:none}@media(max-width:1100px){.overview{grid-template-columns:repeat(2,1fr)}.score{grid-column:1/-1}}@media(max-width:600px){header{padding:16px}.tag{display:none}main{padding:20px 12px}.heading{display:block}.timestamp{text-align:left;margin-top:10px}.overview{gap:8px}.card{padding:14px;min-height:130px}.score{grid-column:1/-1}.ring{width:90px;height:90px}.ring>div{width:72px;height:72px}input{width:100%}th,td{padding:12px}table{min-width:760px}footer{display:block}.foot{flex-wrap:wrap}}@media print{header{background:white;color:black}.tools{display:none}main{padding:0}.overview{grid-template-columns:repeat(4,1fr)}.score{grid-column:1/-1}.scroll{overflow:visible}table{min-width:0}body{background:white}}
</style>
</head>
<body>
<div class="demo" id="demo">Preview · Sample identities — not tenant data</div>
<header><div class="logo" aria-hidden="true">◇</div><div><strong>Agent governance</strong></div></header>
<main>
<div class="heading"><div><h1>Owner &amp; sponsor coverage</h1></div></div>
<section class="overview" aria-label="Assessment summary">
<div class="card score"><div class="ring" id="ring"><div id="percent">—</div></div><div><div class="eyebrow">Compliance</div><strong id="ratio"></strong><div class="bar" id="bar" aria-hidden="true"></div></div></div>
<div class="card"><div class="eyebrow green"><span class="dot"></span>Compliant</div><div class="big" id="complete">0</div><p>Owner and sponsor present</p></div>
<div class="card"><div class="eyebrow"><span class="dot"></span>Minor Risky</div><div class="big" id="ownerOnly">0</div><p>Owner missing · Sponsor present</p></div>
<div class="card"><div class="eyebrow yellow"><span class="dot"></span>Partially risky</div><div class="big" id="partial">0</div><p>Sponsor missing · Owner present</p></div>
<div class="card"><div class="eyebrow red"><span class="dot"></span>Risky</div><div class="big" id="risky">0</div><p>Both missing · Noncompliant</p></div>
</section>
<section class="panel" aria-label="Agent identity inventory">
<div class="panel-head"><h2>Agent identities</h2><span class="count" id="rowcount"></span></div>
<div class="tools"><div class="filters" role="group" aria-label="Filter identities"><button data-filter="all" aria-pressed="true">All</button><button data-filter="noncompliant" aria-pressed="false">Noncompliant</button><button data-filter="risky" aria-pressed="false">Both missing</button><button data-filter="owner-missing" aria-pressed="false">Owner missing</button><button data-filter="sponsor-missing" aria-pressed="false">Sponsor missing</button><button data-filter="complete" aria-pressed="false">Compliant</button></div><input id="search" type="search" placeholder="Search agent, assignee or ID" aria-label="Search agent, assignee or object ID"></div>
<div class="scroll"><table><thead><tr><th scope="col" style="width:28%">Agent identity</th><th scope="col" style="width:24%">Owners</th><th scope="col" style="width:24%">Sponsors</th><th scope="col">Compliance</th></tr></thead><tbody id="rows"></tbody></table></div>
<div id="empty" class="empty" hidden>No matching identities.</div>
<div class="foot"><span id="showing" role="status" aria-live="polite"></span></div>
</section>
<footer><span></span><span></span></footer>
</main>
<script id="report-data" type="application/json">__REPORT_DATA__</script>
<script>
'use strict';
const report=JSON.parse(document.getElementById('report-data').textContent);
const items=report.items||[];
const $=id=>document.getElementById(id);
const status=r=>Number(r.OwnerCount)>0&&Number(r.SponsorCount)>0?'complete':Number(r.OwnerCount)===0&&Number(r.SponsorCount)===0?'risky':Number(r.SponsorCount)===0?'partial':'ownerOnly';
const counts={complete:0,partial:0,risky:0,ownerOnly:0};items.forEach(r=>counts[status(r)]++);
for(const k of Object.keys(counts))$(k).textContent=counts[k];


$('percent').textContent=items.length?Math.round(counts.complete/items.length*100)+'%':'—';
$('ratio').textContent=`${counts.complete} of ${items.length} identities`;
$('ring').style.background=`conic-gradient(var(--green) ${items.length?counts.complete/items.length*360:0}deg,#e8edf1 0deg)`;
for(const [k,c] of [['complete','var(--green)'],['partial','var(--yellow)'],['risky','var(--red)'],['ownerOnly','var(--muted)']]){const el=document.createElement('span');el.style.width=(items.length?counts[k]/items.length*100:0)+'%';el.style.background=c;$('bar').append(el)}
if(report.demo)$('demo').style.display='block';
let filter='all';
const priority={risky:0,partial:1,ownerOnly:2,complete:3};
const sorted=[...items].sort((a,b)=>priority[status(a)]-priority[status(b)]||String(a.DisplayName||'').localeCompare(String(b.DisplayName||'')));
function el(tag,text,cls){const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n}
function assignmentCell(r,role){const td=el('td');const ids=String(r[role+'Ids']||'').split(';').filter(Boolean);const names=String(r[role+'Names']||'').split(';');if(!Number(r[role+'Count'])){td.append(el('span','Not assigned','missing'));return td}ids.forEach((id,i)=>{const wrap=el('div',undefined,'assignment');wrap.append(el('div',names[i]||'[Name unavailable]'),el('span',id,'id'));td.append(wrap)});return td}
function render(){const query=$('search').value.trim().toLowerCase();const visible=sorted.filter(r=>{const s=status(r);return(filter==='all'||filter===s||filter==='noncompliant'&&s!=='complete'||filter==='owner-missing'&&Number(r.OwnerCount)===0||filter==='sponsor-missing'&&Number(r.SponsorCount)===0)&&[r.DisplayName,r.AgentObjectId,r.OwnerNames,r.OwnerIds,r.SponsorNames,r.SponsorIds].join(' ').toLowerCase().includes(query)});$('rows').replaceChildren();for(const r of visible){const s=status(r);const tr=el('tr');const agent=el('td');agent.append(el('div',r.DisplayName||'[Unnamed identity]','agent'),el('span',r.AgentObjectId,'id'));const result=el('td');const badge=el('span',undefined,'pill '+(s==='complete'?'green':s==='partial'?'yellow':s==='risky'?'red':'neutral'));badge.append(el('span','','dot'),el('span',s==='complete'?'Compliant':'Noncompliant'));result.append(badge,el('div',s==='complete'?'Both assigned':s==='risky'?'Owner & sponsor missing':Number(r.OwnerCount)?'Sponsor missing':'Minor Risky · Owner missing','finding'));tr.append(agent,assignmentCell(r,'Owner'),assignmentCell(r,'Sponsor'),result);$('rows').append(tr)}$('rowcount').textContent=items.length;$('showing').textContent=`Showing ${visible.length} of ${items.length}`;$('empty').hidden=visible.length!==0;$('empty').textContent=items.length?'No matching identities.':'No agent identities returned.'}
document.querySelectorAll('[data-filter]').forEach(b=>b.addEventListener('click',()=>{filter=b.dataset.filter;document.querySelectorAll('[data-filter]').forEach(x=>x.setAttribute('aria-pressed',String(x===b)));render()}));$('search').addEventListener('input',render);render();
</script>
</body></html>

'@
$dashboardPath = Join-Path $OutputDirectory 'AgentIdentity-Dashboard.html'
$dashboardTemplate.Replace('__REPORT_DATA__', $dashboardData) |
    Set-Content -LiteralPath $dashboardPath -Encoding utf8
Write-Host "Dashboard: $dashboardPath"

Write-Host "Full inventory: $inventoryPath"
Write-Host "Findings report: $findingsPath"

}
finally {
    if ($connected) { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null }
}
