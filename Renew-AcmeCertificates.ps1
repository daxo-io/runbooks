[CmdletBinding()]
Param (
  [Parameter(Mandatory = $true)]
  [string] $StorageAccountName,

  [Parameter(Mandatory = $true)]
  [string] $PoshAcmeBlobContainer,

  [Parameter(Mandatory = $true)]
  [string] $KeyVaultName,

  [Parameter(Mandatory = $true)]
  [string[]] $DomainNames,

  [Parameter(Mandatory = $true)]
  [string] $CdnProfileName,

  [Parameter(Mandatory = $true)]
  [string] $CdnEndpointName,

  [Parameter(Mandatory = $true)]
  [string] $AcmeContact,

  [Parameter(Mandatory = $false)]
  [string] $AcmeDirectory = "https://acme-v02.api.letsencrypt.org/directory"
)

function Connect-AzureRunAsAccount {
  $azureRunAsConnection = Get-AutomationConnection -Name "AzureRunAsConnection" -ErrorAction Stop
  Connect-AzAccount -Tenant $azureRunAsConnection.TenantId `
    -Subscription $azureRunAsConnection.SubscriptionId `
    -ApplicationId $azureRunAsConnection.ApplicationId `
    -CertificateThumbprint $azureRunAsConnection.CertificateThumbprint `
    -ServicePrincipal | Out-Null

  Write-Verbose "Connected to Azure as AzureRunAsConnection (Application ID: $($azureRunAsConnection.ApplicationId))" -Verbose
}

function Get-AzureResourceManagerAccessToken {
  $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
  if (-not $azProfile.Accounts.Count) {
    Write-Error "Could not find a valid AzProfile, please run Connect-AzAccount"
    return
  }

  $currentAzureContext = Get-AzContext
  $profileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($azProfile)
  $token = $profileClient.AcquireAccessToken($currentAzureContext.Tenant.TenantId)
  return $token.AccessToken
}

function New-AcmeCertificate {
  [CmdletBinding()]
  Param (
    [Parameter(Mandatory = $true)]
    [string] $AcmeDirectory,

    [Parameter(Mandatory = $true)]
    [string] $AcmeContact,

    [Parameter(Mandatory = $true)]
    [string[]] $DomainNames,

    [Parameter(Mandatory = $true)]
    [string] $WorkingDirectory
  )
  # Set Posh-ACME working directory
  $env:POSHACME_HOME = $WorkingDirectory
  Import-Module Posh-ACME -Force

  # Configure Posh-ACME server
  Set-PAServer -DirectoryUrl $AcmeDirectory

  # Configure Posh-ACME account
  $account = Get-PAAccount
  if (-not $account) {
    # New account
    $account = New-PAAccount -Contact $AcmeContact -AcceptTOS
  }
  elseif ($account.contact -ne "mailto:$AcmeContact") {
    # Update account contact
    Set-PAAccount -ID $account.id -Contact $AcmeContact
  }

  # Acquire access token for Azure (as we want to leverage the existing connection)
  $azureAccessToken = Get-AzureResourceManagerAccessToken

  $azureContext = Get-AzContext

  # Request certificate
  $paPluginArgs = @{
    AZSubscriptionId = $azureContext.Subscription.Id
    AZAccessToken    = $azureAccessToken;
  }

  return New-PACertificate -Domain $DomainNames -DnsPlugin Azure -PluginArgs $paPluginArgs
}

function Import-AcmeCertificateToKeyVault {
  [CmdletBinding()]
  Param (
    [Parameter(Mandatory = $true)]
    [string] $WorkingDirectory,

    [Parameter(Mandatory = $true)]
    [string] $CertificateName,

    [Parameter(Mandatory = $true)]
    [string] $KeyVaultName,

    [Parameter(Mandatory = $true)]
    [string] $KeyVaultCertificateName
  )

  # Set Posh-ACME working directory
  $env:POSHACME_HOME = $WorkingDirectory
  Import-Module -Name Posh-ACME -Force

  # Load Certificate Data
  $certData = Get-PACertificate

  # Load PFX
  $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
  $certificate = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $certData.PfxFullChain, $certData.PfxPass, $flags

  $azureKeyVaultCertificate = Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $KeyVaultCertificateName -ErrorAction SilentlyContinue

  # If we have a new certificate, import it
  if (-not $azureKeyVaultCertificate -or $azureKeyVaultCertificate.Thumbprint -ne $certificate.Thumbprint) {
    Import-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $KeyVaultCertificateName -FilePath $certData.PfxFullChain -Password $certData.PfxPass | Out-Null
    Write-Verbose "Imported new Certificate with Thumbprint $($certificate.Thumbprint) into KeyVault" -Verbose
    return $True
  }

  Write-Verbose "Certificate with Thumbprint $($certificate.Thumbprint) is already present in KeyVault" -Verbose
  return $False
}

function Set-CdnCustomHttps {
  [CmdletBinding()]
  Param (
    [Parameter(Mandatory = $true)]
    [string[]] $DomainNames,

    [Parameter(Mandatory = $true)]
    [string] $KeyVaultName,

    [Parameter(Mandatory = $true)]
    [string] $KeyVaultSecretName,

    [Parameter(Mandatory = $true)]
    [string] $CdnProfileName,

    [Parameter(Mandatory = $true)]
    [string] $CdnEndpointName
  )

  $cdnProfile = Get-AzCdnProfile -ProfileName $CdnProfileName
  $cdnEndpoint = Get-AzCdnEndpoint -CdnProfile $cdnProfile -EndpointName $CdnEndpointName

  $certSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $KeyVaultSecretName

  $subscriptionId = (Get-AzContext).Subscription.Id
  $resourceGroupName = $cdnEndpoint.ResourceGroupName

  $requestBody = @{
    certificateSource           = "AzureKeyVault"
    protocolType                = "ServerNameIndication"
    certificateSourceParameters = @{
      "@odata.type"     = "#Microsoft.Azure.Cdn.Models.KeyVaultCertificateSourceParameters"
      resourceGroupName = $resourceGroupName
      secretName        = $certSecret.Name
      secretVersion     = $certSecret.Version
      subscriptionId    = $subscriptionId
      vaultName         = $KeyVaultName
      updateRule        = "NoAction"
      deleteRule        = "NoAction"
    }
  } | ConvertTo-Json -Compress

  $requestHeaders = @{
    "Authorization" = "Bearer $(Get-AzureResourceManagerAccessToken)"
  }

  foreach ($domain in $DomainNames) {
    Write-Verbose "Sending EnableCustomHttps Request for Domain $domain" -Verbose
    $url = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Cdn/profiles/$CdnProfileName/endpoints/$CdnEndpointName/customDomains/$($domain.Replace(".", "-"))/enableCustomHttps?api-version=2019-04-15"
    $resp = Invoke-RestMethod -Uri $url -Method "Post" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
    Write-Verbose ($resp | ConvertTo-Json -Depth 10) -Verbose
  }
}

# Main entry
$VerbosePreference = "SilentlyContinue"

Connect-AzureRunAsAccount

# Set RunAsAccount AccessPolicy to KeyVault
$runAsServicePrincipal = Get-AzADServicePrincipal -ApplicationId (Get-AzContext).Account.Id
Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -ObjectId $runAsServicePrincipal.Id -PermissionsToSecrets @("get") -PermissionsToCertificates @("get", "import")

$workingDirectory = Join-Path -Path (Convert-Path .) -ChildPath "posh-acme"

$storageContext = New-AzStorageContext -StorageAccountName $StorageAccountName -UseConnectedAccount -Protocol "https"
New-AzStorageContainer -Name $PoshAcmeBlobContainer -Permission Off -Context $storageContext -ErrorAction SilentlyContinue | Out-Null

New-Item $workingDirectory -ItemType "directory" -Force

$storageBlobs = Get-AzStorageBlob -Container $PoshAcmeBlobContainer -Context $storageContext -ErrorAction Stop

Write-Verbose "Downloading files..." -Verbose

foreach ($blob in $storageBlobs) {
  Write-Verbose "Downloading $($blob.Name)" -Verbose
  Get-AzStorageBlobContent -Container $PoshAcmeBlobContainer -Blob $blob.Name -Destination $workingDirectory -Context $storageContext | Out-Null
}

Write-Verbose "Finished downloading Posh-ACME working directory" -Verbose

try {
  Write-Verbose "Renewing Certificate with Posh-ACME" -Verbose

  New-AcmeCertificate -WorkingDirectory $workingDirectory -DomainNames $DomainNames -AcmeContact $AcmeContact -AcmeDirectory $AcmeDirectory

  # For wildcard certificates, Posh-ACME replaces * with ! in the directory name
  $certificateName = ($DomainNames | Select-Object -First 1).Replace("*", "!")
  $azureKeyVaultCertificateName = $certificateName.Replace(".", "-").Replace("!", "wildcard")

  Write-Verbose "Importing Certificate to KeyVault" -Verbose
  $newCertificateImported = Import-AcmeCertificateToKeyVault -WorkingDirectory $workingDirectory -CertificateName $certificateName -KeyVaultName $KeyVaultName -KeyVaultCertificateName $azureKeyVaultCertificateName

  if ($newCertificateImported) {
    Write-Verbose "Enabling CDN Endpoint Custom HTTPS" -Verbose
    Set-CdnCustomHttps -DomainNames $DomainNames -KeyVaultName $KeyVaultName -KeyVaultSecretName $azureKeyVaultCertificateName -CdnProfileName $CdnProfileName -CdnEndpointName $CdnEndpointName | Out-Null
  }
}
finally {
  Write-Verbose "Uploading files..." -Verbose
  Get-ChildItem -File -Recurse $workingDirectory | Set-AzStorageBlobContent -Container $PoshAcmeBlobContainer -Context $storageContext -Force | Out-Null
  Write-Verbose "Finished uploading Posh-ACME working directory" -Verbose
}

