Param (
  [Parameter(Mandatory = $true)]
  [string] $SubscriptionId,

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
  try {
    $azureRunAsConnection = Get-AutomationConnection -Name "AzureRunAsConnection"
    Connect-AzAccount -Tenant $azureRunAsConnection.TenantID `
      -Subscription $SubscriptionId `
      -ApplicationId $azureRunAsConnection.ApplicationID `
      -CertificateThumbprint $azureRunAsConnection.CertificateThumbprint `
      -ServicePrincipal | Out-Null

    Write-Output "Connected to Azure as AzureRunAsConnection $($azureRunAsConnection.ApplicationID))"
  }
  catch {
    if (!$azureRunAsConnection) {
      $ErrorMessage = "AzureRunAsConnection not found."
      throw $ErrorMessage
    }
    else {
      Write-Error -Message $_.Exception
      throw $_.Exception
    }
  }
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

  # Resolve the details of the certificate
  $currentServerName = ((Get-PAServer).location) -split "/" | Where-Object -FilterScript { $_ } | Select-Object -Skip 1 -First 1
  $currentAccountName = (Get-PAAccount).id

  # Determine paths to resources
  $orderDirectoryPath = Join-Path -Path $WorkingDirectory -ChildPath $currentServerName | Join-Path -ChildPath $currentAccountName | Join-Path -ChildPath $CertificateName
  $orderDataPath = Join-Path -Path $orderDirectoryPath -ChildPath "order.json"
  $pfxFilePath = Join-Path -Path $orderDirectoryPath -ChildPath "fullchain.pfx"

  # If we have a order and certificate available
  if ((Test-Path -Path $orderDirectoryPath) -and (Test-Path -Path $orderDataPath) -and (Test-Path -Path $pfxFilePath)) {

    # Load order data
    $orderData = Get-Content -Path $orderDataPath -Raw | ConvertFrom-Json

    # Load PFX
    $certificate = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $pfxFilePath, $orderData.PfxPass, "EphemeralKeySet"

    $azureKeyVaultCertificate = Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $KeyVaultCertificateName -ErrorAction SilentlyContinue

    # If we have a different certificate, import it
    If (-not $azureKeyVaultCertificate -or $azureKeyVaultCertificate.Thumbprint -ne $certificate.Thumbprint) {
      Import-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $KeyVaultCertificateName -FilePath $pfxFilePath -Password (ConvertTo-SecureString -String $orderData.PfxPass -AsPlainText -Force) | Out-Null
    }
  }
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
    Write-Output "Sending EnableCustomHttps Request for Domain $domain"
    $url = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Cdn/profiles/$CdnProfileName/endpoints/$CdnEndpointName/customDomains/$($domain.Replace(".", "-"))/enableCustomHttps?api-version=2019-04-15"
    $resp = Invoke-RestMethod -Uri $url -Method "Post" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
    Write-Output $resp | ConvertTo-Json -Depth 10
  }
}

try {
  Connect-AzureRunAsAccount

  $servicePrincipal = Get-AzADServicePrincipal -ApplicationId (Get-AzContext).Account.Id
  Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -ObjectId $servicePrincipal.Id -PermissionsToSecrets @("get") -PermissionsToCertificates @("get", "import")

  $workingDirectory = Join-Path -Path (Convert-Path .) -ChildPath "posh-acme"

  $storageContext = New-AzStorageContext -StorageAccountName $StorageAccountName -UseConnectedAccount -Protocol "https"
  New-AzStorageContainer -Name $PoshAcmeBlobContainer -Permission Off -Context $storageContext -ErrorAction SilentlyContinue | Out-Null

  New-Item $workingDirectory -ItemType "directory" -Force

  $storageBlobs = Get-AzStorageBlob -Container $PoshAcmeBlobContainer -Context $storageContext -ErrorAction Stop

  Write-Output "Downloading files..."

  foreach ($blob in $storageBlobs) {
    Write-Output "Downloading $($blob.Name)"
    Get-AzStorageBlobContent -Container $PoshAcmeBlobContainer -Blob $blob.Name -Destination $workingDirectory -Context $storageContext | Out-Null
  }

  Write-Output "Finished downloading Posh-ACME working directory"

  try {
    Write-Output "Creating new Certificate"
    New-AcmeCertificate -WorkingDirectory $workingDirectory -DomainNames $DomainNames -AcmeContact $AcmeContact -AcmeDirectory $AcmeDirectory | Out-Null

    # For wildcard certificates, Posh-ACME replaces * with ! in the directory name
    $certificateName = ($DomainNames | Select-Object -First 1).Replace("*", "!")
    $azureKeyVaultCertificateName = $certificateName.Replace(".", "-").Replace("!", "wildcard")

    Write-Output "Importing Certificate to KeyVault"
    Import-AcmeCertificateToKeyVault -WorkingDirectory $workingDirectory -CertificateName $certificateName -KeyVaultName $KeyVaultName -KeyVaultCertificateName $azureKeyVaultCertificateName | Out-Null

    Write-Output "Enable CDN Endpoint Custom HTTPS"
    Set-CdnCustomHttps -DomainNames $DomainNames -KeyVaultName $KeyVaultName -KeyVaultSecretName $azureKeyVaultCertificateName -CdnProfileName $CdnProfileName -CdnEndpointName $CdnEndpointName
  }
  finally {
    Write-Output "Uploading files..."
    Get-ChildItem -File -Recurse $workingDirectory | Set-AzStorageBlobContent -Container $PoshAcmeBlobContainer -Context $storageContext -Force | Out-Null
    Write-Output "Finished uploading Posh-ACME working directory"
  }
}
catch {
  Write-Output $_
  throw $_
}
