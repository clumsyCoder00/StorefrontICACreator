<#PSScriptInfo

.VERSION

.GUID

.AUTHOR @

.COMPANYNAME 

.COPYRIGHT 

.TAGS Storefront ICA PublishedApps Citrix

.LICENSEURI

.PROJECTURI

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES
05-20-16: Initial Release
08-27-17: Formatting for PS Gallery

#> 

<#
.SYNOPSIS
   A PowerShell script that creates, downloads and runs Citrix ICA file from authenticated store
.DESCRIPTION
   A Powershell v3 Script that utilizes invoke-webrequest to create, download and launch an application via Citrix ICA file from Storefront.  Script uses explict authentication.
.PARAMETER sfurl 
   Storefront WEB URL (MANDATORY)
.PARAMETER appname
   Published application name (MANDATORY)
.PARAMETER icapath
   Location to save and run ICA from (MANDATORY)
.PARAMETER username
   username to login with (MANDATORY)
.PARAMETER password
   password to login with (MANDATORY)
.PARAMETER domain
   domain to use (MANDATORY)
.EXAMPLE
  .\get-ICAfile_v3_auth.ps1 -sfurl "https://storefront.mydomain.local/Citrix/StoreWeb/" -icapath 'C:\temp\myica.ica' -username 'jsmith' -password 'mypassword' -domain 'mydomain.local' -appname 'Notepad++'
#>
Param
(
    [Parameter(Mandatory=$true)]$sfurl,
    [Parameter(Mandatory=$true)]$appname,
    [Parameter(Mandatory=$true)]$icapath,
    [Parameter(Mandatory=$true)]$username,
    [Parameter(Mandatory=$true)]$password,
    [Parameter(Mandatory=$true)]$domain

)
CLS
write-host "Requesting ICA file. Please Wait..." -ForegroundColor Yellow

#Remove old ica file if found
if (test-path $icapath)
{
    write-host "Removing OLD ICA file..." -ForegroundColor Yellow
    Remove-Item $icapath -Force
}

#start by loading main SF page
$headers = @{
"Accept"='text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8';
"Upgrade-Insecure-Requests"="1";
}

$login = Invoke-WebRequest -Uri ($sfurl) -Method GET -Headers $headers -SessionVariable SFSession

#Gets required tokens
$headers = @{
"Accept"='application/xml, text/xml, */*; q=0.01';
"Content-Length"="0";
"X-Requested-With"="XMLHttpRequest";
"X-Citrix-IsUsingHTTPS"="No";
"Referer"=$sfurl;
}

Invoke-WebRequest -Uri ($sfurl + "Home/Configuration") -Method POST -Headers $headers -WebSession $SFSession|Out-Null

$csrf = $sfsession.cookies.GetCookies($sfurl)|where{$_.name -like "CsrfToken"}
$asp_net_sessionid = $sfsession.cookies.GetCookies($sfurl)|where{$_.name -like "ASP.NET_SessionId"}

$cookiedomain = $csrf.Domain

#Gets needed cookie values
$headers = @{
"Content-Type"='application/x-www-form-urlencoded; charset=UTF-8';
"Accept"='application/json, text/javascript, */*; q=0.01';
"X-Citrix-IsUsingHTTPS"= "No";
"Csrf-Token"=$csrf.value;
"Referer"=$sfurl;
"format"='json&resourceDetails=Default';
}
Invoke-WebRequest -Uri ($sfurl + "Resources/List") -Method POST -Headers $headers -WebSession $SFSession|Out-Null

#Gets authentication methods
$headers = @{
"Accept"='application/xml, text/xml, */*; q=0.01';
"Content-Length"="0";
"X-Citrix-IsUsingHTTPS"="No";
"Referer"=$sfurl;
"Csrf-Token"=$csrf.value;
}

Invoke-WebRequest -Uri ($sfurl + "Authentication/GetAuthMethods") -Method POST -Headers $headers -WebSession $SFSession|Out-Null

#Start Login Process
$headers = @{
"Accept"="application/xml, text/xml, */*; q=0.01";
"Csrf-Token"=$csrf.Value;
"X-Citrix-IsUsingHTTPS"="No";
"Content-Length"="0";
}

Invoke-WebRequest -Uri ($sfurl + "ExplicitAuth/Login") -Method POST -Headers $headers -WebSession $SFSession|Out-Null

#Explicit Authentication
$headers = @{
"Csrf-Token"=$csrf.Value;
"X-Citrix-IsUsingHTTPS"="No";
}

$body = @{
"loginBtn"="Log On";
"password"=$password;
"saveCredentials"="false";
"username"=$username;
"StateContext"="";
}

Invoke-WebRequest -Uri ($sfurl + "ExplicitAuth/LoginAttempt") -Method POST -Headers $headers -Body $body -WebSession $SFSession|Out-Null

#Gets resources and required ICA URL
$headers = @{
"Content-Type"='application/x-www-form-urlencoded; charset=UTF-8';
"Accept"='application/json, text/javascript, */*; q=0.01';
"Csrf-Token"=$csrf.value;
"Referer"=$sfurl;
"X-Citrix-IsUsingHTTPS"= "No";
"X-Requested-With"="XMLHttpRequest";
}

$body = @{
"format"='json';
"resourceDetails"='Default';
}

$content = Invoke-WebRequest -Uri ($sfurl + "Resources/List") -Method POST -Headers $headers -body $body -WebSession $SFSession

#Creates ICA file
$resources = $content.content | convertfrom-json

$resourceurl = $resources.resources|where{$_.name -like $appname}

if ($resourceurl.count)
{
    write-host "MULTIPLE APPS FOUND for $appname.  Check APP NAME!" -ForegroundColor Red
    $resourceurl|select id,name
}
else
{  
Invoke-WebRequest -Uri ($sfurl + $resourceurl.launchurl + '?CsrfToken=' + $csrf.value + "&IsUsingHttps=No") -Method GET -WebSession $SFSession -OutFile $icapath|Out-Null
    if (test-path $icapath)
    {
        write-host "Launching created ICA..."
        Start-Process $icapath
    }
    else
    {
        write-host "ICA not found check configuration"
    }
}