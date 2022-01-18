#enable TLS1.2
$SChannelRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

New-Item $SChannelRegPath"\TLS 1.2\Server" -Force

New-Item $SChannelRegPath"\TLS 1.2\Client" -Force

New-ItemProperty -Path $SChannelRegPath"\TLS 1.2\Server" `
-Name Enabled -Value 1 -PropertyType DWORD

New-ItemProperty -Path $SChannelRegPath"\TLS 1.2\Server" `
-Name DisabledByDefault -Value 0 -PropertyType DWORD

New-ItemProperty -Path $SChannelRegPath"\TLS 1.2\Client" `
-Name Enabled -Value 1 -PropertyType DWORD

New-ItemProperty -Path $SChannelRegPath"\TLS 1.2\Client" `
-Name DisabledByDefault -Value 0 -PropertyType DWORD

#.net to use TLS 1.2
$RegPath1 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319"

New-ItemProperty -path $RegPath1 `
-name SystemDefaultTlsVersions -value 1 -PropertyType DWORD

New-ItemProperty -path $RegPath1 `
-name SchUseStrongCrypto -value 1 -PropertyType DWORD

 

$RegPath2 = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"

New-ItemProperty -path $RegPath2 `
-name SystemDefaultTlsVersions -value 1 -PropertyType DWORD

New-ItemProperty -path $RegPath2 `
-name SchUseStrongCrypto -value 1 -PropertyType DWORD

#disable TLS 1.0 and 1.3
New-Item $SChannelRegPath -Name "TLS 1.0"

New-Item $SChannelRegPath"\TLS 1.0" -Name SERVER

New-ItemProperty -Path $SChannelRegPath"\TLS 1.0\SERVER" `
-Name Enabled -Value 0 -PropertyType DWORD

New-Item $SChannelRegPath"\TLS 1.1\Server" –force

New-Item $SChannelRegPath"\TLS 1.1\Client" –force

New-ItemProperty -Path $SChannelRegPath"\TLS 1.1\Server" `
-Name Enabled -Value 0 -PropertyType DWORD

New-ItemProperty -Path $SChannelRegPath"\TLS 1.1\Server" `
-Name DisabledByDefault -Value 0 -PropertyType DWORD

New-ItemProperty -Path $SChannelRegPath"\TLS 1.1\Client" `
-Name Enabled -Value 0 -PropertyType DWORD

New-ItemProperty -Path $SChannelRegPath"\TLS 1.1\Client" `
-Name DisabledByDefault -Value 0 -PropertyType DWORD

#disable weak ciphers
Disable-TlsCipherSuite -Name "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
Disable-TlsCipherSuite -Name "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_256_GCM_SHA384"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_128_GCM_SHA256"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_256_CBC_SHA256"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_128_CBC_SHA256"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_256_CBC_SHA"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_128_CBC_SHA"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
Disable-TlsCipherSuite -Name "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"
Disable-TlsCipherSuite -Name "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"
Disable-TlsCipherSuite -Name "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"
Disable-TlsCipherSuite -Name "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"
Disable-TlsCipherSuite -Name "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_RC4_128_SHA"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_RC4_128_MD5"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_NULL_SHA256"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_NULL_SHA"
Disable-TlsCipherSuite -Name "TLS_PSK_WITH_AES_256_GCM_SHA384"
Disable-TlsCipherSuite -Name "TLS_PSK_WITH_AES_128_GCM_SHA256"
Disable-TlsCipherSuite -Name "TLS_PSK_WITH_AES_256_CBC_SHA384"
Disable-TlsCipherSuite -Name "TLS_PSK_WITH_AES_128_CBC_SHA256"
Disable-TlsCipherSuite -Name "TLS_PSK_WITH_NULL_SHA384"
Disable-TlsCipherSuite -Name "TLS_PSK_WITH_NULL_SHA256"
