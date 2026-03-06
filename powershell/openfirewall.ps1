New-NetFirewallRule `
  -DisplayName "Allow Tenable" `
  -Direction Inbound `
  -Action Allow `
  -RemoteAddress 10.0.0.8 `
  -Protocol Any `
  -Profile Any
