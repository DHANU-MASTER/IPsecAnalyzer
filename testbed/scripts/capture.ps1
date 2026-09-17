# Native Windows PowerShell Capture Script for IPsec VPN Testbed

$configs = @("tunnel-aes128", "tunnel-aes256-gcm", "transport-aes128")
$trafficTypes = @("icmp", "web", "voip", "mixed")

# Ensure dataset directory exists
if (!(Test-Path "../dataset")) {
    New-Item -ItemType Directory -Force -Path "../dataset" | Out-Null
}

foreach ($config in $configs) {
    foreach ($traffic in $trafficTypes) {
        Write-Host "🚀 Capturing Testbed Traffic: $config + $traffic" -ForegroundColor Cyan

        # Start IPsec tunnel inside Docker container
        docker exec testbed-vpn-client-1 ipsec up $config
        Start-Sleep -Seconds 3

        # Execute capture inside vpn-client container for 15 seconds
        $outputPcap = "/etc/ipsec.d/${config}_${traffic}.pcap"
        docker exec testbed-vpn-client-1 tcpdump -i eth0 -c 50 -w $outputPcap

        # Copy captured pcap out to host dataset folder
        docker cp "testbed-vpn-client-1:${outputPcap}" "../dataset/${config}_${traffic}.pcap"

        # Down tunnel
        docker exec testbed-vpn-client-1 ipsec down $config
        Start-Sleep -Seconds 1
    }
}

Write-Host "✅ Traffic capture complete! PCAP dataset saved to dataset/ directory." -ForegroundColor Green
