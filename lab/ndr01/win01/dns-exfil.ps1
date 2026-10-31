# UC-10 DNS anomaly (T1071.004): fires long random-label DNS queries at SOC01:53.
# Query name length > 40 chars to trip the Suricata pcre "/^.{40,}$/".
$labels = -join ((1..5 | ForEach-Object { -join ((65..90)+(97..122) | Get-Random -Count 8 | ForEach-Object {[char]$_}) }) -join '.')
nslookup "$labels.corp.lab" 10.10.10.5
