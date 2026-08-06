# EnvSeal end-to-end integration smoke test.
# Simulates two developers (Alice shares -> Bob syncs) using isolated
# identities, then verifies the plaintext never leaks into the bundle.
#
# Usage:  powershell -File scripts\e2e.ps1
$ErrorActionPreference = 'Stop'
$base = 'C:\Users\Heman\Desktop\envsync\.scratch'
$exe  = 'C:\Users\Heman\Desktop\envsync\bin\envseal.exe'

function RunAs($identityDir, $workDir, [scriptblock]$body) {
    $prevUP = $env:USERPROFILE
    $prevHOME = $env:HOME
    try {
        $env:USERPROFILE = $identityDir
        $env:HOME = $identityDir
        Push-Location $workDir
        & $body
        if ($LASTEXITCODE -ne 0) { throw "command failed ($LASTEXITCODE)" }
        Pop-Location
    } finally {
        Pop-Location -ErrorAction SilentlyContinue
        $env:USERPROFILE = $prevUP
        $env:HOME = $prevHOME
    }
}

# Reset workspace.
Remove-Item -Recurse -Force "$base" -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path "$base\alice","$base\bob","$base\id-alice","$base\id-bob" | Out-Null

Write-Host "=== 1. Alice initializes ===" -ForegroundColor Cyan
RunAs "$base\id-alice" "$base\alice" { & $exe init --name acme-app }

Write-Host "=== 2. Seed Alice's env files ===" -ForegroundColor Cyan
@'
# canonical reference
DB_HOST=localhost
DB_PORT=5432
API_KEY=changeme
STRIPE_SECRET=sk_test_123
'@ | Set-Content -Path "$base\alice\.env.example" -Encoding ascii
@'
DB_HOST=localhost
DB_PORT=5432
API_KEY=real-abc123
STRIPE_SECRET=changeme
'@ | Set-Content -Path "$base\alice\.env.staging" -Encoding ascii

Write-Host "=== 3. Alice runs check ===" -ForegroundColor Cyan
RunAs "$base\id-alice" "$base\alice" { & $exe check --env staging }

Write-Host "=== 4. Bob initializes (separate identity) ===" -ForegroundColor Cyan
RunAs "$base\id-bob" "$base\bob" { & $exe init --name acme-app }

Write-Host "=== 5. Read Bob's public key (base64 text) ===" -ForegroundColor Cyan
$bobPub = (Get-Content "$base\id-bob\.envseal\identity.pub" -Raw).Trim()
Write-Output "Bob pubkey: $bobPub"

Write-Host "=== 6. Alice registers Bob's key ===" -ForegroundColor Cyan
RunAs "$base\id-alice" "$base\alice" {
    & $exe team add bob@example.com --name Bob --pubkey $bobPub
    & $exe team list
}

Write-Host "=== 7. Alice shares .env.staging to Bob ===" -ForegroundColor Cyan
RunAs "$base\id-alice" "$base\alice" {
    & $exe share --file .env.staging --env staging --to bob@example.com --output "$base\bob"
}

Write-Host "=== 8. Bob syncs the bundle ===" -ForegroundColor Cyan
Write-Host "-- verifying bundle is encrypted (no plaintext leak):" -ForegroundColor Yellow
if (Select-String -Path "$base\bob\STAGING.envseal.enc" -Pattern 'real-abc123' -Quiet) {
    throw 'PLAINTEXT LEAKED in bundle!'
}
RunAs "$base\id-bob" "$base\bob" {
    & $exe sync "$base\bob\STAGING.envseal.enc"
    Write-Host "-- bob/.env.staging contents:" -ForegroundColor Green
    Get-Content "$base\bob\.env.staging"
}

Write-Host "=== 9. Bob verifies with check ===" -ForegroundColor Cyan
RunAs "$base\id-bob" "$base\bob" {
    Copy-Item "$base\alice\.env.example" "$base\bob\.env.example"
    & $exe check --env staging
}

Write-Host "=== 10. Demonstrate merge into an existing .env ===" -ForegroundColor Cyan
Set-Content -Path "$base\bob\.env" -Value 'keep=this' -Encoding ascii
RunAs "$base\id-bob" "$base\bob" {
    & $exe sync --merge --out .env "$base\bob\STAGING.envseal.enc"
    Write-Host "-- merged .env (keep=this preserved + incoming keys):" -ForegroundColor Green
    Get-Content "$base\bob\.env"
}

Write-Host "=== E2E PASSED ===" -ForegroundColor Green
