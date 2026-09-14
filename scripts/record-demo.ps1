param([Parameter(Mandatory=$true)][string]$Target)
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
foreach ($tool in @('cargo', 'py', 'ffmpeg')) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { throw "Missing prerequisite: $tool" }
}
py -c 'import PIL'
if ($LASTEXITCODE -ne 0) { throw 'The selected Python needs Pillow.' }
# Fresh output prevents stale frames from being appended; intermediates are ignored.
$frames = Join-Path 'target' ('demo-' + [guid]::NewGuid().ToString('N'))
cargo run --locked --features record --bin knife-record -- $Target scripts/demo.knife $frames
if ($LASTEXITCODE -ne 0) { throw 'TUI recording failed' }
py scripts/rasterize-frames.py $frames
if ($LASTEXITCODE -ne 0) { throw 'Frame rasterization failed' }
ffmpeg -y -loglevel error -framerate 12 -i "$frames/frame-%04d.png" -vf 'palettegen=stats_mode=diff' "$frames/palette.png"
if ($LASTEXITCODE -ne 0) { throw 'Palette generation failed' }
ffmpeg -y -loglevel error -framerate 12 -i "$frames/frame-%04d.png" -i "$frames/palette.png" -lavfi 'paletteuse=dither=bayer:bayer_scale=3:diff_mode=rectangle' -loop 0 assets/demo.gif
if ($LASTEXITCODE -ne 0) { throw 'GIF encoding failed' }
ffmpeg -y -loglevel error -framerate 12 -i "$frames/frame-%04d.png" -vf 'pad=ceil(iw/2)*2:ceil(ih/2)*2' -c:v libx264 -pix_fmt yuv420p -movflags +faststart assets/demo.mp4
if ($LASTEXITCODE -ne 0) { throw 'MP4 encoding failed' }
Write-Host "Created assets/demo.gif and assets/demo.mp4; frames: $frames"
