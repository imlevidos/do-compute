. $PSScriptRoot/Control-WinApps.ps1

Write-Debug "Starting WinampAutoFlush."

function Get-WinampStatus {
  param(
    [Parameter(Mandatory = $true)]$Window
  )
  $playStatus = $window.SendMessage(0x0400, 0, 104) # 0: stopped, 1: playing, 3: paused
  $SeekPosMS = $window.SendMessage(0x0400, 0, 105)

  $status = "$($window.hWnd);$playStatus;$SeekPosMS"
  return @{
    hWnd        = $window.hWnd
    PlayStatus  = $playStatus
    SeekPosMS   = $SeekPosMS
    statusCheck = $status
  }
}

function Restart-Winamp {
  param(
    [Parameter(Mandatory = $true)]$Window
  )
  $playStatus = $window.SendMessage(0x0400, 0, 104) # 0: stopped, 1: playing, 3: paused
  $SeekPosMS = $window.SendMessage(0x0400, 0, 105)
  Write-Debug "Winamp: hWnd: $($window.hWnd), PlayStatus: $playStatus, SeekPos: $SeekPosMS"

  Write-Debug "Restarting Winamp.."
  $window.SendMessage(0x0400, 0, 135) | Out-Null

  while ($true) {
    try {
      $window = [System.Windows.Win32Window]::FromProcessName("winamp")
      break
    }
    catch {
      Write-Debug "Waiting for Winamp to restart.."
      Start-Sleep -Seconds 1
    }
  }

  Write-Debug "Winamp restarted: hWnd: $($window.hWnd), PlayStatus: $playStatus, SeekPos: $SeekPosMS"


  switch ($playStatus) {
    1 {
      Write-Debug "Pressing: Play"
      $window.SendMessage(0x0111, 40045, 0) | Out-Null
      Write-Debug "Seeking to previous pos: $seekPosMS"
      $window.SendMessage(0x0400, $SeekPosMS, 106) | Out-Null
    }
    3 {
      Write-Debug "Pressing: Play"
      $window.SendMessage(0x0111, 40045, 0) | Out-Null
      Write-Debug "Seeking to previous pos: $seekPosMS"
      $window.SendMessage(0x0400, $SeekPosMS, 106) | Out-Null
      Write-Debug "Pressing: Pause"
      $window.SendMessage(0x0111, 40046, 0) | Out-Null
    }
  }
}

$FlushAfterSeconds = 30
$RestartedAt = $null
$PlayStopped = $null
$PlayStoppedCheck = $null

Write-Debug "Winamp will be restarted after being inactive for $FlushAfterSeconds seconds."

while ($true) {
  Start-Sleep -Seconds 5

  if (!(Get-Process "winamp" -ErrorAction SilentlyContinue)) {
    Write-Verbose "Winamp not started."
    Continue
  }

  $window = [System.Windows.Win32Window]::FromProcessName("winamp")
  $status = Get-WinampStatus -Window $window

  if ($status.playStatus -eq 1) {
    Write-Verbose "Winamp currently playing, nothing to do."
    $PlayStopped = $null
    Continue
  }

  if (!$PlayStopped) {
    Write-Debug "Winamp is now stopped or paused; recording state."
    $PlayStopped = Get-Date
    $PlayStoppedCheck = $status.statusCheck
    Continue
  }

  if ($PlayStoppedCheck -ne $status.statusCheck) {
    Write-Debug "Winamp state changed since last check, even if it's stopped. Resetting counter."
    $PlayStopped = Get-Date
    $PlayStoppedCheck = $status.statusCheck
    Continue
  }

  if ($RestartedAt -eq $status.statusCheck) {
    Write-Verbose "Winamp already restarted, nothing to do for now."
    Continue
  }

  $StoppedSeconds = ($(Get-Date) - $PlayStopped).Seconds
  Write-Debug "Winamp stopped for $StoppedSeconds seconds."

  if ($StoppedSeconds -gt $FlushAfterSeconds) {
    Write-Debug "Winamp stopped for 5 minutes, restarting."
    Restart-Winamp -Window $window
    $window = [System.Windows.Win32Window]::FromProcessName("winamp")
    $status = Get-WinampStatus -Window $window
    $RestartedAt = $status.statusCheck
  }
}
