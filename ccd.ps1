[System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
$foldername = New-Object System.Windows.Forms.FolderBrowserDialog
$foldername.Description = "Select a folder"
$foldername.rootfolder = "MyComputer"
$foldername.SelectedPath = $pwd.Path

if ($foldername.ShowDialog() -eq "OK") {
  Push-Location $foldername.SelectedPath
}
