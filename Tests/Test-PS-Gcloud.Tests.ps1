BeforeDiscovery {
  gcloud config configurations activate default --quiet
  gcloud projects list | Out-Null
  $result = $LASTEXITCODE
  if ($result -eq 1) {
    Write-Information 'gcloud auth login needed'
    gcloud auth login
    # $Raise_Error = "Error running gcloud command. $result"; Throw $Raise_Error
  }
  if ($result -ne 0) {
    $Raise_Error = "Error running gcloud command. $result"; Throw $Raise_Error
  }
}
BeforeAll {
  . "$PSScriptRoot\..\_PSGcloudHelper.ps1"
  $p = '../PS-Gcloud.ps1'
}

Describe 'Tests' {
  Context 'Configurations' {
    BeforeAll {
      $load = Get-LoadOptions -ResourceType Configurations | select -ExpandProperty LoadCmd
      $testConfig = "pester-$(Get-Random)"
    }
    It '[Q]UIT' {
      $result = &$p -Configurations q
      $exit = $LASTEXITCODE
      $exit | Should -Be 0
    }
    It '[A]CTIVATE by ix' {
      $result = &$p -Configurations 1
      $exit = $LASTEXITCODE
      $exit | Should -Be 0
    }
    It '[C]REATE' {
      $result = &$p -Configurations "c=$testConfig" -Show-Command
      $exit = $LASTEXITCODE
      $exit | Should -Be 0
      $result | Should -Be "COMMAND: gcloud config configurations create $testConfig`n"
      # $load = "$load --filter='is_active=True'"
      # $load = $ExecutionContext.InvokeCommand.ExpandString($load)
      # $activeConf = Invoke-Expression $load
      # if ($LASTEXITCODE -ne 0) {
      #   $Raise_Error = 'Error running gcloud command'; Throw $Raise_Error
      # }
  
      # $activeConf = $activeConf | ConvertFrom-Csv
      # $activeConf.name | Should -Be $testConfig
    }
    It '[D]ELETE by name' {
      # gcloud config configurations activate default --quiet
      $result = &$p -Configurations 'e:default' -Show-Command
      $exit = $LASTEXITCODE
      $exit | Should -Be 0
      $result | Should -Be "COMMAND: gcloud config configurations delete default`n"
    }
    It '[D]ELETE by ix' {
      $result = &$p -Configurations 'e1' -Show-Command
      $exit = $LASTEXITCODE
      $exit | Should -Be 0
      $result | Should -Be "COMMAND: gcloud config configurations delete default`n"
    }

    AfterAll {
      # $cmd = Get-LoadOptions -ResourceType Configurations | select -ExpandProperty LoadCmd
      #   gcloud config configurations activate default --quiet
      #   gcloud config configurations delete $testConfig --quiet
    }
  }
}