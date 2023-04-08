BeforeAll {
  $p = '../PS-Gcloud.ps1'
}

Describe 'Tests' {
  Context 'Configurations' {
    It 'Configurations List' {
      $result = &$p -Configurations q
      $exit = $LASTEXITCODE
      $exit | Should -Be 0
      $result | Should -Not -BeNullOrEmpty
    }
  }
}