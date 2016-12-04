# Input : Exe Path, Dumpbin path, Test folder, x86/x64
# 
param (
    [Parameter(Mandatory=$true)][string]$TestFolder,
    [Parameter(Mandatory=$true)][string]$ScyllaExe,
    [Parameter(Mandatory=$true)][string]$Dumpbin
 )
Push-Location
Set-Location $TestFolder

Get-ChildItem -Filter *.exe | ForEach-Object {
  
  # Execute Dumpbin  
  $ExeAbsolutePath = resolve-path ${_};
  $iat_string=  &$Dumpbin /HEADERS $ExeAbsolutePath | Select-String "Import Address Table Directory" ;
  
  # Parse dumbpin log to retrieve the IAT
  $offset, $iat_string = $iat_string -split "\[", 2 ;
  $size, $iat_string = $iat_string -split "\]", 2 ;
  if ($offset -and $size){

    $offset = $offset.Trim();
    $size= $size.Trim();

    # Test ScyllaExe on it
    "{0} => {1} ({2})" -f ${_} , $offset, $size
    &$ScyllaExe $ExeAbsolutePath  $offset, $size
    
    if (-not $?){
      if ($LASTEXITCODE -eq 6){
          "Could not create process : admin priviledges required"
      }
      elseif($LASTEXITCODE -eq 5){
          "Could not create process : access refused"
      }
      elseif($LASTEXITCODE -eq 87){
          "Could not retrieve process entry point : wtf are you doing MS ?"
      }
      else{
          exit $LASTEXITCODE;
      }
    }

  }
}
exit 0;

Pop-Location