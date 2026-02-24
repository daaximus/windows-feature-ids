$dbg_help_path = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\dbghelp.dll" # REQUIRED. NO CHANGE EXCEPT DIRECTORY.
$symbol_path = "srv*c:\symbols*http://msdl.microsoft.com/download/symbols" # REQUIRED. NO CHANGE EXCEPT DIRECTORY.
# set enviroment path of symchk (default: C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe)

$bin_paths = New-Object -TypeName System.Collections.ArrayList
Write-Output "*]]> acquiring all dll/exe/sys/efi in system32"
Get-ChildItem "C:\Windows\System32" -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notlike "*\WinSxS\*" -and $_.FullName -notlike "*\servicing\*" -and $_.FullName -notlike "*\assembly\*" -and $_.FullName -notlike "*\downlevel\*" } | ForEach-Object -Process {
    if($_.Extension -eq ".dll" -or  $_.Extension -eq ".exe" -or $_.Extension -eq ".sys" -or $_.Extension -eq ".efi" ){
        $bin_paths.add($_.FullName) | Out-Null
    }
}

$staged_paths = New-Object -TypeName System.Collections.ArrayList
Write-Output "*]]> creating/updating binary database"
if(-not(Test-Path -Path "$PSScriptRoot\WindowsBinsDB")){
    mkdir "$PSScriptRoot\WindowsBinsDB" | Out-Null
}

$copied_count = 0
$skipped_copy_count = 0

foreach($full_path in $bin_paths)
{
	try{
		$base_name = [System.IO.Path]::GetFileNameWithoutExtension($full_path)
		$file_name = [System.IO.Path]::GetFileName($full_path)
		
		$dest_dir = "$PSScriptRoot\WindowsBinsDB\$base_name"
		$dest_file = "$dest_dir\$file_name"
		
		if (Test-Path $dest_file) {
			$skipped_copy_count++
			$staged_paths.add($dest_file) | Out-Null
			continue
		}
		
		Write-Output "+]]> copying: $file_name"
		
		if (!(Test-Path $dest_dir)) {
			New-Item -ItemType Directory -Path $dest_dir -Force | Out-Null
		}
		
		Copy-Item $full_path -Destination $dest_file -Force | Out-Null
		$staged_paths.add($dest_file) | Out-Null
		$copied_count++
	} catch {
		Write-Output "!]]> copy failed: $_"
		continue;
	}
}

Write-Output "*]]> copied $copied_count new binaries, skipped $skipped_copy_count existing"
Write-Output "*]]> cleaning old analysis results"

$cleaned_count = 0
Get-ChildItem "$PSScriptRoot\WindowsBinsDB" -Recurse -Filter "AnalysisResults.txt" -ErrorAction SilentlyContinue | ForEach-Object {
    Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
    $cleaned_count++
}

Write-Output "*]]> deleted $cleaned_count old result files"
Write-Output "*]]> cleaning stale lock flags"

$stale_count = 0
Get-ChildItem "$PSScriptRoot\WindowsBinsDB\*\.processing" -ErrorAction SilentlyContinue | ForEach-Object {
    Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
    $stale_count++
}
if ($stale_count -gt 0) {
    Write-Output "*]]> removed $stale_count stale .processing flags from interrupted runs"
}

Get-ChildItem "$PSScriptRoot\WindowsBinsDB\*\.complete" -ErrorAction SilentlyContinue | ForEach-Object {
    Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
}

Write-Output "*]]> starting analysis pass"

$total_bins = $staged_paths.Count
$to_process = $total_bins

if ($to_process -eq 0) {
	Write-Output "*]]> no binaries to analyze"
	exit 0
}

$bin_list_file = "$PSScriptRoot\WindowsBinsDB\_binarylist.txt"
$staged_paths | Out-File -FilePath $bin_list_file -Encoding UTF8 -Force

$max_jobs = [Math]::Min(10, $to_process)

Write-Output "*]]> total binaries: $total_bins"
Write-Output "*]]> to analyze: $to_process"
Write-Output "*]]> jobs running: $max_jobs"

Write-Output "*]]> launching analysis"
$job_script = {
    param($bin_list_file, $script_root, $job_id)
    
	if ($env:Path -notlike "*$script_root\IDA*") {
        $env:Path = $env:Path + ";$script_root\IDA"
    }
	
    $bin_list = Get-Content $bin_list_file -ErrorAction Stop | Where-Object { $_.Trim() -ne "" }
    
    $processed = 0
    $skipped = 0
    foreach($full_path in $bin_list) {
        $full_path = $full_path.Trim()
        if ([string]::IsNullOrEmpty($full_path)) { continue }
        
        $target_name = (($full_path.Split("."))[0].Split("\"))[-1]
        
        $bin_dir = "$script_root\WindowsBinsDB\$target_name"
        $processing_flag = "$bin_dir\.processing"
        $complete_flag = "$bin_dir\.complete"
        
        if (Test-Path $complete_flag) {
            $skipped++
            continue
        }
        
        if (Test-Path $processing_flag) {
            continue
        }
        
        if(-not(Test-Path -Path $bin_dir)){
            try { New-Item -ItemType Directory -Path $bin_dir -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
        }
        
        try {
            New-Item -Path $processing_flag -ItemType File -ErrorAction Stop | Out-Null
        } catch {
            continue
        }
        
        Write-Output "<[job $job_id]> starting: $target_name"
        
        New-Item "$bin_dir\AnalysisResults.txt" -ItemType file -Force | Out-Null
        [System.Diagnostics.Process]::Start("ida.exe","-c -A -S`"$script_root\ExtractFeatures.py`" $full_path").WaitForExit(10000000) | Out-Null
		
        Remove-Item $processing_flag -ErrorAction SilentlyContinue
        New-Item $complete_flag -ItemType file -Force | Out-Null
        
        $result_content = Get-Content "$bin_dir\AnalysisResults.txt" -ErrorAction SilentlyContinue
        if(!$result_content){
            Write-Output "<[job $job_id]> !> failed: $target_name"
        } else {
            Write-Output "<[job $job_id]> done: $target_name"
        }
        
        $processed++
    }
    
    return "<[job $job_id]> processed $processed binaries (skipped $skipped already done)"
}

$jobs = @()
for ($idx = 0; $idx -lt $max_jobs; $idx++) {
    Write-Output "+]]> starting job $idx"
    $jobs += Start-Job -ScriptBlock $job_script -ArgumentList $bin_list_file, $PSScriptRoot, $idx
}

try {
    while (Get-Job -State Running) {
        $completed = (Get-ChildItem "$PSScriptRoot\WindowsBinsDB\*\.complete" -ErrorAction SilentlyContinue).Count
        $processing = (Get-ChildItem "$PSScriptRoot\WindowsBinsDB\*\.processing" -ErrorAction SilentlyContinue).Count
        
        Write-Host "`rcompleted: $completed/$total_bins | active: $processing" -NoNewline
        
        foreach ($job in $jobs) {
            $job | Receive-Job
        }
        
        Start-Sleep -Seconds 2
    }
    
    Write-Host ""
    
    foreach ($job in $jobs) {
        Write-Output "]]> results from job $($job.Id):"
        Receive-Job $job
        Remove-Job $job
    }
} finally {
    foreach ($job in $jobs) {
        if ($job.State -eq 'Running') {
            Stop-Job $job -ErrorAction SilentlyContinue
        }
        Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
    
    Get-ChildItem "$PSScriptRoot\WindowsBinsDB\*\.processing" -ErrorAction SilentlyContinue | ForEach-Object {
        Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
    }
}

Remove-Item $bin_list_file -ErrorAction SilentlyContinue

$final_count = (Get-ChildItem "$PSScriptRoot\WindowsBinsDB\*\.complete" -ErrorAction SilentlyContinue).Count
Write-Output "*]]> finished;;analyzed $final_count / $total_bins binaries"