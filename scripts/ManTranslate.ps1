$man = [xml](Get-Content $PSScriptRoot\$($args[0]))

$Templates = @{}
foreach ($temp in $man.SelectNodes('//template')) 
{
    $dataArr = @('FAKE')
    foreach ($d in $temp.data)
    {
        $dataArr += "$($d.name):$($d.inType)"
    }
    $Templates.Add($temp.tid, $dataArr)
}

$Strings = @{}
foreach ($str in $man.SelectNodes('//string')) 
{
    $Strings.Add($str.id, $str.value)
}

$AnalyticalEvent = @()
foreach ($evt in $man.SelectNodes('//event[@channel="channel0"]')) 
{
    $Message = $Strings[$evt.message.SubString(9, $evt.message.Length - 10)];
    $Operation = $Message.SubString(0, $Message.IndexOf(':'))
    $FormattedMessage = [regex]::Replace($Message, '%(\d+)', '{$1}') -f $Templates[$evt.template]
    $AnalyticalEvent += [pscustomobject]@{
        ID        = $evt.value;
        Operation = $Operation;
        Message   = $FormattedMessage
    }
}
$AnalyticalEvent | ConvertTo-Csv | Out-File $PSScriptRoot\$($args[1])