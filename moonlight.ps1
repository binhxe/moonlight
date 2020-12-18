# MoonLight 17/12/2020

param (
    $ADomain = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName
)

function Base64Decode($s)
{
    
	$text = "rq3gsalt6u1iyfzop572d49bnx8cvmkewhj"    	
	$text2 = "0_-."
	$text3 = ""
	$random = New-Object -TypeName System.Random
	
	foreach ($value in [char[]]$s)
	{
		$num = $text2.IndexOf($value)
        if ($num -lt 0)
        {
            $text3 = $text3 + $text[($text.IndexOf($value) + 4) % $text.Length]
        }
        else
        {
            $text3 = $text3 + $text2[0] + $text[$num + $random.Next() % ($text.Length / $text2.Length) * $text2.Length]
        }
		 
	}
    
	return $text3;
}

function Base64Encode($bytes, $rt)
{
				
    $text = "ph2eifo3n5utg1j8d94qrvbmk0sal76c"
	$text2 = ""
	$num = 0

	$i = 0;
	foreach ($b in $bytes)
	{
        
	    $num = [uint32]$num -bor [uint32]([uint32]$b -shl $i)

		for ($i += 8; $i -ge 5; $i -= 5)
	    {
		    $text2 += $text[[int]($num -band 31)]
			$num = $num -shr 5;
	    }
	}
	
    if ($i -gt 0)
	{
	    if ($rt)
		{
            $random = New-Object -TypeName System.Random
		    $num = [uint32]$num -bor [uint32]([uint32]$random.Next() -shl $i)
		}
		$text2 += $text[[int]($num -band 31)]		
    }

    return $text2
}

function DGA($domain)
{
    $encode = $false
    $retval = ""

    foreach ($c in [char[]]$domain)
    {
        if (-not "0123456789abcdefghijklmnopqrstuvwxyz-_.".Contains("$c"))
        {
            $encode = $true
            break
        }
    }
				
    if($encode)
    {
        $retval =  "00"
        $domain_bytes = [System.Text.Encoding]::UTF8.GetBytes($domain)
        $retval += Base64Encode -bytes $domain_bytes -rt $false         
    }
    else
    {
        $retval = Base64Decode -s $domain
    }

    return $retval
}

if ($ADomain -eq "")
{
    write-host "No AD domain detected. Please provide AD domain manually"
}
else
{
    $dga = DGA -domain $ADomain
    write-host "The DGA for domain $ADomain is $dga"
    write-host "Splunk query example: index=proxylogs dest_host=*$a* | fields + dest_host"
}
