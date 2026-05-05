#!/usr/bin/expect -f
# SSH via PKCS#11 (YubiKey) with auto-PIN entry.
# Usage: ssh_askpass.sh <PIN> <ssh_args...>
# Called by app.py _ssh_run_cmd() in pkcs11 mode.

set timeout [lindex $argv 0]
set pin [lindex $argv 1]
set ssh_args [lrange $argv 2 end]

spawn -noecho ssh {*}$ssh_args

expect {
    -nocase "passphrase" {
        send "$pin\r"
        exp_continue
    }
    -nocase "pin" {
        send "$pin\r"
        exp_continue
    }
    -nocase "password:" {
        send "$pin\r"
        exp_continue
    }
    -nocase "yes/no" {
        send "yes\r"
        exp_continue
    }
    timeout {
        exit 1
    }
    eof
}

# Capture exit code of ssh process
lassign [wait] pid spawnid os_error value
exit $value
