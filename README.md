Scan files against an OPSWAT Metascan server using the REST API.

Example Usage:

    # ./scan.py -fp "/bin/*cat*" --json --url https://localhost:8008 -o output.json \
    --user admin --password passwordhere
    Submitting file /bin/mkdir ...
    Submitting file /bin/bzcat ...
    Submitting file /bin/dir ...
    Submitting file /bin/uncompress ...
    Submitting file /bin/openvt ...
    Submitting file /bin/ntfscmp ...
    Submitting file /bin/static-sh ...
    Submitting file /bin/systemd-inhibit ...
    Submitting file /bin/bzfgrep ...
    Submitting file /bin/kmod ...
    Submitting file /bin/networkctl ...
    Submitting file /bin/systemd-sysusers ...
    Submitting file /bin/unicode_start ...
    Submitting file /bin/lessfile ...
    Submitting file /bin/dmesg ...
    Submitting file /bin/mktemp ...
    Submitting file /bin/lessecho ...
    Submitting file /bin/lowntfs-3g ...
    Submitting file /bin/ntfsrecover ...
    Submitting file /bin/btrfs-find-root ...
    Writing output.json ...

    # ./scan.py -fp "/bin/cat" --url https://localhost:8008 --user admin --password passwordhere
    Submitting file /bin/cat ...
    cat (ELF 64-bit LSB) => No Threat Detected - SHA1: f6f536b25d7ee7e314944e41d885d9075f79a9a8
