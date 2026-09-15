Put each team member's SSH PUBLIC key here, named <username>.pub
(the same username listed in ../team-users.conf).

Generate a key on YOUR OWN machine (not on the Kali):
    ssh-keygen -t ed25519 -C "sixto@company"
    cat ~/.ssh/id_ed25519.pub      # paste this line into sixto.pub

Only .pub files belong here. NEVER put a private key
(a file starting with -----BEGIN OPENSSH PRIVATE KEY-----) in this folder.
