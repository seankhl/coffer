# coffer
### a command line tool and minimal dialog for 1password vaults

# what exists now

Right now if you just run the code as normal for go programs:

    go run 1password.go

it will just decrypt a 1Password.opvault/default folder at the given path. For
now, you'll have to edit the path yourself since this code is still in a
fledgling state. It will only decrypt band 0 for now, but it's trivial to
decrypt the rest of the bands, and it will print out the contents of that band,
namely, all the items that are stored in that band.

There is no guarantee that this doesn't trivially leak your password somehow, so
please be careful with it.
