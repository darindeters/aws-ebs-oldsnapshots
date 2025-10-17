# aws-ebs-oldsnapshots
Helps organizations audit across an aws organization snapshot and detacted volume sprawl.

## Minimum snapshot size filter

Use `--min-size-gib` when running `list_old_snapshots.py` to ignore snapshots whose logical size is below the
threshold. For example, `./list_old_snapshots.py --min-size-gib 10` will exclude snapshots smaller than 10 GiB and
report how many snapshots were filtered out in the summary output.
