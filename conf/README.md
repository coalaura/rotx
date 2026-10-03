# Linux system service

Drop the Linux `rotx` binary, your application `rotx.conf` and this entire `conf/` folder into one directory. From that directory, run:

```sh
bash conf/setup.sh
```

Setup requests administrator privileges through `sudo` when necessary. It detects the deployment directory, creates the unprivileged `rotx` service account, secures deployment control files, creates or adopts `data/`, installs the complete systemd unit and enables and starts the service. No fixed installation path, separate drop-in installation or installed `mksvc` is required. The host needs systemd and the usual Linux administration tools, including `systemd-sysusers` and `runuser`.

Place the directory on a persistent, executable filesystem whose parent directories the service user can traverse, for example `/opt/rotx` or `/srv/rotx`. Paths containing spaces and systemd-special characters are escaped automatically. One `rotx.service` is installed per machine. Running setup again updates the installation; running it from a new deployment directory switches the service to that directory and its adjacent data.

The [production example](../examples/production/rotx.conf) shows application configuration, including static serving and reverse proxying. Provision the configured onion keys, included configuration and content before installing. `conf/rotx.conf` defines the Linux service account; the separate top-level `rotx.conf` is the application configuration.

## File access

Static content keeps its existing ownership and permissions. The service can read ordinary readable files under `/srv`, `/var/www`, `/home` or elsewhere without maintaining a directory allowlist. As with an unprivileged nginx worker, files must be readable by the service account and all parent directories must permit traversal. World-readable files under searchable directories work immediately. Owner-only files and private parent directories still require an appropriate group or ACL; the service does not bypass Unix permissions. Existing supplementary groups remain effective after a restart.

Setup makes the top-level application configuration `root:rotx` with mode `0640`. It does not recursively change your static content, included configurations or onion-key trees. Those files must already be readable by `rotx`; private keys can use a read-only service-group grant instead of world readability.

The filesystem is read-only to the service except for the adjacent `data/` directory. Setup gives `rotx` ownership of existing data, preserves its contents and makes `data/` and `data/tmp/` private. Tor state, disk compression caches and temporary files all live there. `TMPDIR` points to `data/tmp/`; private `/tmp`, `/var/tmp` and `/dev/shm` are read-only. The service cannot modify its binary, configuration or served content, even when their ordinary mode bits would allow writes. Do not put content you want protected from service writes under `data/`.

## Runtime policy

The service runs without root privileges, Linux capabilities, privilege escalation or privileged-port binding. It retains the `mksvc` hardening baseline: protected kernel settings, modules, logs, clock and control groups; restricted syscalls and namespaces; private devices and IPC; hidden unrelated processes; no core dumps; and a `0077` file-creation mask. Home directories are visible read-only rather than hidden.

Tor can connect to the network and bind its unprivileged loopback listener. Reverse proxies can reach local or remote upstreams. Executable memory remains available for Tor's HashX PoW JIT; `memfd` creation stays blocked. User namespaces are disabled to preserve ordinary file ownership and group access. CPU and memory caps are unset so the policy works across different Tor and proxy-buffering workloads.

```sh
sudo journalctl -u rotx.service -f
sudo systemctl restart rotx.service
systemctl cat rotx.service
systemd-analyze security rotx.service
```

Site-specific overrides can be added with `sudo systemctl edit rotx.service`; setup preserves them. Overrides can change the shipped security guarantees. Tor bootstrapping and onion descriptor publication remain asynchronous; successful service startup does not imply the onion address is already reachable.

## Maintenance

The unit was generated with `mksvc` and adapted for relocatable, automatic installation and data-only writes. Deploy the supplied files and rerun `bash conf/setup.sh` when updating.

To uninstall:

```sh
bash conf/uninstall.sh
```

Uninstall removes the service but preserves application files, data and the service account. Keeping the account reserved protects ownership of retained private state and allows a later reinstall to reuse it.
