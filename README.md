# Serverus SSHnape

Secure a VPS with one command.

Fresh VPS, one command, done. A few minutes later it's locked down and ready for your production apps.

```bash
curl -sLO https://raw.githubusercontent.com/chalmovsky/serverus-sshnape/main/serverus-sshnape.sh && chmod +x serverus-sshnape.sh && ./serverus-sshnape.sh <ip>
```

You type the root password once. That's the last time you'll ever need it.

## What it does

- Generates an ed25519 SSH key and installs it on the server
- Verifies the key works before changing anything
- Disables password login, root is key-only
- Overrides the provider sshd drop-ins that keep password login on
- Checks the effective sshd config before restarting sshd
- Locks the root password
- Firewall: deny all incoming, allow 22 (rate-limited), 80, 443
- Stops Docker from bypassing the firewall, containers are only reachable on 80 and 443
- Fail2ban: 3 failed SSH logins = 1 hour ban, repeat offenders = 1 week
- Automatic security updates, reboots at 04:00 UTC only when an update needs it
- Time sync with chrony, timezone set to UTC
- Adds a swap file if there is no swap, sized to RAM (1–4 GB)
- Caps log sizes: journal at 500 MB, Docker at 10 MB × 3 per container
- Hardens kernel network settings: SYN cookies, no ICMP redirects, no source routing
- auditd watches the SSH keys of every account that can log in, plus users, sudoers, cron, systemd and PAM
- Disables cups, avahi, rpcbind and nfs if present
- Takes the Ubuntu Pro and ESM ads out of the login message, keeps the update count
- Installs `security-check`: tells you "✅ All good" or what needs a look, then the details
- Adds the key to your `~/.ssh/config`

Then connect with:

```bash
ssh root@<ip>
```

For Ubuntu servers. Run it from macOS or Linux.

Safe to re-run: firewall rules you added yourself are kept. Reinstalled the server? Run it again and pick "start fresh" - it forgets the old key and the old host key for you.

## Alerts on your phone

The script asks if you want alerts. Say yes and the server texts you when something critical happens:

- SSH login from an IP that hasn't logged in during the last 30 days
- SSH keys, SSH config, users, sudoers or cron changed - with the file, who did it and with what
- A process killed for running out of memory
- A new port starts listening (just the port number)
- Disk over 90% full
- Server rebooted
- Every Monday morning, a short check-in, so silence never means "the bot died"

It walks you through it: create a bot with @BotFather, paste the token, send the bot a message, and it says hello back. Free. Use a separate bot for each server. You can add it later too: re-run the script on a hardened server and say yes.

Send `/status` to the bot any time and it answers with the health check:

```
✅ All good

🔑 Logins (24h): 3 from 1 IPs
🚫 Failed SSH attempts (24h): 212 from 48 IPs · 5 banned now
🌐 Open ports: tcp/22, tcp/80, tcp/443
💾 Disk 34% · RAM 1.1Gi/1.9Gi · swap 0B/1.0Gi
🛡 Firewall on · fail2ban on · clock synced
⏱ up 3 days, 2 hours · no reboot pending
```

It only answers you, and only runs that one read-only check.

Your own jobs can text you too:

```bash
send-alert "backup failed"
```

A dead server can't text you, so use an outside uptime check for that.

## Running containers

Bind to localhost and put a reverse proxy in front:

```yaml
ports:
  - "127.0.0.1:3000:3000"
```

## Lost your key

Boot the server into your provider's rescue mode, mount the disk and add a new key to `/root/.ssh/authorized_keys`. The provider's web console won't do: no account has a password to log in with.

## License

MIT. See [LICENSE](LICENSE).
