# Serverus SSHnape

Secure a VPS with one command.

Fresh VPS, one command, done. A few minutes later it's locked down and ready for your production apps.

**Made for Debian 12 (bookworm) and 13 (trixie).** Pick Debian when your provider asks for an image. Ubuntu still works, but it's not recommended.

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
- Stops Docker from bypassing the firewall, containers are only reachable on the server's ports 80 and 443
- Fail2ban: 3 failed SSH logins = 1 hour ban, repeat offenders = 1 week
- Installs pending security updates right away, then automatically, reboots at 04:00 UTC only when an update needs it
- Checks from the outside that the server refuses password login
- Time sync with chrony, timezone set to UTC
- Adds a swap file if there is no swap, sized to RAM (1–4 GB)
- Caps log sizes: journal at 500 MB, Docker at 10 MB × 3 per container
- Hardens kernel network settings: SYN cookies, no ICMP redirects, no source routing
- auditd watches the SSH keys of every account that can log in, plus users, sudoers, cron, systemd and PAM
- Disables cups, avahi, rpcbind and nfs if present
- On Ubuntu: takes the Ubuntu Pro and ESM ads out of the login message, keeps the update count
- Installs `security-check`: tells you "All good" or what needs a look, then the details
- Adds the key to your `~/.ssh/config`
- Optional: puts the server behind a Cloudflare Tunnel, with 80 and 443 closed ([below](#behind-a-cloudflare-tunnel))

Then connect with:

```bash
ssh root@<ip>
```

For Debian 12+ servers. Ubuntu works but is not recommended. Run it from macOS or Linux.

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

It walks you through it: create a bot with @BotFather, paste the token, send the bot a message, and it says hello back. Free. You can add it later too: re-run the script on a hardened server and say yes.

Send `/status` to the bot any time and it answers with the health check:

```
[web1]
All good

Logins (24h): 3 from 1 IPs
Failed SSH attempts (24h): 212 from 48 IPs · 5 banned now
Open ports: tcp/22, tcp/80, tcp/443
Disk 34% · RAM 1.1Gi/1.9Gi · swap 0B/1.0Gi
Firewall on · fail2ban on · clock synced
up 3 days, 2 hours · no reboot pending
```

### One bot for all your servers

You need one bot, however many servers you have. The script remembers it on your machine, in `~/.config/serverus-sshnape/telegram`, readable only by you. On the next server it asks "Add this server to your bot?" and you press Enter. On another machine, paste the same token.

It also asks for a name for the server, like `web1`. Every alert starts with it and commands take it. Give each server a different one; leave it empty and the server's hostname is used.

| Send | What happens |
| --- | --- |
| `/servers` | Every server answers with one line: its name, how it's doing, how long it's been up |
| `/status` | Every server answers with its health check. `/status web1` asks just one |
| `/reboot web1` | Reboots that server. It texts you when it's back |
| `/shutdown web1 yes` | Powers that server off. It stays off until you start it in your provider's panel |
| `/remove web1` | Takes that server off the bot: no more alerts from it, and it forgets the bot's token |

To add a server, run the script on it and say yes to Telegram. To put a removed one back, do the same. A server you deleted at your provider needs no removing: it just stops answering.

No answer to a command? Check the name with `/servers`. A reboot, shutdown or removal only happens on the server whose name you typed, never on all of them.

The bot only listens to your chat, and nothing you type is run as a command: each word above maps to one fixed action. Still, whoever gets into your Telegram account can now reboot or shut down your servers, so turn on two-step verification in Telegram.

Servers set up with an older version of this script take the bot's messages for themselves. Run the script on them once more, then they share.

Your own jobs can text you too:

```bash
send-alert "backup failed"
```

A dead server can't text you, so use an outside uptime check for that.

## Behind a Cloudflare Tunnel

The script asks if you want a tunnel. Say yes and visitors reach your sites through Cloudflare instead of connecting to the server: free DDoS protection, and the server's IP appears in no DNS record. It works on Cloudflare's free plan.

You need a Cloudflare account with your domain on it. The script walks you through getting the token when it asks:

1. In the [Cloudflare dashboard](https://dash.cloudflare.com) go to Networking > Tunnels and click Create Tunnel.
2. Give it a name and click Create Tunnel.
3. The page shows commands to install and run `cloudflared`. Don't run them. The token is the long `eyJ...` text at the end of the command: copy it, or the whole command. The operating system you pick there doesn't matter.
4. Paste it into the script. Leave the page open: once the script is done it shows the tunnel as connected, and you click Continue.

Then the script:

- Installs `cloudflared` from Cloudflare's apt repo, kept up to date with the other automatic updates
- Runs it as a service under its own account with no privileges. The token sits in a file only root and that service can read, never in a command line
- Closes 80 and 443 once the tunnel is connected. Only SSH stays open, on IPv4 and IPv6. A token that doesn't connect is undone and closes nothing
- Makes containers unreachable from outside, whatever ports they publish
- Blocks outgoing port 25, for the server and its containers: mail a server delivers itself shows its IP
- Warns about anything listening on a public address and containers publishing ports without `127.0.0.1`
- Checks from your machine that 80 and 443 don't answer
- With Telegram alerts on: texts you when the tunnel goes down and when it's back, and shows it in `/status`

Then put your sites on the tunnel. For each hostname: Networking > Tunnels > your tunnel > Routes > Add route > Published application, enter the hostname, set Service URL to `http://127.0.0.1:80` and click Add route. Cloudflare creates the DNS record itself. Your web server listens there in plain HTTP and Cloudflare does the HTTPS. With Caddy that means `http://example.com { ... }` site blocks and `default_bind 127.0.0.1`.

The server remembers it is tunnel-only: re-running the script keeps 80 and 443 closed. To add a tunnel later, or swap the token, re-run and say yes. To go back: `rm /etc/serverus-sshnape/tunnel-only`, `systemctl disable --now cloudflared`, `ufw delete reject out 25/tcp`, and re-run.

### Keeping the IP secret

The tunnel only protects you while nobody knows the server's IP. One place that shows it undoes all the others, and you can't take it back: the only fix after a leak is a new IP.

**DNS**

- Never point a record at the server. No `A` or `AAAA`, not as "DNS only", not for a minute, not for a harmless-looking `ssh.` or `dev.`. Every hostname is a tunnel route.
- No wildcard records, no `MX` to the server, and never its IP in an SPF record.
- No reverse DNS (PTR) with your domain on the IP.
- Deleted records stay public. DNS history sites keep a record that existed for five minutes forever.

**The server answering the internet**

- Never open 80 or 443, not even to get a certificate. Scanners sweep every IP, read the page or certificate, and tie your domain to the IP within hours.
- Bind every service to `127.0.0.1`, never `0.0.0.0`. In Docker: `"127.0.0.1:PORT:PORT"`.
- No other public service on the same server: no mail, game, VPN or FTP server.
- All sites on the server go through the tunnel, or none. One site outside it exposes the rest.

**The server calling out**

When the server fetches a URL someone else chose, that someone sees its IP: webhooks, link previews, "import from URL", avatar URLs, RSS and calendar imports, rendering user HTML to PDF. Send those through a relay, such as a small Cloudflare Worker. Calls to services you picked yourself (a mail API, a payment provider, object storage) are fine.

**Mail**

Send through a mail API (Resend, Brevo, ...), never from the server, and don't run a mail server on it.

**Your own content**

- Keep the IP out of code, docs, commits, issues and screenshots, private repos included. It belongs in `~/.ssh/config` and gitignored env files; use a placeholder like `203.0.113.10` elsewhere.
- No error or debug pages that print server details, no `X-Backend` or `Via` headers.
- SSH to the IP, never to a domain. Point uptime checks at the domain, never the IP.

**IPv6 counts too.** The server has an IPv6 address and every rule applies to it.

**Now and then**, look the IP up on search.censys.io and shodan.io: it should show SSH only, with no domain next to it. If it leaks anyway, get a new IP (IPv4 and IPv6), then find and close what leaked it.

## Running containers

Bind to localhost and put a reverse proxy in front:

```yaml
ports:
  - "127.0.0.1:3000:3000"
```

Without a tunnel, the reverse proxy is the one thing that answers on 80 and 443. Behind a tunnel the reverse proxy binds to `127.0.0.1:80` as well, and nothing answers publicly.

## Lost your key

Boot the server into your provider's rescue mode, mount the disk and add a new key to `/root/.ssh/authorized_keys`. The provider's web console won't do: no account has a password to log in with.

## License

MIT. See [LICENSE](LICENSE).
