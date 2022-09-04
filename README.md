# SMTP Nostr Gateway

# Dependencies
- Node
- Iptables or UFW (not explained here)

## Getting Started
1. Add firewall rules to allow SMTP traffic (see this [guide](https://www.cyberciti.biz/faq/how-to-save-iptables-firewall-rules-permanently-on-linux/) to make this change permanent)

  ```
  sudo iptables -A INPUT -p tcp --dport 25 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
  sudo iptables -A OUTPUT -p tcp --sport 25 -m conntrack --ctstate ESTABLISHED -j ACCEPT
  ```

2. Create file with secret (once)

  ```
  mkdir -p /etc/smtp-nostr-gateway
  echo -n "definitely-do-not-use-this-secret" | sudo tee /etc/smtp-nostr-gateway/secret
  ```

3. Install packages

  ```
  npm install
  ```

4. Run

  ```
  sudo SECRET=$(cat /etc/smtp-nostr-gateway/secret) node index.js
  ```

