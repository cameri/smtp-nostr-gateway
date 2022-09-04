# SMTP Nostr Gateway

# Dependencies
- Node v18
- `iptables` or `ufw` (not explained here)

## Getting Started
1. Add firewall rules to allow SMTP traffic (see this [guide](https://www.cyberciti.biz/faq/how-to-save-iptables-firewall-rules-permanently-on-linux/) to make this change permanent)

  ```sh
  sudo iptables -A INPUT -p tcp --dport 25 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
  sudo iptables -A OUTPUT -p tcp --sport 25 -m conntrack --ctstate ESTABLISHED -j ACCEPT
  ```

2. Create key & certificate for TLS
  ```sh
  # Warning: Follow the steps below at your own risk

  export DOMAIN=your.domain # e.g. wlvs.space
  
  cd certs/

  # Generate private key
  openssl genrsa -des3 $DOMAIN.key 1024

  # Generate certificate sign request
  openssl req -new -key $DOMAIN.key -out $DOMAIN.csr

  # Remove passphrase from key
  openssl rsa -in $DOMAIN.original -out $DOMAIN.key

  # Generate certificate from request & private key
  openssl x509 -req -days 365 -in $DOMAIN.csr -signkey $DOMAIN.key -out $DOMAIN.crt

  # Update the cert and key file on index.js 
  ```

3. Create file with secret (once)

  ```sh
  mkdir -p /etc/smtp-nostr-gateway
  echo -n "definitely-do-not-use-this-secret" | sudo tee /etc/smtp-nostr-gateway/secret
  ```

4. Install packages

  ```sh
  npm install
  ```

5. Run

  ```sh
  sudo SECRET=$(cat /etc/smtp-nostr-gateway/secret) node index.js
  ```

