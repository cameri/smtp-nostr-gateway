const fs = require('fs');
const secp256k1 = require('@noble/secp256k1')
const { SMTPServer } = require('smtp-server')
const { simpleParser } = require('mailparser')
const { getRandomValues, createCipheriv, createHmac } = require('crypto')
const WebSocket = require('ws')

const relay = 'wss://relay.damus.io'
const cert = './certs/wlvs.space.crt'
const key = './certs/wlvs.space.key'
const allowedPattern = /^[a-f0-9]{64}@wlvs\.space$/ // pubkey-in-hex@wlvs.space

const secret = process.env.SECRET;
if (typeof secret !== 'string' || !secret.length) {
  throw new Error('SECRET is not set or is empty')
}

let ws
connectWs()

function connectWs() {
  ws = new WebSocket(relay)

  const secret = process.env.SECRET;
  if (typeof secret !== 'string' || !secret.length) {
    throw new Error('SECRET is not set or is empty')
  }

  var heartbeat
  heartbeat = setInterval(() => {
    ws.ping()
  }, 10000);

  ws.onopen = () => {
    console.log('Connected to', relay)
  }

  ws.onerror = (err) => {
    console.log('websocket error:', err)
  }

  ws.onmessage = (event) => {
    console.log('websocket received: %s', event.data);
  };

  ws.onclose = () => {
    clearInterval(heartbeat)
    console.log('websocket closed')
    connectWs(relay)
  }
}

function encrypt( privkey, pubkey, text ) {
  var key = Buffer.from(secp256k1.getSharedSecret( privkey, '02' + pubkey, true )).toString('hex').substring( 2 );
  var iv = getRandomValues(new Uint8Array(16));
  var cipher = createCipheriv( 'aes-256-cbc', Buffer.from(key, 'hex'), iv );
  var encryptedMessage = cipher.update(text,"utf8","base64");
  emsg = encryptedMessage + cipher.final( "base64" );
  return emsg + "?iv=" + Buffer.from(iv.buffer).toString('base64');
}

const serializeEvent = (event) => JSON.stringify([
  0,
  event.pubkey,
  event.created_at,
  event.kind,
  event.tags,
  event.content,
])

const server = new SMTPServer({
  key: fs.readFileSync(key),
  cert: fs.readFileSync(cert),
  authOptional: true,
  size: 10*1024, // allow messages up to 1 kb
  onRcptTo(address, session, callback) {
    console.log('Received mail for', address.address)

    if (!allowedPattern.test(address.address)) {
      console.error('Error: Invalid recipient')
      err = new Error("Invalid recipient: " + address.address)
      err.responseCode = 510
      return callback(err)
    }

    let expectedSize = Number(session.envelope.mailFrom.args.SIZE) || 0;
    if (expectedSize > 10*1024) {
      console.error('Error: Mail exceeds maximum size')
      err = new Error("Insufficient channel storage: " + address.address);
      err.responseCode = 452;
      return callback(err);
    }
    callback();
  },
  async onData(stream, session, callback) {
    stream.on('end', () => {
      let err;
      if (stream.sizeExceeded) {
        err = new Error("Message exceeds fixed maximum message size");
        err.responseCode = 552;
        return callback(err);
      }
      callback(null, "Message received");
    })

    const mail = await simpleParser(stream);

    const hmac = createHmac('sha256', secret)

    hmac.update(mail.from.value[0].address)

    const privkey = hmac.digest().toString('hex')

    const senderPubkey = Buffer.from(secp256k1.getPublicKey(privkey, true)).toString('hex').substring(2)

    const content = `To: ${mail.to.text}\r\nFrom: ${mail.from.text}\r\nSubject: ${mail.subject}\r\n${mail.text}`

    const created_at = Math.floor(mail.date.getTime()/1000)

    for (const address of mail.to.value) {
      const [pubkey] = address.address.match(/^[a-f0-9]+/)
      const event = {
        pubkey: senderPubkey,
        kind: 4,
        content: encrypt(privkey, pubkey, content),
        created_at,
        tags: [
          ['p', pubkey],
        ],
      }

      const id = Buffer.from(
        await secp256k1.utils.sha256(
          Buffer.from(serializeEvent(event))
        )
      ).toString('hex')

      const sig = Buffer.from(
        await secp256k1.schnorr.sign(id, privkey)
      ).toString('hex')
  
      const message = ['EVENT', { ...event, id, sig }]
      
      console.log(`Mail forwarded to ${pubkey}`)

      ws.send(JSON.stringify(message))
    }
  }
})

server.on('error', (error) => {
  console.error('Server error', error)
})

const port = 25
server.listen(port, undefined, undefined, () => {
  console.log('Listening on port', port)
})
