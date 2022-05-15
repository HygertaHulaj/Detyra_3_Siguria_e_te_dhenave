const client = require('dgram').createSocket('udp4');
const fs = require('fs');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const publicKey = fs.readFileSync('publickey.pem');
const saltRounds = 10;
const [node, file, command, ...args] = process.argv;
var key;

switch(command) {
  case 'register': register(args[0], args[1], args[2], args[3], args[4]);
  break;
  case 'login': login(args[0], args[1]);
  break;
  case 'help': help();
  break;
  default: console.log(`${command} is not a recognized command`);
  break;
}

function register(username, password, id, faculty, average) {
  if(!validate(username, password, id, faculty, average)) {
    console.log('Wrong parameters given');
    process.exit();
  }

  bcrypt.hash(password, saltRounds, function(err, hash) {
    const msg = Buffer
      .from(JSON.stringify({
        request: 'register',
        username,
        password: hash,
        id,
        faculty,
        average}));
    sendEncrypted(msg, 3000, 'localhost');
  });

}

function login(username, password) {
  if(!validate(username, password)) {
    console.log('Wrong parameters given');
    process.exit();
  }

  const msg = Buffer.from(JSON.stringify({request: 'login', username, password}));
  sendEncrypted(msg, 3000, 'localhost')
}

client.on('error', (err) => {
  console.log(`There was an error connecting:\n` + err.stack);
})

client.on('message', (msg) => {
  const message = JSON.parse(decrypt(msg));
  if(message.type == 'login_ok') {
    jwt.verify(message.info, publicKey, function(err, decoded) {
      if (err) {
        console.log("JWT from the server is invalid");
      }
      else {
        console.log("JWT is valid, message received:\n", decoded);
      }
    });
  } else {
    console.log('Message received:\n' + message.info);
  }
  process.exit();
})

function help() {
  console.log('register [username] [password] [id] [faculty] [average] - Creates a new user account');
  console.log('login [username] [password] - Logs in to an existing account');
  console.log('help - Lists commands');
  process.exit();
}

function validate(...args) {
  for (let i = 0; i < args.length; i++) {
    if(!args[i]) {
      return false;
    }
  }
  return true;
}

function sendEncrypted(message, port, ip) {
  const [encrypted, iv, rsaEncryptedKey] = encodeDesCBC(message);
  client.send(Buffer.from(iv + "." + rsaEncryptedKey + "." + encrypted, 'utf8'), port, ip);
}

function decrypt(message) {
  const [iv, encrypted] = message.toString('utf8').split(".");
  const decrypted = crypto.createDecipheriv('des-cbc', Buffer.from(key), Buffer.from(iv, 'base64'));
  let d = decrypted.update(encrypted, 'base64', 'utf8');
  d += decrypted.final('utf8');
  return d;
}

function encodeDesCBC(textToEncode) {
  key = crypto.randomBytes(8);
  const iv = crypto.randomBytes(8);
  const cipher = crypto.createCipheriv('des-cbc', key, iv);
  let c = cipher.update(textToEncode, 'utf8', 'base64');
  c += cipher.final('base64');
  const rsaEncryptedKey = crypto.publicEncrypt(publicKey, key).toString('base64');
  return [c, iv.toString('base64'), rsaEncryptedKey];
}
