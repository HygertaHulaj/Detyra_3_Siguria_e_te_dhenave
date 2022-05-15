const server = require('dgram').createSocket('udp4');
const fs = require('fs');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const convert = require('xml-js');
const jwt = require('jsonwebtoken');
const privateKey = fs.readFileSync('private.key');

server.bind(3000);

server.on('listening', () => {
  const address = server.address();
  console.log(`server listening ${address.address}:${address.port}`);
});

server.on('error', (err) => {
  console.log(`server error:\n${err.stack}`);
  server.close();
});

server.on('message', (msg, rinfo) => {
  const [message, key, iv] = decrypt(msg);
  let info = JSON.parse(message);
  switch(info.request) {
    case 'register': createUser(info, rinfo, key, iv);
    break;
    case 'login': authenticate(info, rinfo, key, iv);
    break;
    default: sendEncrypted({type: 'err', info: 'ERROR'}, rinfo.port, rinfo.address, key, iv);
    break;
  }
});

function createUser(user, rinfo, key, iv) {
  delete user.request;

  let xmlDb = fs.readFileSync('database.xml', (err, data) => {
    if (err) console.log(err.stack);
  }).toString();

  const options = {compact: true, ignoreComment: true, spaces: 2};
  let jsonDb = convert.xml2js(xmlDb, options);
  const users = toArray(jsonDb.db.user);
  const usernames = users.map(u => u.username._text);

  for (let i = 0; i < usernames.length; i++) {
    if (usernames[i] == user.username) {
      sendEncrypted({type: 'register_err', info: 'USERNAME ALREADY EXISTS'}, rinfo.port, rinfo.address, key, iv);
      return;
    }
  }
  
  users.push(user);
  jsonDb.db.user = users;
  xmlDb = convert.js2xml(jsonDb, options);

  fs.writeFileSync("database.xml", xmlDb, (err) => {
    if (err) {
      sendEncrypted({type: 'register_err', info: 'ERROR IN USER CREATION'}, rinfo.port, rinfo.address, key, iv);
      return;
    }
  });

  sendEncrypted({type: 'register_ok', info: 'USER CREATED'}, rinfo.port, rinfo.address, key, iv);
}

function authenticate(user, rinfo, key, iv) {
  const xmlDb = fs.readFileSync('database.xml', (err, data) => {
    if (err) console.log(err.stack);
  }).toString();

  const options = {compact: true, ignoreComment: true, spaces: 2};
  const jsonDb = convert.xml2js(xmlDb, options);

  const users = toArray(jsonDb.db.user);
  const usernames = users.map(u => u.username._text);
  const passwords = users.map(u => u.password._text);

  for (let i = 0; i < usernames.length; i++) {
    if (usernames[i] == user.username) {
      bcrypt.compare(user.password, passwords[i], function(err, res) {
        if (res) {
          delete users[i].password;
          const token = jwt.sign(flattenTextNodes(users[i]), privateKey, {algorithm: 'RS256'});
          sendEncrypted({type: 'login_ok', info: token }, rinfo.port, rinfo.address, key, iv);
        }
        else {
          sendEncrypted({type: 'login_err', info: 'WRONG USERNAME OR PASSWORD'}, rinfo.port, rinfo.address, key, iv);
        }
      });
      return;
    }
  }

  sendEncrypted({type: 'login_err', info: 'WRONG USERNAME OR PASSWORD'}, rinfo.port, rinfo.address, key, iv);
}

function toArray(arg) {
  if (Array.isArray(arg)) {
    return arg
  } else if (typeof arg !== 'undefined') {
    return [arg]
  } else {
    return []
  }
}

function sendEncrypted(message, port, ip, key, iv) {
  const cipher = encodeDesCBC(JSON.stringify(message), key, iv);
  server.send(Buffer.from(iv.toString('base64') + "." + cipher, 'utf8'), port, ip);
}

function decrypt(message) {
  const msgArr = message.toString('utf8').split(".");
  const iv = Buffer.from(msgArr[0], 'base64');
  const rsaEncryptedKey = Buffer.from(msgArr[1], 'base64');
  const encrypted = Buffer.from(msgArr[2], 'base64');
  const desKey = crypto.privateDecrypt(privateKey.toString(), rsaEncryptedKey);
  const decrypted = crypto.createDecipheriv('des-cbc', desKey, iv);
  let d = decrypted.update(encrypted, 'base64', 'utf8');
  d += decrypted.final('utf8');
  return [d, desKey, iv];
}

function encodeDesCBC(textToEncode, key, iv) {
  var cipher = crypto.createCipheriv('des-cbc', key, iv);
  var c = cipher.update(textToEncode, 'utf8', 'base64');
  c += cipher.final('base64');
  return c;
}

function flattenTextNodes(data) {
  if (typeof data === 'object' && !Array.isArray(data)) {
    const keys = Object.keys(data)
    if (keys.length === 1 && '_text' in data) {
      return data._text
    } else {
      return keys.reduce((acc, key) => {
        acc[key] = flattenTextNodes(data[key])
        return acc
      }, {})
    }
  } else {
    return data;
  }
}
