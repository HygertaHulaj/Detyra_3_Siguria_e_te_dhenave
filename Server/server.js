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
