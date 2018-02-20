var crypto = require("crypto");

var key = 'opbatch123456789';
var input = 'HKOO';
var iv = new Buffer(16);
iv[0] = 0x9d;
iv[1] = 0x30;
iv[2] = 0x5c;
iv[3] = 0x8a;
iv[4] = 0x86;
iv[5] = 0x3c;
iv[6] = 0x10;
iv[7] = 0x90;
iv[8] = 0x94;
iv[9] = 0xd4;
iv[10] = 0xb5;
iv[11] = 0x77;
iv[12] = 0xa1;
iv[13] = 0x57;
iv[14] = 0xb0;
iv[15] = 0x02;
var cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
var cipheredOutput = cipher.update(input, 'utf8');
cipheredOutput += cipher.final('base64');

console.log('ciphered output : ', cipheredOutput);

var decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
var decipheredOutput = decipher.update(cipheredOutput, 'base64');
decipheredOutput += decipher.final('utf8');

console.log('deciphered output : ', decipheredOutput);

