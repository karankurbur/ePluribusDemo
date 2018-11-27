/**
 * New script file
 */

/**
 * 
 * @param {org.example.empty.SendDataToVerifier} data
 * @transaction
 */

async function sendDataToVerifier(data) {
    console.log(data);

    var ns = 'org.example.empty';
    var me = getCurrentParticipant();
    const registery = await getAssetRegistry(ns + '.UnverifiedCredential');
    var factory = getFactory();
    var asset = factory.newResource('org.example.empty', 'UnverifiedCredential', uuid());
    // asset.credId = uuid();
    asset.dataURL = data.dataURL;
    asset.verifier = data.verifier;
    asset.sender = me.username;
    return registery.add(asset);
}

/**
 * //check if hash is already in credential list

 * @param {org.example.empty.VerifierValidate} data
 * @transaction
 */
async function VerifierValidate(data) {
    // if (data.verified) {
    var factory = getFactory();
    var ns = 'org.example.empty';
    var me = getCurrentParticipant();
    const registery = await getAssetRegistry(ns + '.UnverifiedCredential');
    const veriferData = await registery.get(data.credId);
    //console.log(veriferData);


    const credentialRegistery = await getAssetRegistry(ns + '.CredentialForEndUserLocal');
    const keyRegistery = await getAssetRegistry(ns + '.Key');
    const allKeys = await keyRegistery.getAll();
    const didRegistery = await getAssetRegistry(ns + '.Did');
    const dids = await didRegistery.getAll();




    var tempKey;
    var publicKeyReference;
    for (var i = 0; i < allKeys.length; i++) {
        if (allKeys[i].public === false) {
            tempKey = allKeys[i];
        } else {
            publicKeyReference = allKeys[i];
        }
    }

    var did;
    for (var i = 0; i < dids.length; i++) {
        if (dids[i].publicKey.keyId == publicKeyReference.keyId) {
            did = dids[i];
        }
    }

    //console.log(did);
    //console.log(tempKey);

    var privateKey = await window.crypto.subtle.importKey(
        "jwk", //can be "jwk" (public or private), "spki" (public only), or "pkcs8" (private only)
        {   //this is an example jwk key, other key types are Uint8Array objects
            kty: "EC",
            crv: "P-256",
            x: tempKey.x,
            y: tempKey.y,
            d: tempKey.d,
            ext: true,
        },
        {   //these are the algorithm options
            name: "ECDSA",
            namedCurve: "P-256", //can be "P-256", "P-384", or "P-521"
        },
        true, //whether the key is extractable (i.e. can be used in exportKey)
        ["sign"] //"verify" for public key import, "sign" for private key imports
    );

    var publicKey = await window.crypto.subtle.importKey(
        "jwk", //can be "jwk" (public or private), "spki" (public only), or "pkcs8" (private only)
        {   //this is an example jwk key, other key types are Uint8Array objects
            kty: "EC",
            crv: "P-256",
            x: tempKey.x,
            y: tempKey.y,
            ext: true,
        },
        {   //these are the algorithm options
            name: "ECDSA",
            namedCurve: "P-256", //can be "P-256", "P-384", or "P-521"
        },
        true, //whether the key is extractable (i.e. can be used in exportKey)
        ["verify"] //"verify" for public key import, "sign" for private key imports
    );
    var signedAttestation = await window.crypto.subtle.sign(
        {
            name: "ECDSA",
            hash: { name: "SHA-256" }, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
        },
        privateKey, //from generateKey or importKey above
        utf8AbFromStr(data.attestation) //ArrayBuffer of data you want to sign
    );
    var asset = factory.newResource('org.example.empty', 'CredentialForEndUserLocal', uuid());
    asset.attestation = data.attestation;
    var uint8View = new Uint8Array(signedAttestation);
    console.log(uint8View);
    var sig = [];
    for (var i = 0; i < uint8View.length; i++) {
        sig.push(uint8View[i]);
    }
    asset.signatureArray = sig;
    asset.verifierDid = did; //find did that matches verifier publickey
    asset.owner = veriferData.sender;
    console.log(asset);
    // var verified = await window.crypto.subtle.verify(
    //     {
    //         name: "ECDSA",
    //         hash: { name: "SHA-256" }, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
    //     },
    //     publicKey, //from generateKey or importKey above
    //     new Uint8Array(sig), //ArrayBuffer of the signature
    //     utf8AbFromStr(data.attestation) //ArrayBuffer of the data
    // )
    // console.log("Signature is correct " + verified);
    await credentialRegistery.add(asset);
    // }
}

/**
 * //check if hash is already in credential list

 * @param {org.example.empty.CreatekeyPair} data
 * @transaction
 */
async function CreatekeyPair() {
    var ns = 'org.example.empty';
    var me = getCurrentParticipant();
    console.log(me);
    var factory = getFactory();

    var keys = await window.crypto.subtle.generateKey(
        {
            name: "ECDSA",
            namedCurve: "P-256", //can be "P-256", "P-384", or "P-521"
        },
        true, //whether the key is extractable (i.e. can be used in exportKey)
        ["sign", "verify"] //can be any combination of "sign" and "verify"
    );
    //console.log(keys);

    var public = await window.crypto.subtle.exportKey(
        "jwk", //can be "jwk" (public or private), "spki" (public only), or "pkcs8" (private only)
        keys.publicKey //can be a publicKey or privateKey, as long as extractable was true
    );

    var private = await window.crypto.subtle.exportKey(
        "jwk", //can be "jwk" (public or private), "spki" (public only), or "pkcs8" (private only)
        keys.privateKey //can be a publicKey or privateKey, as long as extractable was true
    );

    console.log(me.$type);


    const keyRegistery = await getAssetRegistry(ns + '.Key');
    const didRegistery = await getAssetRegistry(ns + '.Did');

    var newPublicKey = factory.newResource('org.example.empty', 'Key', uuid());
    var newPrivateKey = factory.newResource('org.example.empty', 'Key', uuid());
    var newDid = factory.newResource('org.example.empty', 'Did', did());



    newPublicKey.x = public.x;
    newPublicKey.y = public.y;
    newPublicKey.public = true;
    newPublicKey.owner = me.username;

    newDid.publicKey = newPublicKey;
    newDid.organization = me.username;
    if (me.$type == 'Verifier') {
        newDid.trusted = true;
    } else {
        newDid.trusted = false;
    }


    newPrivateKey.x = public.x;
    newPrivateKey.y = public.y;
    newPrivateKey.d = private.d;
    newPrivateKey.public = false;
    newPrivateKey.owner = me.username;


    console.log(newDid);
    await didRegistery.add(newDid);
    await keyRegistery.add(newPrivateKey);
    await keyRegistery.add(newPublicKey);


}




/**
 * //check if hash is already in credential list

 * @param {org.example.empty.SendCredentialToServiceProvider} data
 * @transaction
 */
async function SendCredentialToServiceProvider(data) {
    var factory = getFactory();
    var ns = 'org.example.empty';
    var me = getCurrentParticipant();



    const credentialRegistery = await getAssetRegistry(ns + '.CredentialForEndUserLocal');
    const credToShare = await credentialRegistery.get(data.credId);
    console.log(credToShare);


    const keyRegistery = await getAssetRegistry(ns + '.Key');
    const allKeys = await keyRegistery.getAll();
    const didRegistery = await getAssetRegistry(ns + '.Did');
    const dids = await didRegistery.getAll();


    var tempKey;
    var publicKeyReference;
    for (var i = 0; i < allKeys.length; i++) {
        if (allKeys[i].public === false) {
            tempKey = allKeys[i];
        } else {
            publicKeyReference = allKeys[i];
        }
    }

    var did; //sender did
    for (var i = 0; i < dids.length; i++) {
        if (dids[i].publicKey.keyId == publicKeyReference.keyId) {
            did = dids[i];
        }
    }
    
    var privateKey = await window.crypto.subtle.importKey(
        "jwk", //can be "jwk" (public or private), "spki" (public only), or "pkcs8" (private only)
        {   //this is an example jwk key, other key types are Uint8Array objects
            kty: "EC",
            crv: "P-256",
            x: tempKey.x,
            y: tempKey.y,
            d: tempKey.d,
            ext: true,
        },
        {   //these are the algorithm options
            name: "ECDSA",
            namedCurve: "P-256", //can be "P-256", "P-384", or "P-521"
        },
        true, //whether the key is extractable (i.e. can be used in exportKey)
        ["sign"] //"verify" for public key import, "sign" for private key imports
    );

    var signedAttestation = await window.crypto.subtle.sign(
        {
            name: "ECDSA",
            hash: { name: "SHA-256" }, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
        },
        privateKey, //from generateKey or importKey above
        utf8AbFromStr(credToShare.attestation) //ArrayBuffer of data you want to sign
    );


    var asset = factory.newResource('org.example.empty', 'CredentialForServiceProvider', uuid());
    asset.attestation = credToShare.attestation;
    var uint8View = new Uint8Array(signedAttestation);
    console.log(uint8View);
    var sig = [];
    for (var i = 0; i < uint8View.length; i++) {
        sig.push(uint8View[i]);
    }
    asset.senderSignature = sig;
    asset.senderDid = did; //find did that matches verifier publickey
    asset.owner = data.serviceProvider;
    asset.verifierSignature = credToShare.signatureArray;
    asset.verifierDid = credToShare.verifierDid;
    
    console.log(asset);

    const serviceProviderCredentialRegistery = await getAssetRegistry(ns + '.CredentialForServiceProvider');
    serviceProviderCredentialRegistery.add(asset);



}





function utf8AbFromStr(str) {
    var strUtf8 = unescape(encodeURIComponent(str));
    var ab = new Uint8Array(strUtf8.length);
    for (var i = 0; i < strUtf8.length; i++) {
        ab[i] = strUtf8.charCodeAt(i);
    }
    return ab;
}

function strFromUtf8Ab(ab) {
    return decodeURIComponent(escape(String.fromCharCode.apply(null, ab)));
}


function uuid() {
    const s4 = () => Math.floor((1 + Math.random()) * 0x10000).toString(16).substring(1)
    return `${s4()}`
}
function did() {
    const s4 = () => Math.floor((1 + Math.random()) * 0x10000).toString(16).substring(1)
    return `${s4()}${s4()}`
}

var MD5 = function (d) { result = M(V(Y(X(d), 8 * d.length))); return result.toLowerCase() }; function M(d) { for (var _, m = "0123456789ABCDEF", f = "", r = 0; r < d.length; r++)_ = d.charCodeAt(r), f += m.charAt(_ >>> 4 & 15) + m.charAt(15 & _); return f } function X(d) { for (var _ = Array(d.length >> 2), m = 0; m < _.length; m++)_[m] = 0; for (m = 0; m < 8 * d.length; m += 8)_[m >> 5] |= (255 & d.charCodeAt(m / 8)) << m % 32; return _ } function V(d) { for (var _ = "", m = 0; m < 32 * d.length; m += 8)_ += String.fromCharCode(d[m >> 5] >>> m % 32 & 255); return _ } function Y(d, _) { d[_ >> 5] |= 128 << _ % 32, d[14 + (_ + 64 >>> 9 << 4)] = _; for (var m = 1732584193, f = -271733879, r = -1732584194, i = 271733878, n = 0; n < d.length; n += 16) { var h = m, t = f, g = r, e = i; f = md5_ii(f = md5_ii(f = md5_ii(f = md5_ii(f = md5_hh(f = md5_hh(f = md5_hh(f = md5_hh(f = md5_gg(f = md5_gg(f = md5_gg(f = md5_gg(f = md5_ff(f = md5_ff(f = md5_ff(f = md5_ff(f, r = md5_ff(r, i = md5_ff(i, m = md5_ff(m, f, r, i, d[n + 0], 7, -680876936), f, r, d[n + 1], 12, -389564586), m, f, d[n + 2], 17, 606105819), i, m, d[n + 3], 22, -1044525330), r = md5_ff(r, i = md5_ff(i, m = md5_ff(m, f, r, i, d[n + 4], 7, -176418897), f, r, d[n + 5], 12, 1200080426), m, f, d[n + 6], 17, -1473231341), i, m, d[n + 7], 22, -45705983), r = md5_ff(r, i = md5_ff(i, m = md5_ff(m, f, r, i, d[n + 8], 7, 1770035416), f, r, d[n + 9], 12, -1958414417), m, f, d[n + 10], 17, -42063), i, m, d[n + 11], 22, -1990404162), r = md5_ff(r, i = md5_ff(i, m = md5_ff(m, f, r, i, d[n + 12], 7, 1804603682), f, r, d[n + 13], 12, -40341101), m, f, d[n + 14], 17, -1502002290), i, m, d[n + 15], 22, 1236535329), r = md5_gg(r, i = md5_gg(i, m = md5_gg(m, f, r, i, d[n + 1], 5, -165796510), f, r, d[n + 6], 9, -1069501632), m, f, d[n + 11], 14, 643717713), i, m, d[n + 0], 20, -373897302), r = md5_gg(r, i = md5_gg(i, m = md5_gg(m, f, r, i, d[n + 5], 5, -701558691), f, r, d[n + 10], 9, 38016083), m, f, d[n + 15], 14, -660478335), i, m, d[n + 4], 20, -405537848), r = md5_gg(r, i = md5_gg(i, m = md5_gg(m, f, r, i, d[n + 9], 5, 568446438), f, r, d[n + 14], 9, -1019803690), m, f, d[n + 3], 14, -187363961), i, m, d[n + 8], 20, 1163531501), r = md5_gg(r, i = md5_gg(i, m = md5_gg(m, f, r, i, d[n + 13], 5, -1444681467), f, r, d[n + 2], 9, -51403784), m, f, d[n + 7], 14, 1735328473), i, m, d[n + 12], 20, -1926607734), r = md5_hh(r, i = md5_hh(i, m = md5_hh(m, f, r, i, d[n + 5], 4, -378558), f, r, d[n + 8], 11, -2022574463), m, f, d[n + 11], 16, 1839030562), i, m, d[n + 14], 23, -35309556), r = md5_hh(r, i = md5_hh(i, m = md5_hh(m, f, r, i, d[n + 1], 4, -1530992060), f, r, d[n + 4], 11, 1272893353), m, f, d[n + 7], 16, -155497632), i, m, d[n + 10], 23, -1094730640), r = md5_hh(r, i = md5_hh(i, m = md5_hh(m, f, r, i, d[n + 13], 4, 681279174), f, r, d[n + 0], 11, -358537222), m, f, d[n + 3], 16, -722521979), i, m, d[n + 6], 23, 76029189), r = md5_hh(r, i = md5_hh(i, m = md5_hh(m, f, r, i, d[n + 9], 4, -640364487), f, r, d[n + 12], 11, -421815835), m, f, d[n + 15], 16, 530742520), i, m, d[n + 2], 23, -995338651), r = md5_ii(r, i = md5_ii(i, m = md5_ii(m, f, r, i, d[n + 0], 6, -198630844), f, r, d[n + 7], 10, 1126891415), m, f, d[n + 14], 15, -1416354905), i, m, d[n + 5], 21, -57434055), r = md5_ii(r, i = md5_ii(i, m = md5_ii(m, f, r, i, d[n + 12], 6, 1700485571), f, r, d[n + 3], 10, -1894986606), m, f, d[n + 10], 15, -1051523), i, m, d[n + 1], 21, -2054922799), r = md5_ii(r, i = md5_ii(i, m = md5_ii(m, f, r, i, d[n + 8], 6, 1873313359), f, r, d[n + 15], 10, -30611744), m, f, d[n + 6], 15, -1560198380), i, m, d[n + 13], 21, 1309151649), r = md5_ii(r, i = md5_ii(i, m = md5_ii(m, f, r, i, d[n + 4], 6, -145523070), f, r, d[n + 11], 10, -1120210379), m, f, d[n + 2], 15, 718787259), i, m, d[n + 9], 21, -343485551), m = safe_add(m, h), f = safe_add(f, t), r = safe_add(r, g), i = safe_add(i, e) } return Array(m, f, r, i) } function md5_cmn(d, _, m, f, r, i) { return safe_add(bit_rol(safe_add(safe_add(_, d), safe_add(f, i)), r), m) } function md5_ff(d, _, m, f, r, i, n) { return md5_cmn(_ & m | ~_ & f, d, _, r, i, n) } function md5_gg(d, _, m, f, r, i, n) { return md5_cmn(_ & f | m & ~f, d, _, r, i, n) } function md5_hh(d, _, m, f, r, i, n) { return md5_cmn(_ ^ m ^ f, d, _, r, i, n) } function md5_ii(d, _, m, f, r, i, n) { return md5_cmn(m ^ (_ | ~f), d, _, r, i, n) } function safe_add(d, _) { var m = (65535 & d) + (65535 & _); return (d >> 16) + (_ >> 16) + (m >> 16) << 16 | 65535 & m } function bit_rol(d, _) { return d << _ | d >>> 32 - _ }
