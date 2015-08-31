/*
 * * A JavaScript implementation of the Secure Hash Algorithm, SHA-1, as defined
 * * in FIPS PUB 180-1
 * * Version 2.1a Copyright Paul Johnston 2000 - 2002.
 * * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * * Distributed under the BSD License
 * * See http://pajhome.org.uk/crypt/md5 for details.
 * */

/*
 * * Configurable variables. You may need to tweak these to be compatible with
 * * the server-side, but the defaults work in most cases.
 * */
var hexcase = 0; /* hex output format. 0 - lowercase; 1 - uppercase */
var b64pad = "="; /* base-64 pad character. "=" for strict RFC compliance */
var chrsz = 8; /* bits per input character. 8 - ASCII; 16 - Unicode */
var blocksize = 64;

/*
 * * These are the functions you'll usually want to call
 * * They take string arguments and return either hex or base-64 encoded strings
 * */
function hex_sha1(x,y){return binb2hex(hmac_sha1(x,y));}
function b64_sha1(x,y){return binb2b64(hmac_sha1(x,y));}
function b96_sha1(x,y){return binb2b96(hmac_sha1(x,y));}
function og_hex_sha1(s){return binb2hex(core_sha1(str2binb(s), s.length * chrsz));}
function og_b64_sha1(s){return binb2b64(core_sha1(str2binb(s), s.length * chrsz));}
function og_b96_sha1(s){return binb2b96(core_sha1(str2binb(s), s.length * chrsz));}

/*
 * * Calculate the SHA-1 of an array of big-endian words, and a bit length
 * */
function core_sha1(x, len)
{
    /* append padding */
    x[len >> 5] |= 0x80 << (24 - len % 32);
    x[((len + 64 >> 9) << 4) + 15] = len;

    var w = Array(80);
    var a = 1732584193;
    var b = -271733879;
    var c = -1732584194;
    var d = 271733878;
    var e = -1009589776;

    for(var i = 0; i < x.length; i += 16)
    {
        var olda = a;
        var oldb = b;
        var oldc = c;
        var oldd = d;
        var olde = e;

        for(var j = 0; j < 80; j++)
        {
            if(j < 16) w[j] = x[i + j];
            else w[j] = rol(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1);
            var t = safe_add(safe_add(rol(a, 5), sha1_ft(j, b, c, d)),
                    safe_add(safe_add(e, w[j]), sha1_kt(j)));
            e = d;
            d = c;
            c = rol(b, 30);
            b = a;
            a = t;
        }

        a = safe_add(a, olda);
        b = safe_add(b, oldb);
        c = safe_add(c, oldc);
        d = safe_add(d, oldd);
        e = safe_add(e, olde);
    }
    return Array(a, b, c, d, e);

}

/*
 * * Perform the appropriate triplet combination function for the current
 * * iteration
 * */
function sha1_ft(t, b, c, d)
{
    if(t < 20) return (b & c) | ((~b) & d);
    if(t < 40) return b ^ c ^ d;
    if(t < 60) return (b & c) | (b & d) | (c & d);
    return b ^ c ^ d;
}

/*
 * * Determine the appropriate additive constant for the current iteration
 * */
function sha1_kt(t)
{
    return (t < 20) ? 1518500249 : (t < 40) ? 1859775393 :
        (t < 60) ? -1894007588 : -899497514;
}

/*
 * * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * * to work around bugs in some JS interpreters.
 * */
function safe_add(x, y)
{
    var lsw = (x & 0xFFFF) + (y & 0xFFFF);
    var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
    return (msw << 16) | (lsw & 0xFFFF);
}

/*
 * * Bitwise rotate a 32-bit number to the left.
 * */
function rol(num, cnt)
{
    return (num << cnt) | (num >>> (32 - cnt));
}

/*
 * * Convert an 8-bit or 16-bit string to an array of big-endian words
 * * In 8-bit function, characters >255 have their hi-byte silently ignored.
 * */
function str2binb(str)
{
    var bin = Array();
    var mask = (1 << chrsz) - 1;
    for(var i = 0; i < str.length * chrsz; i += chrsz)
        bin[i>>5] |= (str.charCodeAt(i / chrsz) & mask) << (32 - chrsz - i%32);
    return bin;
}

/*
 * * Convert an array of big-endian words to a hex string.
 * */
function binb2hex(binarray)
{
    var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
    var str = "";
    for(var i = 0; i < binarray.length * 4; i++)
    {
        str += hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8+4)) & 0xF) +
            hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8 )) & 0xF);
    }
    return str;
}

/*
 * * Convert an array of big-endian words to a base-64 string
 * */
function binb2b64(binarray)
{
    var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var str = "";
    for(var i = 0; i < binarray.length * 4; i += 3)
    {
        var triplet = (((binarray[i >> 2] >> 8 * (3 - i %4)) & 0xFF) << 16)
            | (((binarray[i+1 >> 2] >> 8 * (3 - (i+1)%4)) & 0xFF) << 8 )
            | ((binarray[i+2 >> 2] >> 8 * (3 - (i+2)%4)) & 0xFF);
        for(var j = 0; j < 4; j++)
        {
            if(i * 8 + j * 6 > binarray.length * 32) str += b64pad;
            else str += tab.charAt((triplet >> 6*(3-j)) & 0x3F);
        }
    }
    return str;
}

function binb2b96(binarray)
{
    s = document.getElementById('message').value;
    s += document.getElementById('prefix').value;
    tab = make_st(core_sha1(str2binb(s),s.length * chrsz));
    var str = "";
    for(var i = 0; i < binarray.length * 4; i += 3)
    {
        var triplet = (((binarray[i >> 2] >> 8 * (3 - i %4)) & 0xFF) << 16)
            | (((binarray[i+1 >> 2] >> 8 * (3 - (i+1)%4)) & 0xFF) << 8 )
            | ((binarray[i+2 >> 2] >> 8 * (3 - (i+2)%4)) & 0xFF);
        for(var j = 0; j < 4; j++)
        {
            if(i * 8 + j * 6 > binarray.length * 32) str += b64pad;
            else str += tab.charAt((triplet >> 6*(3-j)) & 0x3F);
        }
    }
    return str;

}

function make_st(binarray) {
    var tab  = "!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\" +
               "]^_`abcdefghijklmnopqrstuvwxyz{|}~";
    var i = 0;
    while(tab.length > 64) {
        var triplet = (((binarray[i >> 2] >> 8 * (3 - i %4)) & 0xFF) << 16)
            | (((binarray[i+1 >> 2] >> 8 * (3 - (i+1)%4)) & 0xFF) << 8 )
            | ((binarray[i+2 >> 2] >> 8 * (3 - (i+2)%4)) & 0xFF);
        tab = tab.slice(0, (triplet % tab.length)) +
              tab.slice((triplet % tab.length) + 1, tab.length);
        i++;
    }
    return tab;
}

function limitlength(val) {
    var limit = document.getElementById("lenlimit").value;
    if(limit < 0) return val;
    return val.slice(0,limit);
}

function hmac_sha1(key, message) {
    if(key.length > blocksize) {
        key = binb2hex(core_sha1(key, key.length * chrsz));
    } else if (key.length < blocksize) {
        key = pad(key, (blocksize - key.length));
    }
    var o_key_pad = [];
    var i_key_pad = [];
    var o_pad = pad(0x5c, blocksize);
    var i_pad = pad(0x36, blocksize);

    for(i=0; i < key.length; i++) {
        o_key_pad.push(key.charCodeAt(i) ^ o_pad.charCodeAt(i))
    }
    o_key_pad = bina(o_key_pad);

    for(i=0; i < key.length; i++) {
        i_key_pad.push(key.charCodeAt(i) ^ i_pad.charCodeAt(i))
    }
    i_key_pad = bina(i_key_pad);
    var ipm = [];
    var opi = []; 

    message = pad(message, i_key_pad.length)
    for(i=0; i < message.length; i++) {
        ipm.push(message.charCodeAt(i) | i_key_pad.charCodeAt(i))
    }
    ipm = bina(ipm);
    
    var cs1im = binb2hex(core_sha1(ipm, ipm.length * chrsz));
    cs1im = pad(cs1im, o_key_pad.length)
    for(i=0; i < message.length; i++) {
        opi.push(cs1im.charCodeAt(i) | o_key_pad.charCodeAt(i))
    }
    opi = bina(opi);
    return core_sha1(opi, opi.length * chrsz);
}

function bina(binarray)
{
    var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
    var str = "";
    for(var i = 0; i < binarray.length * 4; i++)
    {
        str += hex_tab.charAt(binarray[i] % hex_tab.length); 
    }
    return str;
}

function pad(n, width, z) {
      z = z || '0';
        n = n + '';
          return n.length >= width ? n : new Array(width - n.length + 1).join(z) + n;
}

document.addEventListener('DOMContentLoaded', function() {
    var hash = document.getElementById('hashbutton');
    hash.addEventListener('click', function() {
        switch(document.getElementById("hashtype").value) {
        case "hashh":
            document.getElementById('hash').value =
            limitlength(hex_sha1(document.getElementById('prefix').value, 
                  document.getElementById('message').value));
            break;
        case "hashb64":
            document.getElementById('hash').value =
            limitlength(b64_sha1(document.getElementById('prefix').value, 
                  document.getElementById('message').value));
            break;
        case "hashb96":
            document.getElementById('hash').value =
            limitlength(b96_sha1(document.getElementById('prefix').value, 
                  document.getElementById('message').value));
            break;
        case "oghashh":
            document.getElementById('hash').value =
            limitlength(og_hex_sha1(document.getElementById('prefix').value + 
                  document.getElementById('message').value));
            break;
        case "oghashb64":
            document.getElementById('hash').value =
            limitlength(og_b64_sha1(document.getElementById('prefix').value + 
                  document.getElementById('message').value));
            break;
        case "oghashb96":
            document.getElementById('hash').value =
            limitlength(og_b96_sha1(document.getElementById('prefix').value + 
                  document.getElementById('message').value));
            break;
        }
    });
});
