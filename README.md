# MD5HA1 Command Line Tool

Tool for computing WWW-Digest MD5 HA1 string.

License: MIT
Copyright: Daniel-Constantin Mierla (http://www.asipto.com)

MD5 Hashing Functions:

  * License: MIT
  * Copyright: Project Nayuki (http://www.nayuki.io/page/fast-md5-hash-implementation-in-x86-assembly)

## Overview

SIP digest authentication RFC 3261 is based on HTTP digest authentication RFC 2617 (aka WWW-Digest authentication). Digest authentication is not exchanging the password in clear text between client and server, but uses hashing function to compute a response.

When a SIP client sends a request that needs to be authenticatd (e.g., INVITE, REGISTER request) the server replies with a 401 or 407 unauthorized response, which includes a WWW-Authenticate or Proxy header, for example:

```
WWW-Authenticate: Digest algorithm=MD5, realm=”myrealm.org”, nonce="8e4a6b9f"
```

The client computes the attributes of WWW-Digest authentication and resends the request, now including an "Authorization" or "Proxy-Authorization" header:

```
Authorization: Digest username="myusername", realm=”myrealm.org", nonce="8e4a6b9f", uri="sip:sip.example.com",response="8a224edee7aa9f9b0bea68f50f2288fe", algorithm=MD5
```

The response is computed like:

```
HA1 = MD5("myusername:myrealm.org:password”)
HA2 = MD5("REGISTER:sip:sip.example.com")
response = MD5(HA1+":8e4a6b9f:"+HA2);
```

Many SIP server applications can do WWW-Digest authentication starting from HA1 value for each user. The realm is typically the domain of the SIP server, therefore the combination of username, realm and password ensures the HA1 value is the same, no matter what kind of SIP request and what destination is in SIP traffic. Only when the password is changed, the HA1 has to be updated.

Storing on the server the HA1 in the user profile instead of the clear text password is recommended, because it provides better privacy. However, if an attacker gets access to HA1 value, it can use a forged SIP application to authenticate to the server (very easy to achieve as there are many open source SIP clients). Therefore, if the user profile was compromised, not matter the password was stored in clear text or HA1 format, the password must be changed.

One of the goals for this tool is to ease the generation of HA1 value, mainly with the scope of providing the afferent C code, because the HA1 can be computed in command line with:

```
echo -n "username:realm:password" | md5sum

# or

echo -n "username:realm:password" | md5
```

Another scope it to help evaluating the strength of existing HA1 values. Useful for SIP services that didn't enforce rules to strengthen the passwords when the SIP accounts were created. The HA1 has the same length (32) no matter the length of the clear text password.

Out there are many pentesting (penetration testing) tools for SIP, but they require more resources, like network communication, SIP parsing, etc.

MD5HA1 tool can be used by VoIP admins that have access to user profiles to test the strength of the password stored in HA1 format.

## Install

No external libraries are required. Clone the source code and run 'make' in the project directory. A binary tool named 'md5ha1' should be generated.

## Usage

### Generate HA1

Compute and display the HA1 for a given combination username, realm and password.

```
md5ha1 -c username realm password
```

### Decode HA1

Attempt to match a clear text password for a given combination username, realm and ha1.

Note that, because MD5 is hashing and that means collisions can happen, the discovered password can be different than the actual password set by the user, still, it can be used for authentication.


```
md5ha1 -d [options] username realm ha1
```

The options can be:

  * -t: print execution time at the end
  * -m number: the minimum length of the password to try
  * -M number: the maximum length of the password to try
  * -c name: the characters set name, can be:
    * 'num' - only digits
    * 'hex' - only hex digits
    * 'alpha' - alphabetic characters
    * 'alphanum' - alphanumeric characters
    * 'full' - ascii printable characters
    * file-name - if none above matches, the name is tried to be opened as a text file and load its content as a characters set

For example, testing if the HA1 of user 'alice' with realm 'wonderland.com' is using a 3-digit password (e.g., well known passwords like 101), with printing the execution time:

```
md5ha1 -d -t -m 3 -M 3 -c num alice wonderland.com 35674a0b10d747d9cdb47e0b849aa5e0
```

## Remarks

The tool is still work in progress: lots of planned features not implemented; debug messages, output format, etc. may change.

The first target was to detect short/weak passwords, therefore there is no parallel processing. It can be added in the future.

Even if you test with this tool, it is highly recommended to have active and strong protection of your server for SIP flooding or dictionary attacks. If you run Kamailio, see:

  * http://kb.asipto.com/kamailio:usage:k31-sip-scanning-attack
  * http://www.kamailio.org/wiki/tutorials/security/kamailio-security
  * http://www.kamailio.org/events/2015-KamailioWorld/Day2/26-Daniel-Constantin.Mierla-Kamailio-The-Safety-Of-VoIP-Platforms.pdf

IMPORTANT: use this tool at your own risk, no liability for the developers or copyright holders.
