# Fernet2 and PWFernet Spec Sheet

This document describes version 0x81 (Fernet2) and 0x82 (PWFernet) of the fernet format.

Same as with Fernet:

- All encryption in this version is done with AES 128 in CBC mode.
- All base 64 encoding is done with the "URL and Filename Safe" variant, defined in RFC 4648 as "base64url".

###Install

To use functions in this cryptohw3 libaray, first download the git and include in your directory.

##Fernet2 

Fernet2 is based off of the python crypto Fernet implementation but handles associated data for use of tamper detection. Fernet2 takes the users message (arbitrary length of bytes), a key (16 bytes), and the associated data (arbitrary length of bytes) to produce the token or ciphertext that can be retreived by decrypting with the associated data. 

Another diffence is that upon initialization, the key used to genereate Fernet2 is HMACed and split into siging and encryption keys. 


###Useage of Fernet2
 
```python
from fernet import Fernet2
import os

key = os.urandom(32)
f = Fernet2(key)
msg = "spring break is coming!!!"
associated_data = "have funnnn"
ctx = f.encrypt(msg, associated_data)
txt = f.decrypt(token=ctx, adata=associated_data)
```

##PWFernet

PWFernet is a password based Fernet class but is passed in a user chosen password instead of a key. PWFernet takes the users message (arbitrary length of bytes), a password (arbitrary length of bytes),  and the associated data (arbitrary length of bytes) to produce the token or ciphertext that can be retreived by decrypting with the associated data. The password is used to genereate a key to allow for added level of security (since the key management is all internal).

###Useage of Fernet2
 
```python
from fernet import PWFernet
import os

password = "beach"
f = PWFernet(password, backend=default_backend())
adata = "have funnnn"
tk = f.encrypt("spring break is coming!!!", adata)
txt = f.decrypt(token=tk, adata = adata)
```

<!--Inspired by [link](http://tomdoc.org),-->
<!-- **bold** -->
<!-- *italics* —-->

<!--code: ```css-->
<!--a.button.star{-->
<!--  ...-->
<!--}-->
<!--a.button.star.stars-given{-->
<!--  ...-->
<!--}-->
<!--a.button.star.disabled{-->
<!--  ...-->
<!--}-->
<!--```-->


<!--1. Buttons-->
<!--  1.1 Form Buttons-->
<!--    1.1.1 Generic form button-->
<!--    1.1.2 Special form button-->
<!--  1.2 Social buttons-->
<!--  1.3 Miscelaneous buttons-->



