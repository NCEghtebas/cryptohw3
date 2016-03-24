# Fernet2 and PWFernet Spec Sheet

To use functions in this cryptohw libaray, first download the git and include in your directory.

##Fernet2 

Fernet2 is based off of the python crypto Fernet implementation. Fernet2 handles associated data for use of tamper detection. Upon initialization, the key used to genereate Fernet2 is HMACed and split into siging and encryption keys. 

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

PWFernet 

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
    <!--2. Form elements-->
    <!--  2.1 Text fields-->
    <!--  2.2 Radio and checkboxes-->
    <!--3. Text styling-->
    <!--4. Tables-->
    <!--  4.1 Number tables-->
    <!--  4.2 Diagram tables-->


