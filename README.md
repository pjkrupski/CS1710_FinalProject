# Brainstorming

## Modeling a Credit Card Transaction

It sounds like we're interested in modeling information flow across the network as it facilitates a credit card transaction.
Typically, payment processors require some information in addition to the credit card number to complete a transaction.
Specifically:

- The card verification value (CVV)
- The name of the cardholder
- The phone number of the cardholder
- A billing address

This is typically one-and-done (a single HTTP request contains all of the above), but we could make the model more interesting by having a protocol in which the payment processor has to acknowledge a piece of information before the buyer sends anything else.
For example: sending the digits of the credit card number in chunks, and if the card number is valid (see: <https://en.wikipedia.org/wiki/Luhn_algorithm>), the payment processor requests the CVV, and so on.
This might lead to some interesting problems we can query about: if an eavesdropper gets part of the protocol, is it enough information to derive e.g., the rest of the credit card number?
(This has parallels to certain kinds of cryptographic gadgets that allow partial rewrites or partial information leakage against TLS.)

## Modeling Specific Attack Vectors

- Attacks on HTTP encryption
  - Partial information leakage via [POODLE](https://en.wikipedia.org/wiki/POODLE)
- Attacks on [authentication protocols](https://en.wikipedia.org/wiki/Authentication_protocol)
  - Ideally, you want to know who you're talking to before you send your credit card information :)

## Potential Vulnerabiliteis 

###User
- Account password length
- Uses multifactor authentication?
- Credentials Cached?

###Connection
- Web Brower up to date?
- Http or Https being used?
- Open network?
- Network password length
- Wifi protocol being used? 
- WEP, WPA, WPA2

###End point
- Webserver security up to date?
- Encrypts data at rest? 
- Validates input



References 
###Out of date browser
https://www.whatismybrowser.com/guides/how-to-update-your-browser/faq/what-happens-if-dont-update#:~:text=You%20will%20become%20vulnerable%20to%20security%20problems&text=Web%20browsers%20with%20unpatched%20security,your%20personal%20information%20being%20stolen.

###Webserver vulnerabilities 
https://www.getastra.com/blog/security-audit/web-server-security/

###Classifying vulnerabilities based on OSI
https://www.forcepoint.com/cyber-edu/osi-model#:~:text=The%20OSI%20Model%20(Open%20Systems,between%20different%20products%20and%20software.

