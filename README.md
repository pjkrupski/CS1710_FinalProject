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
