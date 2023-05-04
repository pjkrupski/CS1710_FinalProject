#lang forge 
---------- Components ----------
--User, Connection, Endpoint

sig User {
    useractive: one Boolean,
    password: one Password,
    mfaEnabled: one Status,
    passwordCache: one Status
}


sig Connection { 
    connectionactive: one Boolean,
    browserVersion: one Evaluation,
    layer4Protocol: one TransportProtocol,
    networkPassword: one Password,
    wifiProtocol: one WifiProtocol,
	peer: one Node
}

abstract sig Node {
	endpoints: set Node
}



sig EndPoint extends Node {
    endpointactive: one Boolean,
    osVersion: one Evaluation,
    encryption: one EncryptionAlgorithm,
    inputValidation: one Boolean,
    validUserPacket: one Boolean,
    accessControl: one AccessControl,
    loggingAnalysis: one Boolean
}

--Verification System Sig  ??

---------- Sub Components ----------

---Shared sub components
abstract sig Evaluation {}
one sig Safe extends Evaluation {}
one sig Moderate extends Evaluation {}
one sig Critical extends Evaluation {}

abstract sig Boolean {}
one sig True extends Boolean {}
one sig False extends Boolean {}

abstract sig Status {}
one sig Enabled extends Status {}
one sig Disabled extends Status {}

sig Password {
    length: one Int,   --multiples of 5, 1 = (1-5) chars, 2 = (5-10) chars, 3 = (10-15), 4 = (15-MAX)
    hasSpecChars:  one Boolean,
    hasNumbers: one Boolean,
    hasUpperCase: one Boolean,
    hasPattern: one Boolean
}


---User sub components---


---Connection sub components---

abstract sig TransportProtocol {}
sig HTTP extends TransportProtocol {}
sig HTTPS extends TransportProtocol {}

abstract sig WifiProtocol {}
sig WEP extends WifiProtocol {}
sig WPA extends WifiProtocol {}
sig WPA2 extends WifiProtocol {}


sig PublicKey{}


sig Router extends Node {
}

sig SignedMessage {
    signatureVerifiedBy: one PublicKey  
}

sig Certificate extends SignedMessage {
    participantPublicKey: one PublicKey,
    participant: one Participant,
    expired: one Boolean
}


---EndPoint sub components---
abstract sig EncryptionAlgorithm {}
sig ThreeDES extends EncryptionAlgorithm {}
sig AES extends EncryptionAlgorithm {}
sig TwoFish extends EncryptionAlgorithm {}
sig Plain extends EncryptionAlgorithm {}

abstract sig AccessControl {
}
one sig PasswordBased extends AccessControl {}
one sig Multifactor extends AccessControl{}
one sig TokenBased extends AccessControl{}
one sig None extends AccessControl{}



---Other---

abstract sig Participant {}
sig CardHolder extends Participant{}
sig Issuer extends Participant{}
sig Merchant extends Participant {}
sig Acquirer extends Participant{}


// For now assume single authority, so no certificate chain
sig CertificateAuthority{
    authorityPublicKey: one PublicKey,
    revocationCertificates: set Certificate
}


---------- States ----------

abstract sig State {
    user : one User,
    connection : one Connection,
    endpoint : one EndPoint
}

one sig Initial extends State {}
one sig Active extends State {}
one sig End extends State {}
