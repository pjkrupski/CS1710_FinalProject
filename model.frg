#lang forge 

---------- Components ----------
--User, Connection, Endpoint

sig User {
    --active
    password: one Password
    --mfa Enabled or Disabled
    --password_cache Enabled or Disabled
}

sig Connection {
    --active
    --browerVersion
    --layer4Protocol
    --networkPassword
    --wifiProtocol
    --Number of network hops
     --Helper
    --
}

sig EndPoint {
    --active
    --osVersion
    --encrypted
    --inputValidation
    --Verifying the user packet tag T/F
}

--Verification System Sig  ??

---------- Sub Components ----------
--User, Connection, Endpoint

abstract sig Boolean {}
one sig True extends Boolean {}
one sig False extends Boolean {}

sig Password {
    length: one Int,   --multiples of 5, 1 = (1-5) chars, 2 = (5-10) chars, 3 = (10-15), 4 = (15-MAX)
    hasSpecChars:  one Boolean,
    hasNumbers: one Boolean,
    hasUpperCase: one Boolean,
    hasPattern: one Boolean
}

sig PublicKey{}

sig SignedMessage {
    signatureVerifiedBy: one PublicKey  
}

sig Certificate extends SignedMessage{
    pk: one PublicKey,
    participant: one Participant,
    expired: one Boolean,
}

abstract sig Participant {}
sig CardHolder extends Participant{}
sig Issuer extends Participant{}
sig Merchant extends Participant {}
sig Acquirer extends Participant{}


// For now assume single authority, so no certificate chain
sig CertificateAuthority{
    pk: one PublicKey,
    revocationCertificates: set certificate
}

pred MessageIntegrityHold[m: SignedMessage, participant: Participant, certificate: Certificate, ca: CertificateAuthority]{
    validCertificate[certificate, ca]
    certificate.participant = participant
    m.signatureVerifiedBy = certificate.pk
}

pred validCertificate[certificate: Certificate, ca:CertificateAuthority]{
    not certificate in ca.revocationCertificates
    certificate.expired = False
    certificate.signatureVerifiedBy = ca.pk
}




---------- States ----------

abstract sig State {
    user : one User,
    connection : one connection,
    endpoint : one EndPoint
}

one sig Initial extends State {}
one sig Active extends State {}
one sig End extends State {}

pred InitialToActive {
   
}

pred ActiveToEnd {
  
}

pred EndToInitial {
    
}



---------- Checks ----------

pred safeUser[s : State] {
 
}

pred safeConnection[s : State] {
 
}

pred safeEndPoint[s : State] {
 
}

-----3 levels of passwords------
pred unsafePassword[s : State] {
    s.user.password.length < 3 or

}

pred semisafePassword[s : State] {
    s.user.password 
}

pred safePassword[s : State] {
    s.user.password 
}

test expect {

}

------- Predicates -------

--Ensure security score reaches a certain threshold
pred safeSystem {
    
}

--Ensure user has not stayed logged in past a certain time
pred idolUser {
    
}

--Ensure connection hasn't remained open past a certain time
pred idolConnection {
    
}

--Ensure server hasn't been had card info loaded past a certain time
pred idolEndpoint {
    
}

test expect {
  
}
