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
    browerVersion: one PatchLevel,
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
    osVersion: one PatchLevel,
    encryption: one EncryptionAlgorithm,
    inputValidation: one Boolean,
    validUserPacket: one Boolean
}

--Verification System Sig  ??

---------- Sub Components ----------

---Shared sub components

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

abstract sig PatchLevel {}
sig Critical extends PatchLevel {}
sig Moderate extends PatchLevel {}
sig Updated extends PatchLevel {}

sig PublicKey{}


sig Router extends Node {
}

sig SignedMessage {
    signatureVerifiedBy: one PublicKey  
}

sig Certificate extends SignedMessage{
    participantPublicKey: one PublicKey,
    participant: one Participant,
    expired: one Boolean
}


---EndPoint sub components---
abstract sig EncryptionAlgorithm {}
sig ThreeDES extends EncryptionAlgorithm {}
sig AES extends EncryptionAlgorithm {}
sig TwoFish extends EncryptionAlgorithm {}



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


pred MessageIntegrityHold[m: SignedMessage, participant: Participant, certificate: Certificate, ca: CertificateAuthority]{
    validCertificate[certificate, ca]
    certificate.participant = participant
    m.signatureVerifiedBy = certificate.participantPublicKey
}

pred validCertificate[certificate: Certificate, ca:CertificateAuthority]{
    not certificate in ca.revocationCertificates
    certificate.expired = False
    certificate.signatureVerifiedBy = ca.authorityPublicKey
}

-----3 levels of passwords------
pred unsafePassword[s : State] {
    s.user.password.length < 3 or
    (s.user.password.hasSpecChars = False and s.user.password.hasNumbers = False and s.user.password.hasUpperCase = False) or
    s.user.password.hasPattern = True
}

pred semisafePassword[s : State] {
    s.user.password.length = 3 
    --At least 2 of the following are true    (hasSpecChars, hasNumbers, hasUpperCase)
    (s.user.password.hasSpecChars = True and s.user.password.hasNumbers = True) or
    (s.user.password.hasSpecChars = True and s.user.password.hasUpperCase = True) or
    (s.user.password.hasNumbers = True and s.user.password.hasUpperCase = True)

}

pred safePassword[s : State] {
    s.user.password.length >= 4 
    s.user.password.hasSpecChars = True
    s.user.password.hasNumbers = True 
    s.user.password.hasUpperCase = True
    s.user.password.hasPattern = True
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

pred wellformedNetworkTopology[s: State] {
	-- The network topology should connect the user to the payment processor.
	reachable[s.endpoint, s.connection.peer, endpoints]

	all node: Node {
		reachable[node, s.connection.peer, endpoints] => {
			-- A node should never connect to itself.
			node not in node.endpoints
		}
	}
}

fun networkTopologyScore[s: State]: one Int {
	HTTP in s.connection.layer4Protocol => {
		#s.connection.peer.^endpoints
	} else 0
}

//User score evaluation 
--password cache is a minor danger since exploiting requires access to things outside of model
--and only helps an attack when mfa is disabled
fun userScore[p: Password, mfa: mfaEnabled, cache: passwordCache]: one Int {
    (unsafePassword[p] and mfa = Disabled) => 5 else
    (unsafePassword[p] and mfa = Enabled) => 4 else
    (semisafePassword[p] and mfa = Disabled and cache = Enabled) => 4 else
    (semisafePassword[p] and mfa = Enabled) => 3 else
    (safePassword[p] and mfa = Disabled and cache = Enabled) => 3 else
    (safePassword[p] and mfa = Disabled and cache = Disabled) => 2 else
    (safePassword[p] and mfa = Enabled and cache = Enabled) => 1 else
    (safePassword[p] and mfa = Enabled and cache = Disabled) => 0 
}

/*
Secure Total < 6, AND no single primary component is > 2
Medium
Critical

if any single primary component is 5 CRITICAL
*/







test expect {
  wellformed_sat: { some s: State | wellformedNetworkTopology[s] } is sat
}

//Traces
run {
    some s: State {
        unsafePassword[s] or 
        semisafePassword[s] or
        safePassword[s]
    }
     
 } for exactly 3 State --, exactly 1 User, exactly 1 Connection, exactly 1 EndPoint
   --for {next is linear}