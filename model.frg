#lang forge 

---------- Components ----------
--User, Connection, Endpoint

sig User {
    --active
    password: one Password
    --mfa Enabled or Disabled
    --password_cache Enabled or Disabled
}

sig Password {
    length: one Int,   --multiples of 5, 1 = (1-5) chars, 2 = (5-10) chars, 3 = (10-15), 4 = (15-MAX)
    hasSpecChars:  one Boolean,
    hasNumbers: one Boolean,
    hasUpperCase: one Boolean,
    hasPattern: one Boolean
}

abstract sig Protocol {}
sig HTTP extends Protocol {}
sig HTTPS extends Protocol {}

sig Connection {
    --active
    --browerVersion
    layer4Protocol: one Protocol,
    --networkPassword
    --wifiProtocol
	peer: one Node
}

abstract sig Node {
	endpoints: set Node
}

sig Router extends Node {
}

sig EndPoint extends Node {
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
    participantPublicKey: one PublicKey,
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
    authorityPublicKey: one PublicKey,
    revocationCertificates: set certificate
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

test expect {
  wellformed_sat: { some s: State | wellformedNetworkTopology[s] } is sat
}
