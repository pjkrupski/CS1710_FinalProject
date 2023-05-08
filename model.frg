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
    browserVersion: one PatchLevel,
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

abstract sig PatchLevel {
}
sig Critical extends PatchLevel {}
sig Moderate extends PatchLevel {}
sig Updated extends PatchLevel {}

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
abstract sig EncryptionAlgorithm {
}
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


abstract sig AccessControl {
}
one sig PasswordBased extends AccessControl {}
one sig Multifactor extends AccessControl{}
one sig TokenBased extends AccessControl{}
one sig None extends AcessControl{}

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
pred unsafePassword[p : Password] {
    p.length < 3 or
    (p.hasSpecChars = False and p.hasNumbers = False and p.hasUpperCase = False) or
    p.hasPattern = True
}

pred semisafePassword[p : Password] {
    p.length = 3
    --At least 2 of the following are true    (hasSpecChars, hasNumbers, hasUpperCase)
    (p.hasSpecChars = True and p.hasNumbers = True) or
    (p.hasSpecChars = True and p.hasUpperCase = True) or
    (p.hasNumbers = True and p.hasUpperCase = True)

}

pred safePassword[p : Password] {
    p.length >= 4
    p.hasSpecChars = True
    p.hasNumbers = True
    p.hasUpperCase = True
    p.hasPattern = True
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



fun VersionScore[v: PatchLevel]: one Int {
    {v = Critical} => {2} else {
        {v=Moderate} => {1} else {0}
    }
}

fun EncryptionScore[e: EncryptionAlgorithm]: one Int {
    {e = ThreeDES} => {1} else {
        0
    }
}

fun AccessControlScore[a: AccessControl]: one Int {
    {a = PasswordBased} => {1} else {
        0
    } 
}

fun LoggingAnalysisScore[a: LoggingAnalysisLevel]: one Int {
    {a = False} => {1} else {
        0
    }
}
fun EndPointScore[e: EndPoint]: one Int {
    {e.encryption = Plain or e.inputValidation=False or e.accessControl=None or e.validUserPacket = False} => {5} else
    {add[VersionScore[e.osVersion], EncryptionScore[e.encryption], AccessControlScore[e.accessControl], LoggingAnalysisScore[e.loggingAnalysis]]}
}

fun adversaryAdvantageBrowserVersion[p: PatchLevel]: one Int {
	(p = Critical) => 5 else (p = Moderate) => 1 else 0
}

fun adversaryAdvantageWifiProtocol[pass: Password, proto: WifiProtocol]: one Int {
	(proto = WEP) => {
		unsafePassword[pass] => {
			5
		} else {
			-- PTW attack, chopchop allow for easy password recovery against WEP.
			4
		}
	} else {
		unsafePassword[pass] => {
			5
		} else semisafePassword[pass] => {
			3
		} else {
			0
		}
	}
}

-- Can be semantically interpreted as a security score.
fun adversaryCostConnectionInner[c: Connection]: one Int {
	-- This is currently normalized at 5. Numbers might need to be tweaked.
	-- An attacker can't MITM a connection that isn't live.
	(c.connectionactive = False) => 5 else {
		subtract[5, ((HTTP in c.layer4Protocol) => {
			add[adversaryAdvantageWifiProtocol[c.networkPassword, c.wifiProtocol],
				adversaryAdvantageBrowserVersion[c.browserVersion]]
		} else { 0 })]}
}

fun adversaryCostConnection[c: Connection]: one Int {
	(adversaryCostConnectionInner[c] >= 0) => adversaryCostConnectionInner[c] else 0
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
        (unsafePassword[s.user.password] or
         semisafePassword[s.user.password] or
         safePassword[s.user.password])
		adversaryCostConnection[s.connection] = 0
    }
     
 } for exactly 3 State --, exactly 1 User, exactly 1 Connection, exactly 1 EndPoint

   --for {next is linear}

   --for {next is linear}

