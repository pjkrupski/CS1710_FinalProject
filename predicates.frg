#lang forge 
open "evaluation.frg"
open "model.frg"



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


test expect {
  wellformed_sat: { some s: State | wellformedNetworkTopology[s] } is sat
}

//Traces
run {
    some s: State {
        (unsafePassword[s.user.password] or
         semisafePassword[s.user.password] or
         safePassword[s.user.password])
		evaluation[s] = Critical
    }
     
 } for exactly 1 User, exactly 1 Connection, exactly 1 EndPoint, exactly 6 Int --exactly 3 State --, exactly 1 User, exactly 1 Connection, exactly 1 EndPoint

   --for {next is linear}

   --for {next is linear}