#lang forge 

---------- Components ----------
--User, Connection, Endpoint

sig User {
    --active
    --password
    --mfa Enabled or Disabled
    --password_cache Enabled or Disabled
}

sig Password {
    --length int   multiples of 5 
    --special characters True/False
    --numbers True/False
    --upper case True/False
    --pattern True/False
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
