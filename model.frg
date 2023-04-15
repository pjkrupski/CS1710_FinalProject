#lang forge 

---------- Components ----------

sig User {
    --active
    --password
    --mfa
    --cache 
}

sig Connection {
    --active
    --browerVersion
    --layer4Protocol
    --networkPassword
    --wifiProtocol
}

sig EndPoint {
    --active
    --osVersion
    --encrypted
    --inputValidation
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
