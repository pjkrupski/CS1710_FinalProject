#lang forge 
open "model.frg"

/*Total score evaluation 

Critical:
A system is critical when all three primary components sum to > 7 
or when any individual subcomponent has a score of 5

Moderate: 
A system is moderate when all three primary components sum to [5,6,7]
or when any individual subcomponent has a score of 4

Safe:
A system is safe when all three primary components sum to [0-4]
and when any individual subcomponent has a score of 3 or less


*/

-- Clamp `n` to [0, 5]
fun normalize[n: Int]: one Int {
	n < 0 => 0 else n > 5 => 5 else n
}

-- High cost corresponds to low advantage and vice versa.
--
-- This function converts between the two.
fun costToAdvantage[n: Int]: one Int {
	normalize[subtract[5, n]]
}

// User security cost evaluation
fun adversaryAdvantageUser[p: Password, mfa: mfaEnabled, cache: passwordCache]: one Int {
	--password cache is a minor danger since exploiting requires access to things outside of model
	--and only helps an attack when mfa is disabled
	(unsafePassword[p] and mfa = Disabled) => 5 else
    (unsafePassword[p] and mfa = Enabled) => 4 else
    (semisafePassword[p] and mfa = Disabled and cache = Enabled) => 4 else
    (semisafePassword[p] and mfa = Enabled) => 3 else
    (safePassword[p] and mfa = Disabled and cache = Enabled) => 3 else
    (safePassword[p] and mfa = Disabled and cache = Disabled) => 2 else
    (safePassword[p] and mfa = Enabled and cache = Enabled) => 1 else
    (safePassword[p] and mfa = Enabled and cache = Disabled) => 0 else
	0
}

fun defenderCostUser[s: State]: one Int {
	-- There's a lot of administrative overhead to enforce a safe password policy.
	(all p: Password | safePassword[p]) => {
		2
	} else {
		0
	}
}

fun userScore[s: State]: one Int {
	adversaryAdvantageUser[s.user.password, s.user.mfaEnabled, s.user.passwordCache]
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



// Connection cost evaluation

fun networkTopologyScore[s: State]: one Int {
	HTTP in s.connection.layer4Protocol => {
		#s.connection.peer.^endpoints
	} else 0
}


fun adversaryAdvantageNetworkTopology[s: State]: one Int {
	HTTP in s.connection.layer4Protocol => {
		#s.connection.peer.^endpoints
	} else 0
}

fun adversaryAdvantageBrowserVersion[e: Evaluation]: one Int {
	(e = Critical) => 5 else (e = Moderate) => 1 else 0
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

fun adversaryAdvantageConnection[c: Connection]: one Int {
	-- This is currently normalized at 5. Numbers might need to be tweaked.
	-- An attacker can't MITM a connection that isn't live.
	normalize[
		(c.connectionactive = False) => 0 else {
			costToAdvantage[((HTTP in c.layer4Protocol) => {
				add[adversaryAdvantageWifiProtocol[c.networkPassword, c.wifiProtocol],
					adversaryAdvantageBrowserVersion[c.browserVersion]]
			} else { 0 })]}
	]
}

fun defenderCostConnection[s: State]: one Int {
	-- Cost associated with (securely) maintaining TLS certificates.
	s.connection.layer4Protocol = HTTPS => { 1 } else { 0 }
}

fun connectionScore[c: Connection]: one Int {
	adversaryAdvantageConnection[c]
}

// Endpoint cost evaluation

fun VersionScore[e: Evaluation]: one Int {
    {e = Critical} => {2} else {
        {e=Moderate} => {1} else {0}
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





//Adversarial Functions

fun adversaryAdvantageVersion[v: Evaluation]: one Int {
    {v = Critical} => {2} else {
        {v=Moderate} => {1} else {0}
    }
}

fun adversaryAdvantageEncryption[e: EncryptionAlgorithm]: one Int {
    {e = ThreeDES} => {1} else {
        0
    }
}

fun adversaryAdvantageAccessControl[a: AccessControl]: one Int {
    {a = PasswordBased} => {1} else {
        0
    } 
}

fun adversaryAdvantageLoggingAnalysis[a: LoggingAnalysisLevel]: one Int {
    {a = False} => {1} else {
        0
    }
}

fun adversaryAdvantagEndPoint[e: EndPoint]: one Int {
    {e.encryption = Plain or e.inputValidation=False or e.accessControl=None or e.validUserPacket = False} => {5} else
    {add[
		adversaryAdvantageVersion[e.osVersion],
 		adversaryAdvantageEncryption[e.encryption],
 		adversaryAdvantageAccessControl[e.accessControl],
 		adversaryAdvantageLoggingAnalysis[e.loggingAnalysis]
	]}
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

fun defenderCostEndPoint[s: State]: one Int {
	let e = s.endpoint |
	-- Performant encryption, in general, is implemented in specialized hardware
    -- to thwart side-channel attacks. AES is standardized by NIST, TwoFish is
    -- not. So we posit that specialized hardware for AES is more readily
    -- available (and hence, more cost-effective.)
	let encryptionCost = e.encryption = AES => { 1 } else e.encryption = TwoFish => { 2 } else { 0 } |
	-- You have to pay people to analyze your logs.
	let blueTeamCost = e.loggingAnalysis = True => 1 else 0 |
	-- You have to pay RSA (or some similar company) to mange your tokens and seeds.
	let accessControlCost = e.accessControl = TokenBased => 1 else 0 |
	add[encryptionCost, blueTeamCost, accessControlCost]
}

fun EndPointScore[e: EndPoint]: one Int {
	adversaryAdvantagEndPoint[e]
}



//Final score evalutation
fun evaluation[s: State]: one Evaluation {
	/*
	Secure Total < 6, AND no single primary component is > 2
	Medium
	Critical

	if any single primary component is 5 CRITICAL
	*/

	//Check Safe
    {((add[userScore[s], adversaryAdvantageNetworkTopology[s], EndPointScore[s.endpoint]]) < 5)
	   userScore[s] < 4
	   adversaryAdvantageNetworkTopology[s] < 4
	   EndPointScore[s.endpoint] < 4
	} => Safe else

	//Check Moderate
    {((add[userScore[s], adversaryAdvantageNetworkTopology[s], EndPointScore[s.endpoint]]) <= 7) or
	   userScore[s] = 4 or
	   adversaryAdvantageNetworkTopology[s] = 4 or
	   EndPointScore[s.endpoint] = 4
	} => Moderate else Critical

}

fun evaluationCost[s: State]: one Int {
	add[defenderCostUser[s], defenderCostConnection[s], defenderCostEndPoint[s]]
}
