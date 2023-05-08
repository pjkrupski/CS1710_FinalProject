#lang forge 
open "model.frg"
--open "model.frg"   causes "cycle in loading" error
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



//Connection Score evaluation

fun networkTopologyScore[s: State]: one Int {
	HTTP in s.connection.layer4Protocol => {
		#s.connection.peer.^endpoints
	} else 0
}



//Endpoint Evaluation

fun VersionScore[v: Evaluation]: one Int {
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


//Final score evalutation
fun evaluation[s: State]: one Evaluation {
	//Check Safe
    {((userScore[s.Password, s.mfaEnabled, s.passwordCache] + networkTopologyScore[s] + EndPointScore[s.EndPoint]) < 5)
	   userScore[s.Password, s.mfaEnabled, s.passwordCache] < 4
	   networkTopologyScore[s] < 4
	   EndPointScore[s.EndPoint] < 4
	} => Safe else

	//Check Moderate
    {((userScore[s.Password, s.mfaEnabled, s.passwordCache] + networkTopologyScore[s] + EndPointScore[s.EndPoint]) <= 7) or
	   userScore[s.Password, s.mfaEnabled, s.passwordCache] = 4 or
	   networkTopologyScore[s] = 4 or
	   EndPointScore[s.EndPoint] = 4
	} => Moderate else Critical

}


//Adversarial Analysis

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



