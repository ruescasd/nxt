# Example E2E-VIV Threat Model - Contexts
# This shows how context definitions would look with IDE autocomplete

from nxt import Context, ContextKind


# Subsystems
BB = Context(id="BB", name="Ballot Box", kind=ContextKind.SUBSYSTEM)
VA = Context(id="VA", name="Voting Application", kind=ContextKind.SUBSYSTEM)
BCA = Context(id="BCA", name="Ballot Checking Application", kind=ContextKind.SUBSYSTEM)
EAS = Context(id="EAS", name="Election Administration Server", kind=ContextKind.SUBSYSTEM)
TA = Context(id="TA", name="Trustee Application", kind=ContextKind.SUBSYSTEM)
TAS = Context(id="TAS", name="Trustee Administration Server", kind=ContextKind.SUBSYSTEM)
EST = Context(id="EST", name="Election Subsystem - Tallying", kind=ContextKind.SUBSYSTEM)
EAA = Context(id="EAA", name="Election Administration Application", kind=ContextKind.SUBSYSTEM)
AS = Context(id="AS", name="Authentication Service", kind=ContextKind.SUBSYSTEM)
BP = Context(id="BP", name="Ballot Printer", kind=ContextKind.SUBSYSTEM)
VER = Context(id="VER", name="Verifier", kind=ContextKind.SUBSYSTEM)
SUB = Context(id="SUB", name="Any Subsystem", kind=ContextKind.SUBSYSTEM)
TST = Context(id="TST", name="Trustee Security Token", kind=ContextKind.SUBSYSTEM)

# Networks
IN = Context(id="IN", name="Internet", kind=ContextKind.NETWORK)
EAN = Context(id="EAN", name="Election Administration Network", kind=ContextKind.NETWORK)
EON = Context(id="EON", name="Election Operations Network", kind=ContextKind.NETWORK)
AGN = Context(id="AGN", name="Air-Gapped Network", kind=ContextKind.NETWORK)

# Actors
EA = Context(id="EA", name="Election Administrator", kind=ContextKind.ACTOR)
TR = Context(id="TR", name="Trustee", kind=ContextKind.ACTOR)
VD = Context(id="VD", name="Voter Device", kind=ContextKind.ACTOR)
CRD = Context(id="CRD", name="Credentials", kind=ContextKind.ACTOR)

# Cryptographic primitives
PKE = Context(id="PKE", name="Public Key Encryption", kind=ContextKind.PRIMITIVE)
SIG = Context(id="SIG", name="Digital Signatures", kind=ContextKind.PRIMITIVE)

# Data
VSIG = Context(id="VSIG", name="Voter signature keys", kind=ContextKind.DATA)


# All contexts for easy import
ALL = [
    BB, VA, BCA, EAS, TA, TAS, EST, EAA, AS, BP, VER, SUB, TST,
    IN, EAN, EON, AGN,
    EA, TR, VD, CRD,
    PKE, SIG,
    VSIG,
]
