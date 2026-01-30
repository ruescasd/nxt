# Example E2E-VIV Threat Model - Concrete Attacks
# Specific attacks instantiated from patterns

from nxt import Attack, MitigationApplication, OUT_OF_SCOPE
from . import contexts as ctx
from . import properties as prop
from . import patterns
from . import mitigations as mit


# === Parent attacks (grouping) ===

mismatched_encryption = Attack(
    id="mismatched_encryption",
    name="Mismatched encryption",
    description="The cryptogram does not match the voter's intent.",
    targets=[],  # Children have the specific targets
)

ballot_tampering = Attack(
    id="ballot_tampering",
    name="Ballot tampering",
    description="Cryptograms are altered or removed.",
    targets=[],
)

# === Concrete attacks ===

# Mismatched encryption attacks
cheating_voting_device = Attack(
    id="cheating_voting_device",
    name="Cheating voting device",
    description="The voting application encrypts a cryptogram that does not correspond to the voter's intent.",
    variant_of=patterns.compromised_device,  # ← IDE autocomplete shows available patterns!
    achieves=[mismatched_encryption],
    occurs_in=[ctx.VA],                       # ← Autocomplete shows: BB, VA, EAS, etc.
    targets=[prop.C1_1],                      # ← Autocomplete shows: C1, C1_1, C2_1, etc.
    mitigations=[
        MitigationApplication(
            mitigation=mit.cast_as_intended,  # ← Autocomplete shows available mitigations!
            rationale="The ballot checking process will detect mismatched encrypted submissions. "
                      "For a single compromised device, this checking process (assuming it is "
                      "carried out by the voter using a different, uncompromised device) detects "
                      "this attack, though only if the voter carries it out.",
        ),
        MitigationApplication(
            mitigation=mit.recorded_as_cast,
            rationale="Ballot tracker checks on the bulletin board will detect covert "
                      "submit-and-cast of mismatched ciphertexts.",
        ),
    ],
)


# Ballot tampering attacks - multiple contexts
ballot_tampering_network_in = Attack(
    id="ballot_tampering.network.IN",
    name="Network tampering",
    description="The network adds, alters or removes cryptograms.",
    variant_of=patterns.network_tampering,
    achieves=[ballot_tampering],
    occurs_in=[ctx.IN],
    targets=[prop.C2_1],
    mitigations=[
        MitigationApplication(
            mitigation=mit.recorded_as_cast,
            rationale="For a single altered or removed cryptogram, the ballot tracker checking "
                      "process detects this attack, though only if the voter carries it out.",
        ),
    ],
)

ballot_tampering_network_ean = Attack(
    id="ballot_tampering.network.EAN",
    name="Network tampering",
    description="The network adds, alters or removes cryptograms.",
    variant_of=patterns.network_tampering,
    achieves=[ballot_tampering],
    occurs_in=[ctx.EAN],
    targets=[prop.C2_1],
    mitigations=[
        MitigationApplication(
            mitigation=mit.recorded_as_cast,
            rationale="For a single altered or removed cryptogram, the ballot tracker checking "
                      "process detects this attack, though only if the voter carries it out.",
        ),
    ],
)

ballot_tampering_device_bb = Attack(
    id="ballot_tampering.device.BB",
    name="Compromised device",
    description="One or more subsystems alters or removes cryptograms during storage in the ballot box.",
    variant_of=patterns.compromised_device,
    achieves=[ballot_tampering],
    occurs_in=[ctx.BB],
    targets=[prop.C2_1],
    mitigations=[
        MitigationApplication(
            mitigation=mit.recorded_as_cast,
            rationale="For a single altered or removed cryptogram, the ballot tracker checking "
                      "process detects this attack, though only if the voter carries it out.",
        ),
    ],
)

ballot_tampering_corruption_ea = Attack(
    id="ballot_tampering.corruption.EA",
    name="Corruption",
    description="The election administrator alters or removes cryptograms in the ballot box.",
    variant_of=patterns.corruption,
    achieves=[ballot_tampering],
    occurs_in=[ctx.EA],
    targets=[prop.C2_1],
    mitigations=[
        MitigationApplication(
            mitigation=mit.recorded_as_cast,
            rationale="For a single altered or removed cryptogram, the ballot tracker checking "
                      "process detects this attack, though only if the voter carries it out.",
        ),
    ],
)


# Example with OUT_OF_SCOPE mitigation
shoulder_surfing = Attack(
    id="shoulder_surfing",
    name="Shoulder surfing",
    description="The voter is physically observed while using the voting application.",
    targets=[prop.P1],
    mitigations=[
        MitigationApplication(
            mitigation=OUT_OF_SCOPE,
            rationale="Preventing this attack is outside the system scope. If a voter allows, "
                      "or is coerced into allowing, an observer to watch their entire voting "
                      "session, that observer will learn how they voted.",
        ),
    ],
)


ALL = [
    mismatched_encryption, cheating_voting_device,
    ballot_tampering,
    ballot_tampering_network_in, ballot_tampering_network_ean,
    ballot_tampering_device_bb, ballot_tampering_corruption_ea,
    shoulder_surfing,
]
