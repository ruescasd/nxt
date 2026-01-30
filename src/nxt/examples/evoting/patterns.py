# Example E2E-VIV Threat Model - Attack Patterns
# Abstract attacks that can be instantiated as concrete attacks

from nxt import AttackPattern, MitigationApplication
from . import mitigations as mit


# === Top-level patterns ===

compromised_device = AttackPattern(
    id="compromised_device",
    name="Compromised device",
    description="A device that runs one or more subsystems is altered in a way that affects the system's security.",
)

malware = AttackPattern(
    id="malware",
    name="Malware",
    description="Malicious software infects the device.",
    refines=compromised_device,
    mitigations=[
        MitigationApplication(
            mitigation=mit.cybersecurity_malware,
            rationale="General cybersecurity practices aimed to protect against malware reduce the risk of device infection.",
        ),
    ],
)

intrusion = AttackPattern(
    id="intrusion",
    name="Intrusion",
    description="An adversary gains control of the device.",
    refines=compromised_device,
    mitigations=[
        MitigationApplication(
            mitigation=mit.cybersecurity_intrusion,
            rationale="General cybersecurity practices aimed to protect against intrusion reduce the risk of an adversary gaining control.",
        ),
    ],
)

supply_chain = AttackPattern(
    id="supply_chain",
    name="Supply chain attack",
    description="One or more software dependencies of a subsystem is programmed maliciously.",
    refines=compromised_device,
    mitigations=[
        MitigationApplication(
            mitigation=mit.dependency_minimization,
            rationale="Minimizing the number and size of dependencies reduces the likelihood of malicious dependencies impacting system security.",
        ),
    ],
)


# === Network patterns ===

compromised_network = AttackPattern(
    id="compromised_network",
    name="Compromised network",
    description="Network behavior is altered in a way that affects the system's security.",
)

network_tampering = AttackPattern(
    id="network_tampering",
    name="Network tampering",
    description="An adversary exploits network weaknesses to add, drop, or forge protocol communications.",
    refines=compromised_network,
    mitigations=[
        MitigationApplication(
            mitigation=mit.message_signatures,
            rationale="Application-level digital signatures provide data integrity and authentication for application messages sent on the network.",
        ),
        MitigationApplication(
            mitigation=mit.tls,
            rationale="Transport layer security provides data integrity and authentication within the network.",
        ),
    ],
)

network_sabotage = AttackPattern(
    id="network_sabotage",
    name="Network sabotage",
    description="An adversary broadly disrupts network operation with respect to one or more subsystems or actors.",
    refines=compromised_network,
)


# === Cryptography patterns ===

broken_cryptography = AttackPattern(
    id="broken_cryptography",
    name="Broken cryptography",
    description="An aspect of the cryptography used in the system is flawed in a way that invalidates some or all of its security properties.",
)

broken_primitive = AttackPattern(
    id="broken_primitive",
    name="Broken primitive",
    description="One or more employed cryptographic primitives is fundamentally broken and is exploited.",
    refines=broken_cryptography,
    mitigations=[
        MitigationApplication(
            mitigation=mit.security_proof,
            rationale="A (preferably formal) security proof provides some level of assurance that a cryptographic primitive is not broken.",
        ),
    ],
)

insecure_implementation_owned = AttackPattern(
    id="insecure_implementation_owned",
    name="Insecure implementation---Owned",
    description="The implementation within owned source code is insecure and is exploited.",
    refines=broken_cryptography,
    mitigations=[
        MitigationApplication(
            mitigation=mit.formal_verification,
            rationale="Formal verification provides assurance that the source code satisfies its specification.",
        ),
        MitigationApplication(
            mitigation=mit.external_audits,
            rationale="External audits of the source code provide additional assurance about its security.",
        ),
    ],
)


# === Actor patterns ===

corruption = AttackPattern(
    id="corruption",
    name="Corruption",
    description="One or more subsystems or actors behaves maliciously.",
    mitigations=[
        MitigationApplication(
            mitigation=mit.trust_distribution,
            rationale="Distributing trust among multiple subsystems and actors reduces the likelihood that a corrupt subsystem or actor can compromise the system's security.",
        ),
    ],
)

side_channel = AttackPattern(
    id="side_channel",
    name="Side channel",
    description="An adversary acquires sensitive information via unintended, indirect mechanisms.",
    mitigations=[
        MitigationApplication(
            mitigation=mit.external_audits,
            rationale="External audits to evaluate side-channel resistance can often rule out or quantify specific side channel risks.",
        ),
    ],
)

spoofing = AttackPattern(
    id="spoofing",
    name="Spoofing",
    description="An adversary attacks the system by masquerading as a protocol subsystem or actor.",
    mitigations=[
        MitigationApplication(
            mitigation=mit.controlled_environment,
            rationale="For some parts of the system, a controlled environment can prevent adversaries from masquerading as protocol actors.",
        ),
        MitigationApplication(
            mitigation=mit.message_signatures,
            rationale="Provided an adversary does not acquire the necessary signing keys, the use of digitally signed messages can prevent spoofed messages from impacting system security.",
        ),
    ],
)


ALL = [
    compromised_device, malware, intrusion, supply_chain,
    compromised_network, network_tampering, network_sabotage,
    broken_cryptography, broken_primitive, insecure_implementation_owned,
    corruption, side_channel, spoofing,
]
