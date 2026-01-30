# Example E2E-VIV Threat Model - Mitigations
# Countermeasures that prevent or reduce impact of attacks

from nxt import Mitigation, Scope


cast_as_intended = Mitigation(
    id="M1",
    name="Cast as intended verifiability",
    description="A voter can verify that their ballot was cast as they intended.",
    scope=Scope.PARTIALLY_CORE,
)

recorded_as_cast = Mitigation(
    id="M2",
    name="Recorded as cast verifiability",
    description="A voter can verify that their recorded ballot is identical to the one they cast.",
    scope=Scope.PARTIALLY_CORE,
)

counted_as_recorded = Mitigation(
    id="M3",
    name="Counted as recorded verifiability",
    description="A voter can verify that their ballot was counted.",
    scope=Scope.PARTIALLY_CORE,
)

eligibility_verifiability = Mitigation(
    id="M4",
    name="Eligibility verifiability",
    description="An independent verifier can verify that no ineligible ballots were counted.",
    scope=Scope.PARTIALLY_CORE,
)

message_signatures = Mitigation(
    id="M5",
    name="Message signatures",
    description="Messages on the network are digitally signed.",
    scope=Scope.CORE,
)

tls = Mitigation(
    id="M6",
    name="TLS",
    description="Messages on the network use transport level security.",
    scope=Scope.NON_CORE,
)

cybersecurity_malware = Mitigation(
    id="M7",
    name="Cybersecurity---Malware",
    description="General cybersecurity practices aimed to protect against malware.",
    scope=Scope.NON_CORE,
)

cybersecurity_intrusion = Mitigation(
    id="M8",
    name="Cybersecurity---Intrusion",
    description="General cybersecurity practices aimed to protect against intrusion.",
    scope=Scope.NON_CORE,
)

cybersecurity_escalation = Mitigation(
    id="M9",
    name="Cybersecurity---Escalation",
    description="General cybersecurity practices aimed to protect against privilege escalation.",
    scope=Scope.NON_CORE,
)

dependency_minimization = Mitigation(
    id="M11",
    name="Dependency minimization",
    description="External software dependencies are minimized.",
    scope=Scope.PARTIALLY_CORE,
)

security_proof = Mitigation(
    id="M12",
    name="Security proof",
    description="A security proof of the protocol provides evidence that primitives are secure.",
    scope=Scope.CORE,
)

formal_verification = Mitigation(
    id="M13",
    name="Formal verification",
    description="Formal verification techniques prove implementation correctness.",
    scope=Scope.PARTIALLY_CORE,
)

external_audits = Mitigation(
    id="M14",
    name="External audits",
    description="External performers conduct source code audits.",
    scope=Scope.NON_CORE,
)

trust_distribution = Mitigation(
    id="M17",
    name="Trust distribution",
    description="Trust is distributed among multiple subsystems and actors.",
    scope=Scope.PARTIALLY_CORE,
)

controlled_environment = Mitigation(
    id="M20",
    name="Controlled environment",
    description="Physical environment is controlled to prevent adversarial access.",
    scope=Scope.NON_CORE,
)


ALL = [
    cast_as_intended, recorded_as_cast, counted_as_recorded, eligibility_verifiability,
    message_signatures, tls,
    cybersecurity_malware, cybersecurity_intrusion, cybersecurity_escalation,
    dependency_minimization, security_proof, formal_verification, external_audits,
    trust_distribution, controlled_environment,
]
