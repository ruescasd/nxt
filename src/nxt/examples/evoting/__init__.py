# E2E-VIV Threat Model - Example
# This file assembles the threat model from its components

from nxt import ThreatModel

from . import contexts
from . import properties
from . import mitigations
from . import patterns
from . import attacks


# Build the complete threat model
model = ThreatModel(
    name="E2E-VIV Threat Model",
    description="Threat model for the Tusk Voting System End-to-End Verifiable Internet Voting system.",
    
    properties=properties.ALL,
    contexts=contexts.ALL,
    mitigations=mitigations.ALL,
    patterns=patterns.ALL,
    attacks=attacks.ALL,
)


if __name__ == "__main__":
    # Demo: build graph and run some queries
    G = model.build()
    
    print(f"=== {model.name} ===")
    print(f"Nodes: {G.number_of_nodes()}")
    print(f"Edges: {G.number_of_edges()}")
    print()
    
    # Show attacks targeting C2.1
    print("Attacks targeting C2.1 (Cast votes are correctly recorded):")
    for attack in model.get_attacks_targeting(properties.C2_1):
        print(f"  - {attack.name} [{attack.id}]")
        mits = model.get_mitigations_for(attack)
        for m, rationale in mits:
            print(f"      ↳ Mitigated by: {m.name}")
    print()
    
    # Show attacks in the Ballot Box context
    print("Attacks in Ballot Box context:")
    for attack in model.get_attacks_in_context(contexts.BB):
        print(f"  - {attack.name}")
    print()
    
    # Show outstanding attacks (no mitigations)
    print("Outstanding attacks (no mitigations):")
    for attack in model.get_outstanding_attacks():
        print(f"  - {attack.name} [{attack.id}]")
