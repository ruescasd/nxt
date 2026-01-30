# nxt

A Python framework for expressing threat models as typed Python objects with full IDE support (autocomplete, type checking, refactoring), backed by a NetworkX graph for powerful querying and analysis.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      AUTHORING LAYER                            │
│  Python classes + Pydantic                                      │
│  • IDE autocomplete (Ctrl+Space shows valid references)         │
│  • Type checking (Pylance catches errors)                       │
│  • Refactoring support (rename propagates)                      │
│  • Readable, maintainable threat model code                     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │  model.build()
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      GRAPH LAYER                                │
│  NetworkX DiGraph                                               │
│  • Uniform traversals (ancestors, descendants, paths)           │
│  • Mitigation inheritance via edge following                    │
│  • Outstanding attacks = leaves without mitigation edges        │
│  • Rendering (GraphViz, D3, etc.)                               │
│  • Export to other formats                                      │
└─────────────────────────────────────────────────────────────────┘
```

## Installation

```bash
pip install -e .
```

## Usage

### Define your threat model

```python
from nxt import Property, Context, Mitigation, Attack, AttackPattern
from nxt import ThreatModel, ContextKind, Scope, MitigationApplication

# Properties (security objectives)
CONFIDENTIALITY = Property(id="CONFIDENTIALITY", description="...")
P1 = Property(id="P1", refines=CONFIDENTIALITY, description="No linking voter to vote")

# Contexts (where attacks occur)
BB = Context(id="BB", name="Ballot Box", kind=ContextKind.SUBSYSTEM)

# Mitigations
recorded_as_cast = Mitigation(
    id="M2",
    name="Recorded as cast verifiability",
    description="A voter can verify their ballot was recorded correctly.",
    scope=Scope.PARTIALLY_CORE,
)

# Attack patterns (reusable)
network_tampering = AttackPattern(
    id="network_tampering",
    name="Network tampering",
    description="An adversary exploits network weaknesses.",
    mitigations=[...],  # Inherited by variants
)

# Concrete attacks
ballot_tampering_network = Attack(
    id="ballot_tampering.network",
    name="Network tampering",
    variant_of=network_tampering,  # ← IDE shows available patterns!
    occurs_in=[BB],                # ← IDE shows available contexts!
    targets=[P1],                  # ← IDE shows available properties!
    mitigations=[
        MitigationApplication(
            mitigation=recorded_as_cast,
            rationale="The ballot tracker check detects this attack.",
        ),
    ],
)

# Assemble the model
model = ThreatModel(
    name="My Threat Model",
    properties=[CONFIDENTIALITY, P1],
    contexts=[BB],
    mitigations=[recorded_as_cast],
    patterns=[network_tampering],
    attacks=[ballot_tampering_network],
)
```

### Query the model

```python
# Build the NetworkX graph
G = model.build()

# Find attacks targeting a property
attacks = model.get_attacks_targeting(P1)

# Find attacks in a context
attacks_in_bb = model.get_attacks_in_context(BB)

# Get mitigations for an attack (including inherited ones)
mitigations = model.get_mitigations_for(ballot_tampering_network)

# Find outstanding attacks (no mitigations)
outstanding = model.get_outstanding_attacks()

# Use raw NetworkX for custom queries
import networkx as nx
ancestors = nx.ancestors(G, "ballot_tampering.network")
```

## Example

See `src/nxt/examples/evoting/` for a partial port of the E2E-VIV threat model.

```bash
python -m nxt.examples.evoting
```

## Development

```bash
pip install -e ".[dev]"
pytest
mypy src
```
