# E2E-VIV Threat Model - View Functions
# Replicating legacy view.py queries using NetworkX

from typing import Optional
from nxt import ThreatModel, Property, Attack, Context, Mitigation


def property_tree(model: ThreatModel, root: Optional[Property] = None) -> str:
    """
    Display property tree in legacy format.
    
    Legacy format:
        AVAILABILITY The e-voting properties of {Robustness}...
        ├── A1 Every voter must be able to cast...
        ├── A2 All participants must be able to...
    """
    lines = []
    
    # Get tree order
    if root is None:
        roots = [p for p in model.properties if p.refines is None]
    else:
        roots = [root]
    
    for r in sorted(roots, key=lambda p: p.id):
        _render_property_tree(model, r, lines, prefix="", is_last=True, is_root=True)
    
    return "\n".join(lines)


def _render_property_tree(
    model: ThreatModel,
    prop: Property, 
    lines: list[str], 
    prefix: str,
    is_last: bool,
    is_root: bool
) -> None:
    """Recursively render property tree with box-drawing characters."""
    # Truncate description to ~50 chars for display
    desc = prop.description[:50] + ".." if len(prop.description) > 50 else prop.description
    
    if is_root:
        lines.append(f"{prop.id} {desc}")
        child_prefix = ""
    else:
        connector = "└── " if is_last else "├── "
        lines.append(f"{prefix}{connector}{prop.id} {desc}")
        child_prefix = prefix + ("    " if is_last else "│   ")
    
    # Get children sorted by ID
    children = sorted(
        [p for p in model.properties if p.refines and p.refines.id == prop.id],
        key=lambda p: p.id
    )
    
    for i, child in enumerate(children):
        _render_property_tree(
            model, child, lines, child_prefix, 
            is_last=(i == len(children) - 1),
            is_root=False
        )


def attack_tree(model: ThreatModel, root: Optional[Attack] = None) -> str:
    """
    Display attack tree in legacy format.
    
    Legacy format:
        Bad decryption
        ├─Compromised device (TA)
        ├─Corruption (TR)
    """
    lines = []
    
    if root is None:
        # Roots are attacks with no achieves
        roots = [a for a in model.attacks if not a.achieves]
    else:
        roots = [root]
    
    for r in sorted(roots, key=lambda a: a.name):
        _render_attack_tree(model, r, lines, prefix="", is_last=True, is_root=True)
    
    return "\n".join(lines)


def _render_attack_tree(
    model: ThreatModel,
    attack: Attack, 
    lines: list[str], 
    prefix: str,
    is_last: bool,
    is_root: bool
) -> None:
    """Recursively render attack tree with context annotation."""
    # Format: name (context) for leaf attacks
    ctx_str = ""
    if attack.occurs_in:
        ctx_str = f" ({', '.join(c.id for c in attack.occurs_in)})"
    
    name = attack.name
    
    if is_root:
        lines.append(f"{name}")
        child_prefix = ""
    else:
        connector = "└─" if is_last else "├─"
        lines.append(f"{prefix}{connector}{name}{ctx_str}")
        child_prefix = prefix + ("  " if is_last else "│ ")
    
    # Get children (attacks that achieve this one)
    children = sorted(
        [a for a in model.attacks if attack in a.achieves],
        key=lambda a: a.name
    )
    
    for i, child in enumerate(children):
        _render_attack_tree(
            model, child, lines, child_prefix,
            is_last=(i == len(children) - 1),
            is_root=False
        )


def context_table(model: ThreatModel) -> str:
    """Display contexts in table format."""
    lines = [
        "+------------------------------------+-----------+---------------+",
        "| Name                               | Kind      | Description   |",
        "+====================================+===========+===============+",
    ]
    
    for ctx in sorted(model.contexts, key=lambda c: c.name):
        name = ctx.name[:34].ljust(34)
        kind = ctx.kind.value[:9].ljust(9)
        desc = (ctx.description or "")[:13].ljust(13)
        lines.append(f"| {name} | {kind} | {desc} |")
        lines.append("+------------------------------------+-----------+---------------+")
    
    return "\n".join(lines)


def outstanding_attacks(model: ThreatModel, root: Optional[Attack] = None) -> list[Attack]:
    """
    Get outstanding attacks (leaf attacks with no mitigations).
    
    If root is provided, only consider attacks under that root.
    """
    # Get all attacks to consider
    if root is None:
        attacks_to_check = model.attacks
    else:
        # Collect all descendants of root
        attacks_to_check = []
        _collect_descendants(model, root, attacks_to_check)
    
    outstanding = []
    for attack in attacks_to_check:
        # Check if it's a leaf (no children)
        children = [a for a in model.attacks if attack in a.achieves]
        if children:
            continue  # Not a leaf
        
        # Check if it has mitigations (direct or inherited)
        mits = model.get_mitigations_for(attack)
        if not mits:
            outstanding.append(attack)
    
    return outstanding


def _collect_descendants(model: ThreatModel, attack: Attack, result: list[Attack]) -> None:
    """Collect attack and all its descendants."""
    result.append(attack)
    children = [a for a in model.attacks if attack in a.achieves]
    for child in children:
        _collect_descendants(model, child, result)


def get_attack_identifier(attack: Attack) -> str:
    """
    Build the legacy-style attack identifier.
    
    Format: ParentName.AttackName or ParentName.AttackName.ContextID
    
    Examples:
        - Denial of service.Spoofing.VA
        - Malicious reporting.Malicious reporting of VD
        - Internal sabotage.Subsystem sabotage.SUB
    """
    parts = []
    
    # Get parent name (first achieves)
    if attack.achieves:
        parts.append(attack.achieves[0].name)
    
    # Add attack name
    parts.append(attack.name)
    
    # Add context if present
    if attack.occurs_in:
        parts.append(attack.occurs_in[0].id)
    
    return ".".join(parts)


def get_attacks_for_property(model: ThreatModel, prop: Property) -> list[Attack]:
    """
    Get all attacks that target this specific property.
    
    Unlike get_attacks_targeting which gets descendants too, this only
    returns attacks that directly target this property.
    """
    return [a for a in model.attacks if prop in a.targets]


def get_mitigations_for_property(model: ThreatModel, prop: Property) -> list[Mitigation]:
    """
    Get unique mitigations for all attacks targeting this property.
    
    This follows attack hierarchies (children) and pattern hierarchies
    (instance_of/variant_of) to collect all applicable mitigations.
    """
    seen: set[str] = set()
    result: list[Mitigation] = []
    
    attacks = get_attacks_for_property(model, prop)
    for attack in attacks:
        _collect_attack_mitigations(model, attack, seen, result)
    
    return result


def _collect_attack_mitigations(
    model: ThreatModel, 
    attack: Attack, 
    seen: set[str], 
    result: list[Mitigation]
) -> None:
    """
    Recursively collect mitigations from an attack and its descendants.
    
    This mirrors the legacy behavior which collects mitigations from:
    - Direct attack mitigations
    - Child attack mitigations (attacks that achieve this one)
    - Pattern mitigations (via variant_of/instance_of)
    """
    # Get mitigations from this attack (direct + inherited from pattern)
    for mit, _rationale in model.get_mitigations_for(attack, include_inherited=True):
        # Skip OUT_OF_SCOPE - legacy view doesn't show it in property table
        if mit.id not in seen and mit.id != "OOS":
            seen.add(mit.id)
            result.append(mit)
    
    # Recurse into children (attacks that achieve this one)
    children = [a for a in model.attacks if attack in a.achieves]
    for child in children:
        _collect_attack_mitigations(model, child, seen, result)


def property_table(model: ThreatModel, root: Optional[Property] = None) -> str:
    """
    Display property table in legacy format.
    
    Format matches legacy view.py -e property output with columns:
    Name, Description, Attacks, Mitigations
    
    The table shows tree structure in Name column using └─ prefixes.
    """
    # Get properties in tree order
    if root is None:
        roots = [p for p in model.properties if p.refines is None]
    else:
        roots = [root]
    
    rows: list[tuple[str, str, list[str], list[str]]] = []
    
    for r in sorted(roots, key=lambda p: p.id):
        _collect_property_rows(model, r, rows, level=0, prefix="")
    
    return _format_property_table(rows)


def _collect_property_rows(
    model: ThreatModel,
    prop: Property,
    rows: list[tuple[str, str, list[str], list[str]]],
    level: int,
    prefix: str
) -> None:
    """Recursively collect property rows with tree indentation."""
    # Build name with tree prefix
    if level == 0:
        name = prop.id
        child_prefix = ""
    else:
        name = prefix + prop.id
        child_prefix = prefix + "─"
    
    # Truncate description
    desc = prop.description[:50] + ".." if len(prop.description) > 50 else prop.description
    
    # Get attacks targeting this property
    attacks = get_attacks_for_property(model, prop)
    attack_ids = sorted([get_attack_identifier(a) for a in attacks])
    
    # Get mitigations for this property
    mitigations = get_mitigations_for_property(model, prop)
    mitigation_names = sorted([m.name for m in mitigations])
    
    rows.append((name, desc, attack_ids, mitigation_names))
    
    # Process children
    children = sorted(
        [p for p in model.properties if p.refines and p.refines.id == prop.id],
        key=lambda p: p.id
    )
    
    for child in children:
        if level == 0:
            new_prefix = "└─"
        else:
            new_prefix = child_prefix
        _collect_property_rows(model, child, rows, level + 1, new_prefix)


def _format_property_table(rows: list[tuple[str, str, list[str], list[str]]]) -> str:
    """Format property rows as a table matching legacy output."""
    # Column widths matching legacy output
    name_width = 18
    desc_width = 52
    attack_width = 79
    mit_width = 33
    
    lines = []
    
    # Header
    sep = f"+{'-' * (name_width + 2)}+{'-' * (desc_width + 2)}+{'-' * (attack_width + 2)}+{'-' * (mit_width + 2)}+"
    header_sep = f"+{'=' * (name_width + 2)}+{'=' * (desc_width + 2)}+{'=' * (attack_width + 2)}+{'=' * (mit_width + 2)}+"
    
    lines.append(sep)
    lines.append(f"| {'Name'.ljust(name_width)} | {'Description'.ljust(desc_width)} | {'Attacks'.ljust(attack_width)} | {'Mitigations'.ljust(mit_width)} |")
    lines.append(header_sep)
    
    for name, desc, attacks, mitigations in rows:
        # Calculate max rows needed for this property
        max_rows = max(1, len(attacks), len(mitigations))
        
        for i in range(max_rows):
            # First row gets name and description
            if i == 0:
                name_cell = name[:name_width].ljust(name_width)
                desc_cell = desc[:desc_width].ljust(desc_width)
            else:
                name_cell = " " * name_width
                desc_cell = " " * desc_width
            
            # Attack for this row
            if i < len(attacks):
                attack_cell = attacks[i][:attack_width].ljust(attack_width)
            else:
                attack_cell = " " * attack_width
            
            # Mitigation for this row
            if i < len(mitigations):
                mit_cell = mitigations[i][:mit_width].ljust(mit_width)
            else:
                mit_cell = " " * mit_width
            
            lines.append(f"| {name_cell} | {desc_cell} | {attack_cell} | {mit_cell} |")
        
        lines.append(sep)
    
    return "\n".join(lines)
