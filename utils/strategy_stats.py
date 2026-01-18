from collections import Counter, defaultdict

def build_strategy_statistics(strategies):
    stats = {
        "by_source": Counter(),
        "by_confidence": Counter(),
        "by_mitre": Counter(),
        "by_port": Counter(),
        "by_exploit_type": Counter(),
        "attack_chains": defaultdict(int)
    }

    for s in strategies:
        stats["by_source"][s["exploit_source"]] += 1
        stats["by_confidence"][s["confidence"]] += 1
        stats["by_mitre"][s["mitre_technique"]] += 1
        stats["by_exploit_type"][s["exploit_type"]] += 1

        for p in s.get("related_ports", []):
            stats["by_port"][p] += 1

        chain = " → ".join(s["attack_chain"])
        stats["attack_chains"][chain] += 1

    # Convert Counters to normal dicts (important for JSON)
    return {k: dict(v) for k, v in stats.items()}
