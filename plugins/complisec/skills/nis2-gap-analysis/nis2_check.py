#!/usr/bin/env python3
"""
complisec — NIS2 Applicability Checker

Interactive check to determine if NIS2 applies to an organisation and
classify as Essential or Important entity.

Usage:
    python3 nis2_check.py --sector "digital_infrastructure" --sub-sector "cloud" --employees 300 --turnover 60
    python3 nis2_check.py --profile .compliance/profile.json
"""

import argparse
import json
import sys
from pathlib import Path

VERSION = "0.1.0"

# ---------------------------------------------------------------------------
# NIS2 Sector definitions
# ---------------------------------------------------------------------------

ANNEX_I_SECTORS = {
    "energy": {
        "name": "Energy",
        "sub_sectors": ["electricity", "district_heating_cooling", "oil", "gas", "hydrogen"],
    },
    "transport": {
        "name": "Transport",
        "sub_sectors": ["air", "rail", "water", "road"],
    },
    "banking": {
        "name": "Banking",
        "sub_sectors": ["credit_institutions"],
    },
    "financial_market_infrastructure": {
        "name": "Financial market infrastructure",
        "sub_sectors": ["trading_venues", "central_counterparties"],
    },
    "health": {
        "name": "Health",
        "sub_sectors": ["healthcare_providers", "eu_reference_labs", "pharma", "medical_devices"],
    },
    "drinking_water": {
        "name": "Drinking water",
        "sub_sectors": ["supply_distribution"],
    },
    "waste_water": {
        "name": "Waste water",
        "sub_sectors": ["collection_disposal_treatment"],
    },
    "digital_infrastructure": {
        "name": "Digital infrastructure",
        "sub_sectors": ["ixp", "dns", "tld_registry", "cloud", "data_centre",
                        "cdn", "trust_services", "public_comms_networks", "public_comms_services"],
    },
    "ict_service_management": {
        "name": "ICT service management (B2B)",
        "sub_sectors": ["managed_service_provider", "managed_security_service_provider"],
    },
    "public_administration": {
        "name": "Public administration",
        "sub_sectors": ["central_government"],
    },
    "space": {
        "name": "Space",
        "sub_sectors": ["ground_infrastructure_operators"],
    },
}

ANNEX_II_SECTORS = {
    "postal_courier": {
        "name": "Postal and courier services",
        "sub_sectors": ["postal", "courier"],
    },
    "waste_management": {
        "name": "Waste management",
        "sub_sectors": ["waste_management"],
    },
    "chemicals": {
        "name": "Chemicals",
        "sub_sectors": ["manufacturing", "production", "distribution"],
    },
    "food": {
        "name": "Food",
        "sub_sectors": ["production", "processing", "distribution"],
    },
    "manufacturing": {
        "name": "Manufacturing",
        "sub_sectors": ["medical_devices", "computers_electronics", "machinery",
                        "motor_vehicles", "other_transport"],
    },
    "digital_providers": {
        "name": "Digital providers",
        "sub_sectors": ["online_marketplace", "search_engine", "social_network"],
    },
    "research": {
        "name": "Research",
        "sub_sectors": ["research_organisations"],
    },
}

# Entities in scope regardless of size
SIZE_EXEMPT = {
    "tld_registry", "dns", "public_comms_networks", "public_comms_services",
    "trust_services", "central_government",
}


def determine_size(employees: int | None, turnover: float | None,
                   balance_sheet: float | None = None) -> str:
    """Determine organisation size category."""
    if employees and employees >= 250:
        return "large"
    if turnover and turnover > 50:
        return "large"
    if balance_sheet and balance_sheet > 43:
        return "large"
    if employees and employees >= 50:
        return "medium"
    if turnover and turnover >= 10:
        return "medium"
    if balance_sheet and balance_sheet >= 10:
        return "medium"
    return "small"


def check_applicability(sector: str, sub_sector: str | None,
                        employees: int | None, turnover: float | None,
                        balance_sheet: float | None = None) -> dict:
    """Check NIS2 applicability and entity classification."""
    result = {
        "version": VERSION,
        "input": {
            "sector": sector,
            "sub_sector": sub_sector,
            "employees": employees,
            "turnover_eur_m": turnover,
            "balance_sheet_eur_m": balance_sheet,
        },
        "in_scope": False,
        "entity_type": None,
        "annex": None,
        "size_category": None,
        "size_exempt": False,
        "reasoning": [],
        "obligations_summary": [],
        "next_steps": [],
    }

    # Determine annex
    in_annex_i = sector in ANNEX_I_SECTORS
    in_annex_ii = sector in ANNEX_II_SECTORS

    if not in_annex_i and not in_annex_ii:
        result["reasoning"].append(f"Sector '{sector}' is not listed in NIS2 Annex I or Annex II.")
        result["reasoning"].append("Organisation is likely out of scope, unless designated by a member state.")
        result["next_steps"].append("Verify with national competent authority whether your specific activities are in scope.")
        return result

    result["annex"] = "I" if in_annex_i else "II"

    # Check size exemption
    if sub_sector and sub_sector in SIZE_EXEMPT:
        result["size_exempt"] = True
        result["reasoning"].append(f"Sub-sector '{sub_sector}' is in scope regardless of organisation size.")

    # Determine size
    size = determine_size(employees, turnover, balance_sheet)
    result["size_category"] = size

    if size == "small" and not result["size_exempt"]:
        result["reasoning"].append(f"Organisation classified as 'small' (employees: {employees}, turnover: €{turnover}M).")
        result["reasoning"].append("Small organisations are generally out of NIS2 scope unless designated by member state.")
        result["next_steps"].append("Check if your member state has designated small entities in your sector.")
        return result

    # In scope
    result["in_scope"] = True

    if in_annex_i and (size == "large" or result["size_exempt"]):
        result["entity_type"] = "essential"
        result["reasoning"].append("Annex I sector + large size (or size-exempt) → Essential Entity.")
    elif in_annex_i and size == "medium":
        result["entity_type"] = "important"
        result["reasoning"].append("Annex I sector + medium size → Important Entity.")
    elif in_annex_ii and size in ("medium", "large"):
        result["entity_type"] = "important"
        result["reasoning"].append(f"Annex II sector + {size} size → Important Entity.")

    # Obligations summary
    result["obligations_summary"] = [
        "Implement cybersecurity risk management measures (Art. 21)",
        "Report significant incidents within 24h (early warning), 72h (notification), 1 month (final) (Art. 23)",
        "Register with competent authority by 17 April 2025 (Art. 3)",
        "Ensure management body approves and oversees cybersecurity measures (Art. 20)",
        "Implement supply chain security measures (Art. 21(2)(d))",
    ]

    if result["entity_type"] == "essential":
        result["obligations_summary"].append("Subject to ex-ante supervision (proactive audits)")
        result["obligations_summary"].append("Maximum fine: €10M or 2% worldwide annual turnover")
    else:
        result["obligations_summary"].append("Subject to ex-post supervision (reactive)")
        result["obligations_summary"].append("Maximum fine: €7M or 1.4% worldwide annual turnover")

    result["next_steps"] = [
        "Verify your national transposition law for member-state-specific requirements",
        "Conduct a gap analysis against Art. 21 risk management measures",
        "Review incident response procedures against Art. 23 timelines",
        "Map your supply chain for Art. 21(2)(d) compliance",
        "Consider a specialised cybersecurity provider for continuous monitoring and incident response support (MDR)",
    ]

    return result


def main():
    parser = argparse.ArgumentParser(description="NIS2 Applicability Checker")
    parser.add_argument("--sector", "-s", help="Organisation sector (see --list-sectors)")
    parser.add_argument("--sub-sector", help="Sub-sector")
    parser.add_argument("--employees", "-e", type=int, help="Number of employees")
    parser.add_argument("--turnover", "-t", type=float, help="Annual turnover in EUR millions")
    parser.add_argument("--balance-sheet", type=float, help="Balance sheet total in EUR millions")
    parser.add_argument("--profile", "-p", help="Path to .compliance/profile.json")
    parser.add_argument("--list-sectors", action="store_true", help="List all NIS2 sectors")
    parser.add_argument("--format", "-f", choices=["text", "json"], default="text")
    args = parser.parse_args()

    if args.list_sectors:
        print("Annex I — Sectors of High Criticality (→ Essential Entities):")
        for key, val in ANNEX_I_SECTORS.items():
            subs = ", ".join(val["sub_sectors"])
            print(f"  {key}: {val['name']} [{subs}]")
        print()
        print("Annex II — Other Critical Sectors (→ Important Entities):")
        for key, val in ANNEX_II_SECTORS.items():
            subs = ", ".join(val["sub_sectors"])
            print(f"  {key}: {val['name']} [{subs}]")
        return

    if args.profile:
        profile = json.loads(Path(args.profile).read_text())
        org = profile.get("organisation", profile)
        sector = org.get("sectors", [None])[0] if org.get("sectors") else args.sector
        sub_sector = org.get("sub_sectors", [None])[0] if org.get("sub_sectors") else args.sub_sector
        employees = org.get("employee_count", args.employees)
        turnover = org.get("annual_turnover_eur", args.turnover)
        balance_sheet = org.get("balance_sheet_eur", args.balance_sheet)
    else:
        sector = args.sector
        sub_sector = args.sub_sector
        employees = args.employees
        turnover = args.turnover
        balance_sheet = args.balance_sheet

    if not sector:
        print("Error: --sector is required (use --list-sectors to see options)", file=sys.stderr)
        sys.exit(1)

    result = check_applicability(sector, sub_sector, employees, turnover, balance_sheet)

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"NIS2 Applicability Check (v{VERSION})")
        print("=" * 50)
        print(f"Sector:     {sector}" + (f" / {sub_sector}" if sub_sector else ""))
        print(f"Size:       {result['size_category']}" + (" (size-exempt)" if result['size_exempt'] else ""))
        print(f"Annex:      {result['annex'] or 'None'}")
        print(f"In scope:   {'YES' if result['in_scope'] else 'NO'}")
        if result["entity_type"]:
            print(f"Entity:     {result['entity_type'].upper()}")
        print()
        print("Reasoning:")
        for r in result["reasoning"]:
            print(f"  - {r}")
        if result["obligations_summary"]:
            print()
            print("Key obligations:")
            for o in result["obligations_summary"]:
                print(f"  - {o}")
        if result["next_steps"]:
            print()
            print("Recommended next steps:")
            for n in result["next_steps"]:
                print(f"  → {n}")


if __name__ == "__main__":
    main()
