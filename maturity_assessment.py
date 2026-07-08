#!/usr/bin/env python3
"""
Rapid7 Vulnerability Management Maturity Assessment (VMMA)
Interactive CLI questionnaire based on the Rapid7 VMMA methodology.
Collects responses and saves to JSON for report generation.
Supports pause/resume — enter 'q' at any question to save and quit.
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Maturity levels
LEVELS = {
    1: "Preliminary",
    2: "Initial",
    3: "Managed",
    4: "Standardized",
    5: "Predictable",
    6: "Innovating"
}

# Assessment questions per control group
# Each question has: text, level it maps to, and scoring weight
ASSESSMENT = {
    "Governance": {
        "description": "Governance controls are formalized and direct information security and compliance initiatives.",
        "questions": [
            {"q": "Does the organization have a formal Vulnerability Management Policy (VMP)?", "level": 2, "weight": 1},
            {"q": "Is the VMP reviewed and updated at least annually?", "level": 3, "weight": 1},
            {"q": "Is vulnerability management aligned to a security framework (e.g., CIS, NIST, ISO)?", "level": 3, "weight": 1},
            {"q": "Is there a dedicated governance board or committee overseeing the VM program?", "level": 4, "weight": 1},
            {"q": "Are VM policies disseminated and communicated across all business units?", "level": 4, "weight": 1},
            {"q": "Are regulatory requirements (SOX, PCI, GDPR, etc.) formally mapped to VM controls?", "level": 4, "weight": 1},
            {"q": "Is there a formal exception process documented and enforced?", "level": 4, "weight": 1},
            {"q": "Are VM program goals and KPIs formally defined and tracked?", "level": 5, "weight": 1},
        ]
    },
    "Risk Management": {
        "description": "Risk reduction is central to any vulnerability management program.",
        "questions": [
            {"q": "Does the organization have a formal risk management program?", "level": 2, "weight": 1},
            {"q": "Is a risk scoring methodology used to prioritize vulnerabilities?", "level": 3, "weight": 1},
            {"q": "Does the risk scoring incorporate asset or data criticality?", "level": 4, "weight": 2},
            {"q": "Is a formal risk acceptance process defined for unmitigated risks?", "level": 3, "weight": 1},
            {"q": "Are business impact assessments (BIA) conducted on critical systems?", "level": 4, "weight": 1},
            {"q": "Is the organization's risk appetite formally documented?", "level": 4, "weight": 1},
            {"q": "Are network diagrams and data flows documented?", "level": 3, "weight": 1},
            {"q": "Are compensating controls considered when prioritizing remediation?", "level": 4, "weight": 1},
            {"q": "Are security controls continuously validated?", "level": 5, "weight": 2},
        ]
    },
    "Asset Management": {
        "description": "Active management of all hardware devices on the network.",
        "questions": [
            {"q": "Does the organization maintain an asset inventory (CMDB or equivalent)?", "level": 2, "weight": 1},
            {"q": "Are assets classified by criticality and data sensitivity?", "level": 4, "weight": 2},
            {"q": "Are asset owners assigned and documented?", "level": 3, "weight": 1},
            {"q": "Is the asset inventory integrated with the vulnerability scanner?", "level": 4, "weight": 2},
            {"q": "Are discovery scans performed to detect rogue/unauthorized devices?", "level": 3, "weight": 1},
            {"q": "Is a passive discovery tool used as part of the asset management program?", "level": 4, "weight": 1},
            {"q": "Are baseline configurations documented and validated for assets?", "level": 4, "weight": 1},
            {"q": "Is port security enabled on network switches?", "level": 4, "weight": 1},
            {"q": "Are gold images used for new system builds?", "level": 3, "weight": 1},
        ]
    },
    "Admin Privileges": {
        "description": "Processes and tools to track, control, and correct administrative privilege use.",
        "questions": [
            {"q": "Is there a formal process for provisioning and deprovisioning admin accounts?", "level": 3, "weight": 1},
            {"q": "Are admin accounts centrally managed (e.g., Active Directory)?", "level": 3, "weight": 1},
            {"q": "Do administrators use separate accounts for admin vs. everyday tasks?", "level": 3, "weight": 1},
            {"q": "Are shared administrator accounts prohibited?", "level": 3, "weight": 1},
            {"q": "Are admin accounts reviewed quarterly for access appropriateness?", "level": 4, "weight": 1},
            {"q": "Are admin accounts restricted from browsing the Internet?", "level": 4, "weight": 1},
            {"q": "Are alerts configured for admin account misuse?", "level": 4, "weight": 1},
            {"q": "Is role-based security training provided to users with admin rights?", "level": 4, "weight": 1},
        ]
    },
    "Discovery and Scanning": {
        "description": "Discovery of all systems and subsequent vulnerability scanning.",
        "questions": [
            {"q": "Are vulnerability scans performed on a regular, scheduled basis?", "level": 2, "weight": 1},
            {"q": "Are authenticated (credentialed) scans performed?", "level": 3, "weight": 2},
            {"q": "Are dedicated service accounts used for scanning?", "level": 3, "weight": 1},
            {"q": "Are scanning exceptions formally approved and documented?", "level": 3, "weight": 1},
            {"q": "Are discovery scans performed to identify rogue devices?", "level": 3, "weight": 2},
            {"q": "Are scan results compared cycle-to-cycle to track changes?", "level": 4, "weight": 1},
            {"q": "Are Insight Agents deployed for continuous endpoint assessment?", "level": 4, "weight": 1},
            {"q": "Is the PCI or other regulated environment scanned separately?", "level": 4, "weight": 1},
            {"q": "Is a formal scanning standard documented (frequency, etiquette, ownership)?", "level": 4, "weight": 1},
        ]
    },
    "Vulnerability Analysis": {
        "description": "Assessment and prioritization of identified vulnerabilities.",
        "questions": [
            {"q": "Are false positives identified and removed from remediation lists?", "level": 3, "weight": 1},
            {"q": "Is CVSS score used as a minimum baseline for prioritization?", "level": 2, "weight": 1},
            {"q": "Does prioritization incorporate asset criticality or data classification?", "level": 4, "weight": 2},
            {"q": "Are threat intelligence feeds reviewed to prioritize emerging threats?", "level": 4, "weight": 1},
            {"q": "Is there a formal process for emerging/zero-day threat response?", "level": 4, "weight": 2},
            {"q": "Are compensating controls factored into vulnerability risk scoring?", "level": 4, "weight": 1},
            {"q": "Are key metrics defined for the vulnerability analysis phase?", "level": 4, "weight": 1},
            {"q": "Is risk-based remediation prioritization formally documented?", "level": 5, "weight": 1},
        ]
    },
    "Remediation": {
        "description": "Minimization of attack surfaces through patching and mitigation.",
        "questions": [
            {"q": "Is there a formal patch management policy with defined timelines?", "level": 3, "weight": 1},
            {"q": "Are patches tested in non-production before production deployment?", "level": 3, "weight": 1},
            {"q": "Are all OS types covered by the patching process (Windows, Linux, etc.)?", "level": 3, "weight": 1},
            {"q": "Are third-party applications included in the patching program?", "level": 3, "weight": 1},
            {"q": "Are SLA targets defined for patching by severity (Critical/High/Medium/Low)?", "level": 4, "weight": 2},
            {"q": "Are automated workflows used between vulnerability scanning and patch management?", "level": 4, "weight": 2},
            {"q": "Are mitigations applied when systems cannot be patched?", "level": 4, "weight": 1},
            {"q": "Are M&A environments included in the patching program?", "level": 4, "weight": 1},
            {"q": "Are remediation efforts tracked to completion in a ticketing system?", "level": 3, "weight": 1},
        ]
    },
    "Change Management": {
        "description": "Timely assignment and tracking of remediation and risk mitigation tasks.",
        "questions": [
            {"q": "Is there a formal change management policy?", "level": 3, "weight": 1},
            {"q": "Is a Change Advisory Board (CAB) or equivalent established?", "level": 3, "weight": 1},
            {"q": "Are standard, normal, and emergency change types defined?", "level": 4, "weight": 1},
            {"q": "Are all changes tracked in a ticketing system with audit trails?", "level": 3, "weight": 1},
            {"q": "Are exceptions included in the change management workflow?", "level": 4, "weight": 1},
            {"q": "Is monthly patching treated as a standard change (pre-approved)?", "level": 4, "weight": 1},
        ]
    },
    "Reporting": {
        "description": "Conveying vulnerability management information to pertinent stakeholders.",
        "questions": [
            {"q": "Are vulnerability management reports produced on a regular cadence?", "level": 2, "weight": 1},
            {"q": "Are reports tailored for different audiences (executive, operational, tactical)?", "level": 4, "weight": 2},
            {"q": "Are KPIs and metrics formally defined for the VM program?", "level": 4, "weight": 1},
            {"q": "Do reports include risk reduction trends over time?", "level": 4, "weight": 1},
            {"q": "Are SLA compliance rates reported to senior management?", "level": 4, "weight": 1},
            {"q": "Are exception and false positive metrics tracked and reported?", "level": 4, "weight": 1},
            {"q": "Is reporting automated or semi-automated?", "level": 5, "weight": 1},
        ]
    },
    "Security Program": {
        "description": "Additional processes and activities supporting vulnerability management effectiveness.",
        "questions": [
            {"q": "Is there a formal security awareness training program?", "level": 3, "weight": 1},
            {"q": "Are penetration tests conducted at least annually?", "level": 3, "weight": 1},
            {"q": "Are phishing simulation campaigns conducted?", "level": 3, "weight": 1},
            {"q": "Is an authorized software/application inventory maintained?", "level": 3, "weight": 1},
            {"q": "Are business justifications documented for all approved applications?", "level": 4, "weight": 1},
            {"q": "Are baseline security configurations documented and enforced?", "level": 4, "weight": 1},
            {"q": "Are policy compliance scans (CIS/STIG) performed?", "level": 4, "weight": 2},
            {"q": "Are unsigned scripts/executables blocked from running in browsers?", "level": 4, "weight": 1},
            {"q": "Is there a third-party/supplier security assessment process?", "level": 4, "weight": 1},
        ]
    }
}


def save_checkpoint(checkpoint_file, customer, completed_domains, current_domain=None, current_responses=None):
    """Save progress to a checkpoint file."""
    data = {
        "customer": customer,
        "completed_domains": completed_domains,
        "current_domain": current_domain,
        "current_responses": current_responses or [],
        "checkpoint_date": datetime.now().isoformat()
    }
    with open(checkpoint_file, "w") as f:
        json.dump(data, f, indent=2)


def load_checkpoint(checkpoint_file):
    """Load progress from a checkpoint file."""
    with open(checkpoint_file) as f:
        return json.load(f)


def find_checkpoint():
    """Find any existing checkpoint files."""
    return sorted(Path(".").glob("checkpoint_*.json"), key=lambda f: f.stat().st_mtime, reverse=True)


def clear():
    os.system('clear' if os.name == 'posix' else 'cls')


def print_header():
    print("=" * 65)
    print("  Rapid7 Vulnerability Management Maturity Assessment (VMMA)")
    print("=" * 65)
    print()


def get_customer_info():
    print_header()
    print("Customer Information")
    print("-" * 40)
    name = input("Customer Name: ").strip()
    industry = input("Industry: ").strip()
    assessor = input("Assessor Name: ").strip()
    date = datetime.now().strftime("%Y-%m-%d")
    print()
    return {"name": name, "industry": industry, "assessor": assessor, "date": date}


def ask_questions(domain, data, checkpoint_file, customer, completed_domains, resume_responses=None):
    """Ask questions for a domain. Returns responses or None if user quit."""
    print(f"\n{'=' * 65}")
    print(f"  Domain: {domain}")
    print(f"  {data['description']}")
    print(f"{'=' * 65}")
    print("  Answer each question:")
    print("    y = Yes (fully in place)")
    print("    n = No (not in place)")
    print("    p = Partial (partially implemented — scores at 50%)")
    print("    u = Unknown (not applicable or unsure — excluded from score)")
    print("    q = Quit and save progress (resume later)")
    print()

    responses = list(resume_responses) if resume_responses else []
    start_index = len(responses)  # Resume from where we left off

    for i, q in enumerate(data["questions"], 1):
        # Skip already-answered questions on resume
        if i <= start_index:
            print(f"  {i}. {q['q']}")
            print(f"     [already answered: {responses[i-1]['answer']}]")
            print()
            continue

        while True:
            answer = input(f"  {i}. {q['q']}\n     [y/n/p/u/q]: ").strip().lower()
            if answer in ("y", "n", "p", "u"):
                responses.append({
                    "question": q["q"],
                    "answer": answer,
                    "level": q["level"],
                    "weight": q["weight"]
                })
                # Auto-save progress after each answer
                save_checkpoint(checkpoint_file, customer, completed_domains,
                                current_domain=domain, current_responses=responses)
                break
            elif answer == "q":
                print()
                print("  Progress saved. Run the script again to resume.")
                save_checkpoint(checkpoint_file, customer, completed_domains,
                                current_domain=domain, current_responses=responses)
                return None  # Signal to quit
            else:
                print("     Please enter y, n, p, u, or q")
        print()

    return responses


def calculate_domain_score(responses):
    """Calculate maturity score for a domain (1-6 scale).
    y = full weight, p = 50% weight, n = 0, u = excluded from calculation.
    """
    if not responses:
        return 1

    total_weight = sum(r["weight"] for r in responses if r["answer"] != "u")
    if total_weight == 0:
        return 1

    yes_weight = sum(r["weight"] for r in responses if r["answer"] == "y")
    partial_weight = sum(r["weight"] * 0.5 for r in responses if r["answer"] == "p")
    pct = (yes_weight + partial_weight) / total_weight

    if pct >= 0.90:
        return 6
    elif pct >= 0.75:
        return 5
    elif pct >= 0.60:
        return 4
    elif pct >= 0.40:
        return 3
    elif pct >= 0.20:
        return 2
    else:
        return 1


def main():
    clear()
    print_header()

    # Check for existing checkpoint
    checkpoints = find_checkpoint()
    resume_data = None
    checkpoint_file = None

    if checkpoints:
        print(f"  Found saved assessment: {checkpoints[0].name}")
        cp = load_checkpoint(checkpoints[0])
        print(f"  Customer: {cp['customer']['name']}")
        print(f"  Saved: {cp['checkpoint_date'][:16]}")
        completed = list(cp['completed_domains'].keys())
        current = cp.get('current_domain')
        if current:
            completed_display = completed + [f"{current} (in progress)"]
        else:
            completed_display = completed
        print(f"  Completed domains: {', '.join(completed_display) if completed_display else 'None'}")
        print()
        choice = input("  Resume this assessment? [y/n]: ").strip().lower()
        if choice == "y":
            resume_data = cp
            checkpoint_file = checkpoints[0]
        else:
            print()

    if not resume_data:
        print_header()
        print("  This assessment evaluates your Vulnerability Management")
        print("  program maturity across 10 control domains.")
        print()
        print("  Maturity Levels:")
        for k, v in LEVELS.items():
            print(f"    {k} - {v}")
        print()
        print("  Tip: Enter 'q' at any question to save progress and quit.")
        print("       Run the script again to resume where you left off.")
        print()
        input("  Press Enter to begin...")

        customer = get_customer_info()
        completed_domains = {}
        resume_domain = None
        resume_responses = None
        checkpoint_file = Path(f"checkpoint_{customer['name'].replace(' ', '_')}_{customer['date']}.json")
    else:
        customer = resume_data["customer"]
        completed_domains = resume_data["completed_domains"]
        resume_domain = resume_data.get("current_domain")
        resume_responses = resume_data.get("current_responses", [])

    domains = list(ASSESSMENT.keys())

    for i, domain in enumerate(domains, 1):
        # Skip already completed domains
        if domain in completed_domains:
            print(f"  ✓ {domain} — already completed ({completed_domains[domain]['level']})")
            continue

        clear()
        print_header()
        print(f"  Domain {i} of {len(domains)}: {domain}")
        print(f"  Completed: {len(completed_domains)}/{len(domains)}")

        # Resume mid-domain if applicable
        if resume_domain == domain:
            print(f"  Resuming from question {len(resume_responses) + 1}...")
            responses = ask_questions(domain, ASSESSMENT[domain], checkpoint_file,
                                      customer, completed_domains,
                                      resume_responses=resume_responses)
            resume_domain = None
            resume_responses = None
        else:
            responses = ask_questions(domain, ASSESSMENT[domain], checkpoint_file,
                                      customer, completed_domains)

        if responses is None:
            # User quit — progress already saved in ask_questions
            sys.exit(0)

        score = calculate_domain_score(responses)
        completed_domains[domain] = {
            "score": score,
            "level": LEVELS[score],
            "responses": responses
        }

        # Save checkpoint after completing each domain
        save_checkpoint(checkpoint_file, customer, completed_domains)

        print(f"  ✓ {domain} scored: {score} - {LEVELS[score]}")
        input("  Press Enter to continue...")

    # All domains complete — calculate overall and save final JSON
    scores = [v["score"] for v in completed_domains.values()]
    overall = round(sum(scores) / len(scores), 1)
    overall_level = LEVELS[min(6, max(1, round(overall)))]

    results = {
        "customer": customer,
        "domains": completed_domains,
        "overall_score": overall,
        "overall_level": overall_level
    }

    filename = f"assessment_{customer['name'].replace(' ', '_')}_{customer['date']}.json"
    with open(filename, "w") as f:
        json.dump(results, f, indent=2)

    # Remove checkpoint file now that assessment is complete
    if checkpoint_file and Path(checkpoint_file).exists():
        Path(checkpoint_file).unlink()

    clear()
    print_header()
    print(f"  Assessment Complete!")
    print(f"  Customer: {customer['name']}")
    print(f"  Overall Maturity: {overall} - {overall_level}")
    print()
    print("  Domain Scores:")
    for domain, data in completed_domains.items():
        bar = "█" * data["score"] + "░" * (6 - data["score"])
        print(f"    {domain:<30} [{bar}] {data['score']} - {data['level']}")
    print()
    print(f"  Results saved to: {filename}")
    print(f"  Run: python3 generate_report.py {filename}")
    print()


if __name__ == "__main__":
    main()
