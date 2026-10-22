# Phase 1 Multi-Cloud Threat Model in Python

A runnable, offline capstone project for Mahesh Dommati. Model an Azure/AWS/GCP enterprise GenAI assistant using the bank-vault analogy. Demonstrate assets, identities, data flows, trust boundaries, STRIDE threats, risk prioritization, controls, attack paths, and recovery.

## Requirements

Python 3.10 or newer. Uses only the Python standard library. No installation, cloud account, API key, subscription, or network access required.

## Run

Extract this ZIP, open a terminal in the `multi-cloud-threat-model` folder and run:

```bash
python threat_model.py examples/vault-genai.json --validate-only
python threat_model.py examples/vault-genai.json --out reports
python -m unittest discover -s tests -v
```

On Windows use `py` if `python` is unavailable; on macOS/Linux use `python3` if needed. Open `reports/threat-model.html` in a browser. Open the Markdown file in a Mermaid-capable Markdown viewer to render the architecture diagram. The HTML is an escaped, printable source view; it does not render Mermaid. Print from the browser to save a PDF if desired.

## GitHub Actions

The workflow in `.github/workflows/python-ci.yml` runs on pushes, pull requests, and manual dispatch. It uses Python 3.10 to validate the sample model and run the unit tests. It does not publish reports or deploy to a cloud provider.

## What you submit

- `examples/vault-genai.json`: your reviewed system model.
- `reports/threat-model.md`: executive summary, assets, architecture diagram, flows, boundaries, threat register, controls, attack paths and response/recovery.
- `reports/threat-model.html`: portable print view.
- `reports/risk-register.csv`: sortable risk register with owners and scores.
- `reports/risk-register.json`: full scored threats for further tooling.
- Python source and passing test output.

Generated sample reports are included. Running the command overwrites files with these names in the output folder; choose a new output folder to preserve an earlier report.

## How the project works

1. An analyst defines assets, components, flows, boundaries, threats and controls in JSON.
2. Python validates IDs, references, scores, STRIDE categories, control coverage and validation evidence.
3. It calculates and sorts current risk and conditional residual targets.
4. It exports a reproducible report and machine-readable risk registers.

This is an analyst-driven report generator, not an automated vulnerability scanner, AI threat discovery service or completeness guarantee. Validation checks structure and references, not whether controls actually work. Status `validated` is an analyst assertion backed by an evidence reference; the program cannot verify the evidence.

## Customize your model

Copy `examples/vault-genai.json`, then replace the assumptions and sample system with your real design. Update assets and owners first, components and trust boundaries next, then flows, threats and attack paths. All references must match existing IDs. A component has one primary boundary; additional crossed boundaries are represented in the threat records and described in flow authorization.

Each threat requires:

- Unique `id`; one or more `stride` values (`S`, `T`, `R`, `I`, `D`, `E`).
- `scenario`, `weakness`, business `impact`, `assets`, `boundaries`, `owner`.
- Integer `likelihood`, `impact_score`, `target_likelihood`, `target_impact` from 1 to 5.
- `controls` containing `prevent`, `detect`, `respond`, `recover`.
- A concrete `validation` test.
- `status`: `proposed` or `validated`; nonempty `evidence` is mandatory for validated records.

Risk = likelihood x impact. Low 1-4, Moderate 5-9, High 10-16, Critical 17-25. Proposed controls never lower current risk. The conditional target becomes current only after you explicitly mark controls validated and supply evidence. All sample controls are proposed. Do not mark validated merely to achieve a desired rating.

## A practical capstone workflow

1. Confirm business purpose, data classification, regions, provider contracts and architecture assumptions.
2. Draw the flows and identify where identity or authorization changes.
3. Review every boundary against all six STRIDE categories; document applicability and gaps in your review notes.
4. Describe weaknesses as assumptions until verified. Connect each scenario to business impact.
5. Review the four included multi-step attack paths and add project-specific ones.
6. Assign named owners and test controls in an authorized lab; store evidence outside sensitive report content.
7. Re-score risk, agree remediation/acceptance decisions and regenerate the deliverable.

## Demo script

- Explain why private networking alone does not protect the vault.
- Run validation and generation; show the architecture and T1-T11.
- Show T2: a legitimate employee must not retrieve another group's documents.
- Show T3: a valid cloud token still needs narrow cross-cloud permission.
- Show T5: release integrity protects workload credentials and data.
- Explain why proposed controls do not reduce current scores.
- Run tests and describe negative authorization tests, alert drills and restore evidence needed for production.

## Scope and limitations

The sample assumes Azure application/model services, AWS source documents and GCP ingestion/retrieval. No actual cloud environment was inspected. Controls, scores, detection thresholds, owners and RTO/RPO are illustrative proposals. Exact services and federation mechanisms must be selected and verified before implementation. The report does not provision infrastructure, execute attack paths, collect secrets or query cloud APIs. Avoid adding credentials, raw prompts or confidential document contents to model files or evidence strings.

The model is based on the supplied `Day-1-10.pdf` Phase 1 Security Mindset Reset, especially the deliverable requirements on PDF page 8, plus the bank-vault analogy. The original attachment is not redistributed in this project. STRIDE is used as an organizing method; risk scores are ordinal judgments. This project grants no production approval or compliance certification.
