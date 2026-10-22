"""Offline, dependency-free threat model validator and report generator."""
import argparse
import csv
import html
import io
import json
from pathlib import Path

STRIDE = {'S': 'Spoofing', 'T': 'Tampering', 'R': 'Repudiation',
          'I': 'Information disclosure', 'D': 'Denial of service', 'E': 'Elevation of privilege'}

def rating(score):
    return 'Critical' if score >= 17 else 'High' if score >= 10 else 'Moderate' if score >= 5 else 'Low'

def validate(model):
    def require(condition, message):
        if not condition:
            raise ValueError(message)
    for field in ('title', 'summary', 'assumptions', 'vault_mapping', 'assets', 'components', 'boundaries', 'flows', 'threats', 'attack_paths'):
        require(field in model and bool(model[field]), f'Missing or empty field: {field}')
    indexes = {}
    for group in ('assets', 'components', 'boundaries', 'flows', 'threats', 'attack_paths'):
        require(isinstance(model[group], list), f'{group} must be a list')
        ids = [item['id'] for item in model[group]]
        require(all(isinstance(x, str) and x for x in ids), f'Invalid ID in {group}')
        require(len(set(ids)) == len(ids), f'Duplicate ID in {group}')
        indexes[group] = set(ids)
    for component in model['components']:
        require(component['boundary'] in indexes['boundaries'], f"Unknown boundary in {component['id']}")
    for flow in model['flows']:
        require(flow['source'] in indexes['components'] and flow['target'] in indexes['components'], f"Unknown component in {flow['id']}")
        require(bool(flow['authorization']), f"Authorization missing in {flow['id']}")
    for threat in model['threats']:
        tid = threat['id']
        require(bool(threat['assets']) and set(threat['assets']) <= indexes['assets'], f'Unknown or empty assets in {tid}')
        require(bool(threat['boundaries']) and set(threat['boundaries']) <= indexes['boundaries'], f'Unknown or empty boundaries in {tid}')
        require(bool(threat['stride']) and set(threat['stride']) <= STRIDE.keys(), f'Invalid STRIDE in {tid}')
        for field in ('scenario', 'weakness', 'impact', 'owner', 'validation'):
            require(bool(threat[field]), f'{field} missing in {tid}')
        for field in ('likelihood', 'impact_score', 'target_likelihood', 'target_impact'):
            require(type(threat[field]) is int and 1 <= threat[field] <= 5, f'{field} must be integer 1..5 in {tid}')
        for stage in ('prevent', 'detect', 'respond', 'recover'):
            require(bool(threat['controls'][stage]), f'{stage} controls missing in {tid}')
        require(threat['status'] in ('proposed', 'validated'), f'Invalid status in {tid}')
        require(threat['status'] != 'validated' or bool(threat.get('evidence')), f'Validated threat requires evidence in {tid}')
    for path in model['attack_paths']:
        require(bool(path['threats']) and set(path['threats']) <= indexes['threats'], f"Unknown or empty threats in {path['id']}")
        require(len(path['steps']) >= 2 and bool(path['breakpoints']), f"Incomplete attack path {path['id']}")
    return model

def scored_threats(model):
    result = []
    for t in model['threats']:
        t = dict(t)
        t['inherent_score'] = t['likelihood'] * t['impact_score']
        t['target_score'] = t['target_likelihood'] * t['target_impact']
        # Proposed controls do not reduce the current score.
        t['current_score'] = t['target_score'] if t['status'] == 'validated' else t['inherent_score']
        t['current_rating'] = rating(t['current_score'])
        result.append(t)
    return sorted(result, key=lambda x: (-x['current_score'], x['id']))

def report(model, threats):
    lines = []
    def p(s=''): lines.append(s)
    def heading(s): p('\n## ' + s + '\n')
    def table(headers, rows):
        def cell(x): return str(x).replace('|', '\\|').replace('\n', ' ')
        p('| ' + ' | '.join(map(cell, headers)) + ' |')
        p('| ' + ' | '.join('---' for _ in headers) + ' |')
        for row in rows: p('| ' + ' | '.join(map(cell, row)) + ' |')
    p('# ' + model['title']); p('\n' + model['summary'])
    p('\nDesign exercise. This report does not discover cloud resources or confirm vulnerabilities. Threats and scores require human review.')
    heading('Executive priorities')
    for t in threats[:3]: p(f"- {t['id']} {t['scenario']} Current risk {t['current_score']} ({t['current_rating']}); owner: {t['owner']}.")
    heading('Assumptions and scope')
    for a in model['assumptions']: p('- ' + a)
    heading('Bank vault control mapping')
    table(['Vault element', 'Cloud protection'], [(x['vault'], x['cloud']) for x in model['vault_mapping']])
    heading('Assets')
    table(['ID', 'Asset', 'Classification', 'CIA priority', 'Owner'], [(x['id'], x['name'], x['classification'], x['cia'], x['owner']) for x in model['assets']])
    heading('Architecture components and boundaries')
    table(['ID', 'Component', 'Cloud', 'Boundary'], [(x['id'], x['name'], x['cloud'], x['boundary']) for x in model['components']])
    table(['Boundary', 'Trust decision'], [(x['id'], x['description']) for x in model['boundaries']])
    heading('Architecture map')
    p('```mermaid'); p('flowchart TD')
    for c in model['components']:
        label=html.escape(c['name'], quote=True)
        # Mermaid IDs use generated safe identifiers, never user-provided identifiers.
        p(f'  n{model["components"].index(c)}["{label}"]')
    ids={c['id']:i for i,c in enumerate(model['components'])}
    for i,f in enumerate(model['flows']): p(f'  n{ids[f["source"]]} -->|F{i+1}| n{ids[f["target"]]}')
    p('```')
    heading('Data flows')
    table(['ID', 'Direction', 'Data', 'Authorization'], [(f['id'], f['source']+' to '+f['target'], f['data'], f['authorization']) for f in model['flows']])
    heading('Risk method')
    p('Likelihood and impact use ordinal 1-5 scales. Likelihood: rare, unlikely, plausible, likely, expected under the assumed weakness. Impact: negligible, limited, material team disruption, major business harm, broad confidential-data loss or privileged compromise. Score = likelihood x impact. Low 1-4; Moderate 5-9; High 10-16; Critical 17-25. Targets are conditional on control validation. Proposed controls do not lower current risk. Scores are judgments, not measured probabilities.')
    heading('Threat register')
    table(['ID', 'STRIDE', 'Scenario', 'Assets / boundaries', 'Inherent', 'Current', 'Target', 'Status'], [(t['id'], '/'.join(t['stride']), t['scenario'], ', '.join(t['assets']+t['boundaries']), t['inherent_score'], str(t['current_score'])+' '+t['current_rating'], t['target_score'], t['status']) for t in threats])
    heading('Controls and validation')
    for t in threats:
        p('\n### '+t['id']+' '+t['scenario']+'\n')
        p('Weakness: '+t['weakness']);p('\nBusiness impact: '+t['impact']);p('\nOwner: '+t['owner'])
        for key in ('prevent', 'detect', 'respond', 'recover'): p('\n'+key.title()+': '+t['controls'][key])
        p('\nValidation: '+t['validation'])
        if t.get('evidence'): p('\nEvidence: '+t['evidence'])
    heading('Attack paths')
    for a in model['attack_paths']:
        p('\n### '+a['id']+' '+a['name']+'\n');p(' > '.join(a['steps']));p('\nThreats: '+', '.join(a['threats']));p('\nBreakpoints: '+a['breakpoints'])
    heading('Remediation and production gate')
    p('Before production: validate document authorization, federation claims and release integrity; test alert routing and clean restoration. Assign named owners. Review all remaining High/Critical risks with the security lead and business data owner. Record any acceptance, approver, compensating control and expiry. This generated report grants no approval.')
    heading('Incident response and recovery')
    p('Declare an incident and preserve evidence; isolate affected workloads and deny compromised principals in every cloud; assess source documents read or modified; fix root causes and rebuild clean artifacts; restore trusted source versions and ACLs, reindex and verify authorization before reopening. Removing trust alone may not invalidate issued sessions. Backups do not undo disclosure. Proposed recovery targets: RTO 4 hours and RPO 24 hours, pending business approval and restore testing.')
    heading('Source and limitations')
    p('Based on the supplied Day-1-10.pdf Phase 1 Security Mindset Reset, especially the capstone requirements on PDF page 8, and the user-provided bank-vault analogy. The sample is an illustrative Azure/AWS/GCP GenAI design, not a live assessment. No provider credentials, network access or LLM API is required. The generator formats analyst-authored threats; it does not infer security completeness.')
    return '\n'.join(lines)+'\n'

def generate(model, destination):
    validate(model)
    threats=scored_threats(model)
    destination=Path(destination);destination.mkdir(parents=True,exist_ok=True)
    md=report(model,threats)
    (destination/'threat-model.md').write_text(md,encoding='utf-8')
    # Escaped source provides a safe, portable print view without external JavaScript.
    content='<!doctype html><html lang="en"><meta charset="utf-8"><title>Threat model report</title><style>body{max-width:1100px;margin:40px auto;padding:24px;font:15px/1.6 system-ui;color:#163047}pre{white-space:pre-wrap;overflow-wrap:anywhere} @media print{body{margin:0;padding:0;font-size:10pt}}</style><h1>Multi-Cloud Threat Model</h1><p>Readable source report. Open the Markdown file in a Mermaid-capable viewer for the architecture diagram. Use Print to save this view as PDF.</p><pre>'+html.escape(md)+'</pre></html>'
    (destination/'threat-model.html').write_text(content,encoding='utf-8')
    (destination/'risk-register.json').write_text(json.dumps(threats,indent=2)+'\n',encoding='utf-8')
    with (destination/'risk-register.csv').open('w',newline='',encoding='utf-8') as f:
        writer=csv.writer(f);writer.writerow(['id','scenario','owner','inherent_score','current_score','current_rating','target_score','status'])
        for t in threats:
            vals=[t[k] for k in ('id','scenario','owner','inherent_score','current_score','current_rating','target_score','status')]
            # Neutralize formula prefixes when opening analyst input in spreadsheets.
            writer.writerow(["'"+v if isinstance(v,str) and v.startswith(('=','+','-','@','\t','\r')) else v for v in vals])
    return threats

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('model',type=Path,help='Analyst-authored model JSON')
    parser.add_argument('--out',type=Path,default=Path('reports'))
    parser.add_argument('--validate-only',action='store_true')
    args=parser.parse_args()
    try:
        model=json.loads(args.model.read_text(encoding='utf-8'))
        validate(model)
        if args.validate_only: print('Model validation passed.'); return
        threats=generate(model,args.out)
    except (OSError,ValueError,KeyError,TypeError) as exc:
        parser.exit(2,f'Model error: {exc}\n')
    print(f'Generated 4 reports in {args.out.resolve()} from {len(threats)} threats.')

if __name__=='__main__':main()
