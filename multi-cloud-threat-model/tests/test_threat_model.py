import copy
import json
import tempfile
import unittest
from pathlib import Path
import threat_model as tm

MODEL=Path(__file__).resolve().parents[1]/'examples/vault-genai.json'
class ModelTests(unittest.TestCase):
    def setUp(self): self.model=json.loads(MODEL.read_text())
    def test_rating_boundaries(self):
        self.assertEqual([tm.rating(s) for s in (1,4,5,9,10,16,17,25)],['Low','Low','Moderate','Moderate','High','High','Critical','Critical'])
    def test_unknown_asset_rejected(self):
        self.model['threats'][0]['assets']=['unknown']
        with self.assertRaises(ValueError): tm.validate(self.model)
    def test_out_of_range_rejected(self):
        self.model['threats'][0]['likelihood']=6
        with self.assertRaises(ValueError): tm.validate(self.model)
    def test_proposed_controls_do_not_reduce_current_risk(self):
        for t in tm.scored_threats(self.model): self.assertEqual(t['current_score'],t['inherent_score'])
    def test_validated_requires_evidence(self):
        self.model['threats'][0]['status']='validated'
        with self.assertRaises(ValueError): tm.validate(self.model)
        self.model['threats'][0]['evidence']='Lab test record 123, reviewed by owner'
        tm.validate(self.model)
        t=next(t for t in tm.scored_threats(self.model) if t['id']=='T1')
        self.assertEqual(t['current_score'],10)
    def test_exports_and_safe_html(self):
        self.model['summary']='<script>alert(1)</script>'
        with tempfile.TemporaryDirectory() as d:
            tm.generate(self.model,d)
            self.assertEqual(len(list(Path(d).iterdir())),4)
            text=(Path(d)/'threat-model.html').read_text()
            self.assertNotIn('<script>',text)
            self.assertIn('&lt;script&gt;',text)
            self.assertEqual(len(json.loads((Path(d)/'risk-register.json').read_text())),11)
if __name__=='__main__':unittest.main()
