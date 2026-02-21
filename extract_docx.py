"""Extract text from DSCM_v2_final.docx for processing."""
import os
import sys
import zipfile
import xml.etree.ElementTree as ET

def extract_docx_text(path):
    ns = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
    with zipfile.ZipFile(path, 'r') as z:
        xml_content = z.read('word/document.xml')
    root = ET.fromstring(xml_content)
    paragraphs = []
    for p in root.iter('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}p'):
        texts = []
        for t in p.iter('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t'):
            if t.text:
                texts.append(t.text)
            if t.tail:
                texts.append(t.tail)
        para = ''.join(texts).strip()
        if para:
            paragraphs.append(para)
    return '\n'.join(paragraphs)

base = os.path.dirname(os.path.abspath(__file__))
search_paths = [
    os.path.join(base, 'Alexandra', 'DSCM_v2_final.docx'),
    os.path.join(base, 'DSCM_v2_final.docx'),
    os.path.expanduser(r'~\DSCM_v2_final.docx'),
    r'C:\Users\Alexandra\DSCM_v2_final.docx',
    r'C:\Users\Alexandra\OneDrive\Рабочий стол\Прогер\DSCM_v2_final.docx',
]

for p in search_paths:
    if os.path.isfile(p):
        text = extract_docx_text(p)
        out_path = os.path.join(base, 'DSCM_v2_final_extracted.txt')
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(text)
        print(f"Extracted to {out_path}")
        sys.exit(0)

print("File not found in any search path", file=sys.stderr)
sys.exit(1)
