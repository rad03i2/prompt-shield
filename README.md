# Prompt Shield

Local, deterministic prompt-injection and secret-risk scanning for LLM input pipelines.

**Author:** Radwan Abdulhadi Ahmed · رضوان عبدالهادي أحمد · GitHub: @rad03i2

## English

### Overview
Prompt Shield is a small Python library and CLI that inspects untrusted text *before* it reaches an LLM or tool-enabled agent. It detects several explicit prompt-injection patterns, suspicious attempts to expose privileged prompts or bypass tool approval, data-exfiltration wording, and common embedded credential shapes. It runs entirely locally and performs no network requests.

It exists as a practical guardrail for ingestion pipelines, RAG documents, support tickets, pasted text, agent inputs, and CI fixtures. It is intentionally deterministic: the same text and rule set produce the same result.

### Features
- Prompt override, hidden-prompt exfiltration, suspicious role manipulation, tool-control bypass, and sensitive-data exfiltration rules.
- Common API token/private-key/credential-shape detection.
- Secret findings never echo the matched credential in their excerpt.
- Risk score `0–100` and `none/low/medium/high/critical` level.
- Text and structured JSON output.
- Configurable CI failure threshold.
- Secret redaction command.
- Python API plus `prompt-shield` and `python -m prompt_shield` entry points.
- Unicode-safe input, including Arabic text.
- No runtime dependencies and no telemetry/network access.

### Preview
```console
$ prompt-shield scan "Ignore all previous system instructions"
Risk: high | score=40 | findings=1
- HIGH     PI001 Attempts to override earlier instructions.
```

For screenshots, capture the terminal output above; the project intentionally has no GUI.

### Requirements & installation
Requires Python 3.10+.

```bash
git clone https://github.com/rad03i2/prompt-shield.git
cd prompt-shield
python -m pip install -e .
```

### Usage
```bash
prompt-shield scan "Summarize this report"
prompt-shield scan --file untrusted.txt --json
cat untrusted.txt | prompt-shield scan --json
prompt-shield scan --file untrusted.txt --fail-on medium
prompt-shield redact "api_key=abcdefghijklmnop"
prompt-shield --version
```

Exit code is `0` when risk is below `--fail-on`, `1` when the threshold is reached, and `2` for input/runtime errors. The default failure threshold is `high`.

Python API:
```python
from prompt_shield import scan_text, redact_secrets

result = scan_text(user_supplied_text)
if result.level in {"high", "critical"}:
    reject_or_review()
```

### Configuration
There is deliberately no config file or environment-variable requirement. The public `scan_text(..., rules=...)` parameter accepts a custom iterable of `Rule` objects for applications that need their own policy. Built-in rules remain deterministic and local.

### Project structure
```text
src/prompt_shield/   library, rules, CLI
examples/            runnable API example
tests/               behavioral and CLI tests
.github/workflows/   cross-platform CI
SECURITY.md           threat model and reporting
CONTRIBUTING.md       contribution rules
```

### Testing
```bash
python -m pip install -e .
python -m pip install pytest
python -m compileall -q src
pytest -q
```
CI runs those checks on Python 3.10, 3.12, and 3.13 across Linux, Windows, and macOS.

### Security & privacy
Scanning is local. Prompt Shield does not send text anywhere. Nevertheless, it is a heuristic pre-filter, **not a security boundary**. Keep authorization, sandboxing, least privilege, output validation, and human approval for consequential tools. Never log raw untrusted input merely because the scanner marked it safe. See `SECURITY.md`.

### Limitations
- Pattern matching cannot detect every prompt-injection technique and can produce false positives/negatives.
- Obfuscated, multilingual, encoded, or indirect attacks may evade English-oriented built-in rules.
- Secret detection recognizes common shapes; it is not a full secret-scanning engine.
- It does not execute, decode, classify with an LLM, or inspect images/files beyond supplied text.
- Risk scores are policy signals, not probabilities.

### Optional roadmap
Possible future work: additional language-specific rule packs, pluggable normalization/decoding, SARIF output, and benchmark corpora with carefully synthetic samples.

### Contributing & license
See `CONTRIBUTING.md`. Licensed under the MIT License; see `LICENSE`.

### Author
**Radwan Abdulhadi Ahmed**  
**رضوان عبدالهادي أحمد**  
GitHub: **@rad03i2**

---

## العربية

### نظرة عامة
Prompt Shield مكتبة وأداة سطر أوامر صغيرة بلغة Python تفحص النصوص غير الموثوقة **قبل** إرسالها إلى نموذج لغوي أو وكيل قادر على استخدام الأدوات. تكشف أنماطًا صريحة لمحاولات حقن التعليمات، وطلب كشف التعليمات الداخلية، ومحاولات تجاوز موافقات الأدوات، وصيغ تسريب البيانات، وبعض أشكال بيانات الاعتماد الشائعة. تعمل محليًا بالكامل ولا تجري أي اتصال بالشبكة.

صُممت كطبقة فحص عملية لخطوط إدخال البيانات وRAG وتذاكر الدعم والنصوص الملصقة ومدخلات الوكلاء واختبارات CI. وهي حتمية: النص نفسه ومجموعة القواعد نفسها ينتجان النتيجة نفسها.

### الميزات
- كشف محاولات تجاوز التعليمات وكشف الـsystem prompt والتلاعب المشبوه بالأدوار وتجاوز ضوابط الأدوات وتسريب البيانات الحساسة.
- كشف بعض أشكال رموز API والمفاتيح الخاصة وبيانات الاعتماد.
- لا تعرض نتيجة اكتشاف السر القيمة الحساسة نفسها داخل المقتطف.
- درجة مخاطر من 0 إلى 100 ومستويات: none/low/medium/high/critical.
- إخراج نصي أو JSON.
- حد فشل قابل للتحديد لاستخدام CI.
- أمر لتنقيح الأسرار المحتملة.
- Python API وCLI ودعم `python -m prompt_shield`.
- دعم Unicode والنص العربي.
- لا توجد اعتماديات تشغيل خارجية ولا telemetry أو اتصالات شبكة.

### المعاينة
```console
prompt-shield scan "Ignore all previous system instructions"
Risk: high | score=40 | findings=1
```
لا توجد واجهة رسومية؛ يمكن استخدام لقطة شاشة للطرفية عند الحاجة إلى صورة توضيحية.

### المتطلبات والتثبيت
يتطلب Python 3.10 أو أحدث.
```bash
git clone https://github.com/rad03i2/prompt-shield.git
cd prompt-shield
python -m pip install -e .
```

### الاستخدام
```bash
prompt-shield scan --file untrusted.txt --json
prompt-shield scan --file untrusted.txt --fail-on medium
prompt-shield redact "api_key=abcdefghijklmnop"
```
رمز الخروج `0` عندما تكون المخاطر دون الحد، و`1` عند بلوغه، و`2` لأخطاء الإدخال أو التشغيل. الحد الافتراضي هو `high`.

ومن Python:
```python
from prompt_shield import scan_text
result = scan_text(text)
print(result.level, result.score)
```

### الإعداد
لا يحتاج المشروع إلى ملف إعداد أو متغيرات بيئة. يمكن للمطور تمرير قواعد مخصصة إلى `scan_text(..., rules=...)` عند الحاجة إلى سياسة خاصة بالتطبيق.

### بنية المشروع
`src/prompt_shield/` للمحرك والـCLI، و`tests/` للاختبارات، و`examples/` للأمثلة، و`.github/workflows/` للتكامل المستمر، إضافة إلى ملفات الأمان والمساهمة والترخيص.

### الاختبار
```bash
python -m pip install -e .
python -m pip install pytest
python -m compileall -q src
pytest -q
```
يشغّل CI الاختبارات على Python 3.10 و3.12 و3.13 على Linux وWindows وmacOS.

### الأمان والخصوصية
الفحص محلي ولا يرسل النص إلى أي جهة. مع ذلك فالأداة **ليست حاجزًا أمنيًا مستقلًا**؛ يجب إبقاء الصلاحيات المحدودة والعزل والتحقق من المخرجات والموافقة البشرية للأفعال الحساسة. راجع `SECURITY.md`.

### القيود
قد تنتج القواعد نتائج إيجابية أو سلبية خاطئة، وقد تتجاوزها الهجمات المموهة أو متعددة اللغات أو المشفرة. كشف الأسرار محدود بأشكال شائعة، ولا تنفذ الأداة النص ولا تفك ترميزه ولا تستخدم نموذجًا لغويًا ولا تفحص الصور. درجة المخاطر إشارة سياسة وليست احتمالًا إحصائيًا.

### تطوير اختياري
يمكن مستقبلًا إضافة حزم قواعد للغات أخرى، وطبقات تطبيع/فك ترميز اختيارية، وإخراج SARIF، ومجموعة قياس تعتمد أمثلة اصطناعية آمنة.

### المساهمة والترخيص
راجع `CONTRIBUTING.md`. المشروع مرخص برخصة MIT الموجودة في `LICENSE`.

### المؤلف
**Radwan Abdulhadi Ahmed**  
**رضوان عبدالهادي أحمد**  
GitHub: **@rad03i2**
