# Viva preparation notes

Maps each claim in the synopsis to where it is implemented, and prepares answers for
the questions an examiner is most likely to ask.

---

## Synopsis → code map

| Synopsis section | Claim | Where it lives |
|---|---|---|
| Abstract | RF / SVM / LogReg / XGBoost | `app/ml/train.py` → `build_models()` |
| Abstract | TF-IDF, tokenisation, stop-word removal, stemming | `app/ml/preprocessing.py` |
| Abstract | Confidence score generation | `app/ml/predict.py` → `predict_one()` |
| Abstract | Web-based dashboard | `frontend/src/pages/` |
| §III Problem | Self-adaptive framework | `app/routers/admin.py` → `_merge_feedback()` |
| §IV 4.1.1 | Data collection layer | `data/generate_dataset.py` |
| §IV 4.1.2 | Preprocessing + ML analytics layer | `app/ml/features.py`, `train.py` |
| §IV 4.1.3 | Prediction + dashboard layer | `app/routers/predict.py`, frontend |
| §IV 4.4 | Use cases: register, search, upload, view results | `routers/auth.py`, `predict.py`, `history.py` |
| §IV 4.4 | Admin: manage dataset, train/update models, view reports | `routers/admin.py` |
| §V Outcome | Model comparison, reduced false positives | `train.py` selection rule, `/api/predict/compare` |
| §V Outcome | Confidence scores + security recommendations | `app/ml/explain.py` |

---

## Likely questions

### "Why is the dataset synthetic? Isn't that cheating?"

There is no public, redistributable Play Store dataset with reliable genuine/fake
labels. The alternatives were: scrape one (legally and practically fragile, and still
unlabelled), or generate one that encodes the fraud indicators reported in the
literature.

The important part is what was done to keep it honest. The first version was **too
easy** — all four models scored an identical F1 of 0.9573, which is a leakage signature,
not a good result. Diagnosis showed the review vocabularies were disjoint: genuine apps
only ever received long thoughtful reviews, fakes only received `"Nice app!!!"`. TF-IDF
separated the classes perfectly, so the models learned nothing transferable.

The fix was to make both classes draw from **overlapping** pools and add two hard-case
populations (see below). After that the models diverged and F1 settled at ~0.969, with
the residual errors concentrated in the ambiguous cases rather than in label noise.

The pipeline accepts any CSV with the same schema, so swapping in real data is a
one-flag change.

### "Why do you deliberately include apps that are hard to classify?"

Two populations exist purely to prevent shortcut learning:

- **Sophisticated fakes** — coherent description, 2–3 excess permissions, plausible
  rating. Without these, "spammy wording" becomes a sufficient condition for *fake*.
- **Scruffy-but-genuine indies** — one app, no website, no privacy policy, low rating,
  small binary. Without these, the model learns *"solo developer = fraud"*, which is the
  exact false-positive problem §III of the synopsis criticises in prior work.

### "Why did you pick SVM when XGBoost had the same F1?"

The selection rule is highest F1, ties broken on the **lower false-positive rate**.
SVM and XGBoost tie on both metrics here; SVM wins on ordering and is ~40× faster to
train (7s vs 142s), which matters for the retraining loop.

The deeper point: accuracy is the wrong headline metric for this problem. Telling a
user that a legitimate banking app is fake causes more harm than missing one
counterfeit, because it destroys trust in every future verdict the tool gives.

### "How do you know the model isn't just memorising?"

Three checks:

1. Stratified 5-fold cross-validation on the training split, reported alongside the
   held-out test metrics.
2. 2% deliberate label noise, so a model that reaches 100% is overfitting by definition.
3. The independent rule engine. If the model's probability and the rule score diverge
   sharply on a case, that is surfaced rather than hidden — a memorising model would
   disagree with the rules far more often.

### "What does 'explainable' actually mean here? Did you use SHAP?"

No — deliberately. Three reasons:

1. The selected model changes between training runs, and SHAP's explainer differs per
   model family. A rules layer produces one consistent output regardless.
2. Every rule maps to a citable fraud indicator, so each finding survives the question
   *"why did it say that?"*.
3. It runs in microseconds, which the real-time requirement needs.

The **model still decides the verdict**. The rules explain and corroborate it, and
`model_alignment` reports when the two disagree.

### "Show me the self-adaptive loop."

`Scan → user flags wrong verdict → /api/feedback → admin reviews →
_merge_feedback() folds accepted rows into the dataset → background retraining →
ml.load(force=True) hot-swaps the artifact.`

Corrections need admin acceptance before they can move the model — otherwise anyone
could poison it by mass-reporting. Rejected feedback stays in the audit trail.

### "Why not use androguard for the APK parsing?"

Androguard pulls ~40 MB of transitive dependencies (cryptography, asn1crypto, a full
DEX disassembler) for one job: reading permissions. The custom parser decodes only the
binary manifest's string constant pool — every declared permission appears there
verbatim as `android.permission.XXX`, because AXML stores all attribute values as
string-pool references.

It handles UTF-8 and UTF-16 pools, and degrades gracefully on obfuscated manifests
where a strict tree parser would throw. Tested against both encodings plus three
malformed-input cases.

**Be honest about the limit:** it reports permissions *declared*, not permissions
*used at runtime*, and it does not decompile DEX — so a dynamically-loaded payload is
invisible to it.

### "What would you do with more time?"

In priority order: retrain on real labelled Play Store data; add DEX analysis to catch
dynamically-loaded payloads; replace lexicon sentiment with a fine-tuned transformer
for multilingual reviews; add drift monitoring so the admin is alerted when live
prediction distributions shift away from the training distribution.

---

## Demo script (5 minutes)

1. **Sign in** as admin. Point out the seeded account.
2. **Scan → Load example** → *Scan app*. Verdict lands at ~98.8% fake, Critical band.
3. **Point at the risk spine.** Two markers: the model score and the independent rule
   score. This is the piece to talk about — a single number would hide disagreement.
4. **Scroll the findings.** 17 risk signals, grouped, each with a severity and a
   reason in plain language. Read out the SMS permission one.
5. **Compare all models** → shows all four agreeing. Agreement across four models is
   stronger evidence than any single score.
6. **Download PDF report.**
7. **Upload APK** tab → analyse a real APK → show that permissions were read from the
   binary manifest, not typed in.
8. **Analytics** → distribution, top signals, per-category breakdown.
9. **Administration** → model comparison table with the false-positive column, pending
   corrections, *Retrain model*.

---

## Numbers to have memorised

- 6,000 apps · 65% genuine / 35% fake · 2% label noise
- 3,323 features = 3,000 TF-IDF (description) + 1,500 (reviews) capped by `min_df`,
  plus 41 engineered + 10 category
- Selected model: SVM · F1 0.9693 · ROC-AUC 0.9751 · FPR 0.91%
- 41 engineered features across 5 families
- ~20 explainability rules across 5 groups
- Inference: single-digit milliseconds after model warm-up at boot
