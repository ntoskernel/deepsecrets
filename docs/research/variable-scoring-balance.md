# Variable-scoring balance: measured against SecretBench

Date: 2026-09-10. Branch `2.1-dev`. Scope: `deepsecrets/rules/variable_scoring_rules.json`, `deepsecrets/core/helpers/variable_evaluator.py`, and the naturalness score they consume.

The question: were the rule scores, which were set by hand, balanced against each other, and if not, what should change? Short answer: the decision threshold sits near a reasonable operating point, but that is an accident of double counting. Most measurable gains come from fixing rule patterns and collapsing duplicate evidence, not from retuning numbers.

## How the scorer decides

- A variable is dangerous when the sum of fired rule scores is above 0 (`variable_evaluator.py:99`). Evaluation stops as soon as the running sum reaches -100 (`:69`), and a value with zero entropy is never dangerous (`:78`).
- Entropy does not take part in that decision. It only shapes the reported confidence (`confidence_from_evaluation_result`, `:105-134` at the time of the study, `:105-114` after the monotonic rewrite).
- The SARIF output groups confidence into tiers: LOW below 3, MEDIUM 3 to 5, HIGH 6 to 8, VERY-HIGH 9 and above (`deepsecrets/core/model/response/dojo_sarif.py:50-80`).

## Data and method

| Item | Value |
| --- | --- |
| Labels | `/secretbench/secretbench.csv`: 97,479 candidates (15,086 `Y`, 82,393 `N`) with file, line and value |
| Corpus | `/secretbench/bench/Files` |
| Sample | 25,000 files with at least one candidate (random, seed 42): 22,400 processed, 2,515 over 1 MB skipped, 85 timed out |
| Variables | Everything the production tokenizers hand to `SemanticEngine` (`LexerTokenizer(deep_token_inspection=True)` plus `CheapVarSearchTokenizer`, same length-1 and space filters) |
| Labelling | A variable is `Y`/`N` when its value matches a candidate on the same line, either exactly or covering at least half of it after the harness normalisation. Other variables are unlabelled background (`BG`). |
| Background sampling | All background variables the current rules flag, plus 3% of the rest (weighted back up). They stand for about 4.7 million variables. |
| De-duplication | One row per (repository, name, value): 152,345 rows, 1,595 `Y`, 6,511 `N`, 566 repositories |
| Split | 70/30 by repository hash. Changes were chosen on the train split and are reported on the held-out split. |

Three measures are reported throughout: recall on `Y`, false-positive rate on `N` (hard negatives chosen by the SecretBench annotators), and background alerts per 1,000 variables, which estimates how noisy the result is.

Caveats:

- Background is unlabelled. SecretBench's candidate generation missed things, and some flagged background variables are real secrets; see the password sample below.
- `Y` is concentrated: 801 of 1,595 are private keys, mostly 64-hex keys from one repository (libra). The numbers were re-run with at most 25 labelled rows per repository; conclusions did not change.
- SecretBench's own labels are debatable in places: several libra `*_public_key` values and some `client_id`/`app_id` values are labelled `Y`.
- File paths were rebuilt from the CSV's `file_path` column so that `SEM_VAR_FILE_PATHS` sees `/tests/`-style paths.

## Current performance

| Split | Recall `Y` | FPR `N` | Background alerts / 1k | `Y` share among labelled flags |
| --- | --- | --- | --- | --- |
| All | 0.869 | 4.8% | 0.79 | 0.82 |
| Held-out | 0.820 | 4.9% | 0.64 | 0.76 |

Of the 209 missed `Y` variables, 124 match no positive name rule at all (names such as `Id`, `url`, `hash`, `webhook_url`, `appId`, `clientId`, `SentryUrl`). About 70 are blocked by red-flag rules. Only 3 are blocked by the natural-language rule. `Username` and `Database and Server URL` candidates are never flagged. Those belong to the regex engine rather than to variable scoring.

## Findings

### 1. Refitting the existing weights does not help

A weighted logistic regression over the same rule features, with its threshold set to the current background alert rate, reaches held-out recall between 0.808 and 0.834. The variant with more recall than today (0.834) raises the `N` FPR to 6.6%; the one with a lower FPR (4.5%) also has lower recall (0.808). Adding entropy buckets as features gives 0.840 recall at a 7.6% `N` FPR. With the per-repository cap, every refit has lower recall than the current rules. Retuning numbers on today's rules is not where the gains are.

### 2. Name evidence is counted two to six times

Each concept has a "slices" rule and a "full name" rule, and the `key`/`token` rules stack on top. Name-only scores for a neutral random value:

| Name | Score | Name | Score |
| --- | --- | --- | --- |
| `password`, `secret`, `client_secret` | 25 | `api_key` | 60 |
| `db_password` | 31 | `API_TOKEN`, `auth_token`, `csrf_token` | 68 |
| `secret_key`, `private_key` | 40 | `access_token` | 78 |
| `<vendor>_key` (`sendgrid_key`) | 15 | `aws_secret_access_key` | 85 |
| `token` | 17 | `key` | 7 |
| `credentials`, `auth`, `bearer`, `dsn` | 0 | `session_id` | -20 |

Consequences:

- A single -50 value penalty removes any password-class name but not an api/token-class one.
- A generic `<vendor>_key` (+15) is cancelled by one red flag (-15/-20).
- A per-rule score says little about the evidence it carries.

Measured against labels, the likelihood ratio of each rule (`Y` vs `N`, ×10) is +21 to +36 for the high-confidence and token rules and +12 to +14 for the key rules, while the current scores range from +4 to +25. The -50 value penalties sit at an implied -20 (dummy) and -38 (natural). The sums work only because positive rules co-fire.

Collapsing each pair into one rule (`HIGH_CONFIDENCE_FULLNAME_1` = 40, `HIGH_CONFIDENCE_FULLNAME_2` = 30, both `SLICES` rules = 0) is the only single change that improves both sides: held-out recall rises from 0.820 to 0.843, with `N` FPR unchanged and background alerts 2% lower.

### 3. The natural-language penalty mostly means "has no digits"

Simulated random secrets (3,000 per cell):

| Alphabet | Length 8 | 16 | 24 | 40 |
| --- | --- | --- | --- | --- |
| lowercase letters | 95% rated natural | 99% | 100% | 100% |
| mixed-case alphanumeric | 23% | 5.4% | 1.6% | 0.1% |
| hex | 0% | 0% | 0% | 0% |

The mixed-case figure equals the chance that a random value has no digit. Values containing digits score 0 (KI-ENG-02).

On SecretBench the rule is nevertheless cheap and effective: it fires on 0.2% of `Y`, 10.1% of `N` and 41.9% of background, and costs 3 missed secrets.

For password-named variables with word values, SecretBench has no labels at all (0 `Y`, 0 `N` in the sample). The background shows what such variables hold: `password=admin`, `password=security`, `password=heslo`, `userpwd=agora`, `trustStorePassword=athenz`, and demo credentials for ofbiz and pulsar. These are real hardcoded passwords, mostly weak or default. Exempting password names from the penalty would flag them, adding about 8% background alerts and no measurable recall on labelled data. Keeping them at LOW confidence (a -25 penalty instead of -50, so the score lands at about 5 and confidence at 2) reports them without polluting the higher tiers. Whether to report them is a policy decision, not something the benchmark settles.

### 4. Pattern defects

Marginal effect of removing one alternative (all data; `+Y` and `+N` count variables that become flagged):

| Rule | Alternative | +Y | +N | Background | Why it misfires |
| --- | --- | --- | --- | --- | --- |
| `NAME_SLICE_REDFLAGS` | `str` | 8 | 0 | 0 | Hungarian-notation prefix (`strSecret1`) |
| `NAME_SLICE_REDFLAGS` | `last` | 3 | 0 | ~0 | `LastFMAPIKey` splits to `last fmapikey` |
| `NAME_SLICE_REDFLAGS` | `uri` | 2 | 0 | 0 | `formUriBasicAuthPassword` |
| `NAME_SLICE_REDFLAGS` | `open` | 1 | 0 | 0 | `openWeatherAPIKey`, `open_ai_key` |
| `NAME_SLICE_REDFLAGS` | `storage` | 1 | 0 | ~0 | `storage_key` |
| `FULLNAME_REDFLAGS` | `uri` | 3 | 0 | 0 | unanchored substring: `securityToken`, `security_key` |
| `FULLNAME_REDFLAGS` | `algo` | 1 | 0 | 0 | unanchored substring: `algoliaAdminKey` |
| `DUMMY_VALUES` | `.*day.*` | 3 | 0 | ~0 | random secrets that happen to contain "day" |
| `NAME_SLICE_REDFLAGS` | `public` | 3 | 188 | ~0 | keep |
| `NAME_SLICE_REDFLAGS` | `id` | 8 | 12 | ~0 | keep (mixed evidence) |

`FULLNAME_REDFLAGS` alternatives such as `data`, `type`, `name`, `path` and `algo` match anywhere in the normalised name, so `datadog_key`, `algolia_key` and `security_key` score 0 or below and can never be flagged. Anchoring all bare words at once (`^word$`) raises the `N` FPR from 4.8% to 7.8%, because several of those substring hits are correct by accident. For example, Algolia search keys are public and SecretBench labels them `N`. Fix them one alternative at a time.

Other defects:

- `SEM_VAR_DB_AS_PART_OF_NAME` (+6) has the wrong sign: it fires on 0.0% of `Y` and 0.7% of `N`. Disabling it changes nothing on `Y` and removes 0.6% of alerts.
- `SEM_VAR_FALSE_STARTING_SEQ` vetoes (-1000) values that start with `-` or `_`, which covers about 3% of random base64url secrets. No labelled `Y` or background variable in the sample depends on it. Dropping the two characters had no measured cost.
- `SEM_VAR_DUMMY_VALUES` ends with `[^A-Za-z0-9]*`, which matches the empty string. Normalisation strips whole-word digit runs, so every all-digit value (and about 2.5% of 8-character hex values) counts as a dummy. Making it `+` adds 6% alerts and no recall, because all-digit values are mostly noise. Keep the behaviour but document it; this is also why `token=12312312345645456` in `tests/fixtures/1.txt` is not reported.
- Dead or duplicated alternatives: `.*${.*` can never match (`$` is an anchor); `.*password.*` appears twice in `DUMMY_VALUES`, as do `public` and `list` in `NAME_SLICE_REDFLAGS`; `.*examp.*`/`.*exampl.*` and `.*serv.*`/`.*servi.*`/`.*service.*` overlap; `saving`, `threshold` and `.*urlkey.*` never fired in the sample.
- `SEM_VAR_VALUE_LENGTH` is named "less than 4 chars" but uses `<= 4`.

### 5. The confidence formula is not monotonic

For a fixed name score, a medium-entropy value gets lower confidence than a low-entropy one. Once entropy passes 3.0, the formula switches branch and caps the name part at 5:

| Name score | H=2.5 | H=3.5, gibberish | H=4.5, gibberish |
| --- | --- | --- | --- |
| 20 | 8 | 6 | 9 |
| 25 | 10 | 7 | 10 |

In practice the tiers are still ordered: the `Y` share among labelled flags is 33% (LOW, only 3 labelled rows), 36% (MEDIUM), 82% (HIGH) and 93% (VERY-HIGH). Confidence 10, the low-entropy branch, is less precise than 9 (90% against 94%) and carries more background alerts (576 against 260). A monotonic formula (name part up to 6, value-randomness part up to 4) places 1,033 `Y` in VERY-HIGH instead of 753, at the same 93% precision.

### 6. Small or neutral items

- `SEM_VAR_FILE_PATHS` (-5) carries almost no evidence (likelihood ratio about 1). Disabling it gains 1.1 recall points and adds 5.5% alerts. Leave it.
- Halving the red-flag scores (-10/-8) gains 3.5 recall points but adds 39% background alerts. Not worth it.
- The -100 early abort never changes a verdict today, because no name reaches +100. If a future rule pushes positive evidence past 100, rule order starts to matter.

## Recommendations

Ordered by measured value. Items 1 to 3 need no Python changes.

1. **Collapse duplicate name evidence**: `HIGH_CONFIDENCE_FULLNAME_1` = 40, `HIGH_CONFIDENCE_FULLNAME_2` = 30, both `SLICES` rules = 0 (or deleted after checking the patterns they uniquely match).
2. **Remove the misfiring alternatives**: `str`, `last`, `open`, `uri` and `storage` from `NAME_SLICE_REDFLAGS`; `uri` and `algo` from `FULLNAME_REDFLAGS`; `.*day.*` from `DUMMY_VALUES`. Also disable `DB_AS_PART_OF_NAME` and drop `-` and `_` from `FALSE_STARTING_SEQ`.

   Items 1 and 2 together, held-out: recall 0.820 → 0.846, `N` FPR 4.9% → 4.9%, background alerts 0.637 → 0.640 per 1k. On all data: +23 `Y`, -9 `N`, background unchanged within sampling noise.
3. **Hygiene** with no behaviour change: remove the dead and duplicated alternatives and fix the `VALUE_LENGTH` name.
4. **Password names with word values**: add condition support to `VariableScoringRule` (for example an `unless`/`when` list of `{target, pattern}` checks). Then give `NATURAL_LANGUAGE_VALUES` an exception for names ending in `password`/`passwd`/`pwd`, with a separate -25 rule for that case, so such values are reported at LOW confidence. Cost: about 8% more LOW-tier alerts. This resolves `tests/core/engines/semantic/test_semantic.py::test_ini_in_txt`.
5. **Monotonic confidence** (applied, see below): replace the two-branch formula so that more randomness never lowers confidence.
6. **Name coverage**: the largest remaining miss class (124 variables) is names with no positive rule. Candidates are `webhook`, `credentials`, `dsn` and `auth`/`bearer`. Measure each before adding it: SecretBench labels `client_id`/`app_id` both ways.
7. **Longer term**: the naturalness scorer should stop rating random letters-only strings as language. Fixing it moves every semantic count; see KI-ENG-02 and KI-BENCH-07.

## Applied changes

Recommendations 1, 2 and 4 were applied on 2026-09-10, with four adjustments that came out of measuring them:

| Change | Why |
| --- | --- |
| `FULLNAME_1` +40, `FULLNAME_2` +30, both `SLICES` rules and `DB_AS_PART_OF_NAME` disabled | Recommendations 1 and 2 |
| `str`, `last`, `open`, `uri`, `storage` removed from `NAME_SLICE_REDFLAGS`; `uri`, `algo` from `FULLNAME_REDFLAGS`; `.*day.*` from `DUMMY_VALUES`; `-` and `_` from `FALSE_STARTING_SEQ` | Recommendation 2 |
| `VariableScoringRule` gained `when` / `unless` conditions; `NATURAL_LANGUAGE_VALUES` skips names ending in `password`/`passwd`/`pwd`, and `NATURAL_LANGUAGE_PASSWORD_VALUES` (-24) handles them | Recommendation 4. The penalty is -24, not -25: a word-valued password under `/tests/` must stay above 0 after `FILE_PATHS` (-5), which is the case in `tests/fixtures/1.txt` |
| `.*hashed.*` added to `FULLNAME_REDFLAGS` | Adjustment: with password names at +30, the -20 `hashed` slice left `hashed_secret` (detect-secrets baselines) at +10 and moved about 170 of them from MEDIUM to HIGH. The extra -15 drops them, about 1,100 background alerts, with no `Y` lost |
| `pass$` added to `FULLNAME_2` | Adjustment: disabling the DB rule dropped `db_pass` from confidence 8 to 4. Re-enabling it would add 6 labelled false positives; treating a name ending in `pass` as a password changes nothing on SecretBench |
| New `NONSECRET_LAST_SLICE` (-30) with an `unless` for `accesskeyid$` | Adjustment: removing `uri` from the red flags let `oauth-redirect-uri` through, and the old rules already flagged `oauth_client_id`, `secret_id`, `password_length`, `password_hint`, `secret_arn` and `api_key_id` at confidence 6 to 10. The last word of a name says what the value is. Without the exemption the rule loses 21 AWS access key ids, which SecretBench labels as secrets |

Measured on the same data (`benchmarker/scoring_balance/compare.py`; the harness agrees with the production evaluator on every row):

| | Recall `Y` | FPR `N` | `Y` share of labelled flags | Background alerts / 1k |
| --- | --- | --- | --- | --- |
| Held-out, before | 0.820 | 4.89% | 0.758 | 0.637 |
| Held-out, after | 0.846 | 4.45% | 0.780 | 0.684 |
| All, before | 0.869 | 4.78% | 0.817 | 0.795 |
| All, after | 0.883 | 4.36% | 0.832 | 0.669 |

The held-out background increase is entirely in the LOW tier (word-valued passwords). At MEDIUM and above, held-out background alerts are flat (0.604 to 0.611 per 1k before the last-slice rule, which only removes alerts), and they fall by about 30% over all data. On the fixtures, a real scan goes from 102 to 111 findings. The 9 new ones are hardcoded passwords at confidence 0 or 1. No finding is lost, and no finding's confidence goes down.

### Monotonic confidence (recommendation 5)

`confidence_from_evaluation_result` is now one sum: naming 0.2 per point up to 20 (the old entropy branch, unchanged for weak names), then 0.6 per point up to 25, so a strong name alone reaches 7; plus value randomness 0 to 5 as before; clamped at 10. The shape is forced by the confidence floors in `tests/core/helpers/test_variable_evaluator.py`. A weak name with a random value (`Mytoken`, score 5) must reach 6 while `key` (score 7) stays at or below 6, and a strong name alone (`SERVICE_OAUTH`) must reach 7. A plain additive split (name 0 to 6, value 0 to 4) calibrated slightly better but broke two of those floors.

Tier calibration with the applied rules (`benchmarker/scoring_balance/calib.py`, all data; the formula agrees with production on every row):

| Tier | Before: `Y` / `N` / `Y` share | After: `Y` / `N` / `Y` share |
| --- | --- | --- |
| LOW | 1 / 1 / 50% | 1 / 3 / 25% |
| MEDIUM | 69 / 111 / 38% | 69 / 110 / 39% |
| HIGH | 542 / 110 / 83% | 160 / 81 / 66% |
| VERY-HIGH | 797 / 62 / 93% | 1,179 / 90 / 93% |

Verdicts do not change, so recall and FPR are untouched. 382 more real secrets land in VERY-HIGH at the same 93% precision, and precision now rises with every tier. The fixture scan keeps its 111 findings: 18 move from HIGH to VERY-HIGH, and 9 drop, all name-only evidence with low-entropy values (`db_pass = 'nacc6opq'` 10 to 7, four 8-character `*_kubeconfig_token` values 7 to 4). Values of 8 characters or fewer cannot exceed 3.0 bits of Shannon entropy, so they never earn the value part; normalising entropy by length would fix that but also moves the S105/S106 split.

Still open: recommendation 3 (hygiene), 6 (name coverage) and 7 (naturalness). `signing_key` briefly lost the `\bsign` match of the disabled `SLICES_2` (+15, confidence 8); `FULLNAME_1` now accepts `sign(ing)?`, which restores confidence 10 for `signing_key`, `signingToken` and `slack_signing_secret` and changes no verdict on SecretBench. `datadog_key` is still blocked by the `data` red flag, because removing `data` adds as many labelled false positives as it recovers.

## Regression cases

`tests/core/helpers/test_variable_scoring_cases.py` holds labelled cases with synthetic values: variables that should be flagged, variables that should not, monotonicity checks, and a check that word-valued passwords land in the LOW tier.

Cases the current rules get wrong are marked `known_imbalance(...)`, which is `pytest.mark.xfail(strict=True)`. A rebalancing that fixes one turns it into XPASS, which fails the run until the marker is removed. The table therefore checks a change in both directions. Before the applied changes, 46 passed and 16 were known imbalances. After them and the monotonic confidence formula, the table runs 88 checks: 84 pass and 4 remain known imbalances: random letters-only values under weaker names (2, needs a better naturalness scorer), `datadog_key` and `credentials`. Fixes for each were measured and cost precision without recovering a labelled secret, so they stay open.

## Reproducing

The scripts live in `benchmarker/scoring_balance/`, which is git-ignored like the rest of `benchmarker/` and exists only on the machine that holds the dataset. Run them from the repository root:

```bash
PYTHONPATH=$(pwd) python benchmarker/scoring_balance/extract.py 25000 <data-dir>/vars.jsonl 60   # ~45 min on 60 workers
bash benchmarker/scoring_balance/run_all.sh <data-dir>                                         # ~10 min
```

`<data-dir>` must be outside the repository: the extracted rows contain real secret values from SecretBench. `variants.py`, `marginal.py` and `combined.py` read the live `deepsecrets/rules/variable_scoring_rules.json`, so re-running them after a rule change measures the change. `V0 current` must report 0 mismatches against the production evaluator.

To measure a rule change, compare two rule files on the same data. It also re-evaluates the new file with the production `VariableEvaluator`, and `harness_vs_production_mismatch` must be 0:

```bash
PYTHONPATH=$(pwd) python benchmarker/scoring_balance/compare.py <data-dir>/vars.feat.jsonl OLD.json deepsecrets/rules/variable_scoring_rules.json
```
