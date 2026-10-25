# W3: Key-Homomorphic Implicit-Certificate Reproduction Package

Reference implementations, preserved measurements, and reproduction commands for the W3 research project, whose working paper title is **Security Conditions and Simulation Boundaries for Key-Homomorphic Implicit Certificates**. The paper is under preparation; this repository does not assert acceptance or publication.

This is a **separate repository** from the [JISA R3 reproduction package](https://github.com/sea0114/gic-prototype). That repository supplies the documentation format and the W2/JISA comparison reference. Its experiments are not copied into or pooled with this dataset.

## 1. Scope and configuration map

The package has ten finite certificate configurations, each implementing ECQV-type and PV-type issuance, user completion, public-key reconstruction, and full preimage validation:

| Key map | Provider/profile | Configurations | Role |
| --- | --- | --- | --- |
| Schnorr-type scalar map | NIST P-256, `ecdsa` | `scalar-P256-ECQV`, `scalar-P256-PV` | Matched scalar baseline |
| Schnorr-type scalar map | BLS12-381 G1, `py-ecc` | `scalar-BLSG1-ECQV`, `scalar-BLSG1-PV` | Scalar baseline; no BLS signatures or pairing in this adapter |
| PS key map | BLS12-381 pairing setting | `PS-ECQV`, `PS-PV` | Full two-scalar secret representation |
| Waters key map | BLS12-381 pairing setting | `Waters-ECQV`, `Waters-PV` | Actual valid group-element pair with relation guards |
| Okamoto-type representation map | BLS12-381 G1 | `Okamoto-BLSG1-ECQV`, `Okamoto-BLSG1-PV` | Genuine non-injective full two-scalar representation |

The P-256 representation-control run repeats only the first two configurations with a separate implementation policy. It does **not** add two schemes. GQ remains a static, source-separated comparison in the research; there is no GQ execution configuration here. The GQ conference study and the older JISA-interface specialization have different parameter distributions and games, and must not be conflated.

The objects are key-map/certificate adapters, not an implementation of certified-signature composition security. Signatures, full NE exposure games, two-run forking machines, and production PKI services are not implemented by this harness. Conditional mathematical reductions are not established by passing the tests.

## 2. Installation

Run commands from this repository root, using **CPython 3.12.14** for the measured-environment match:

```sh
git clone https://github.com/sea0114/w3-implicit-certificates.git
cd w3-implicit-certificates
python -m pip install --target vendor --only-binary=:all: -r requirements.scalar.lock.txt
```

The scalar lock includes `requirements.lock.txt`: py-ecc 8.0.0 and its pinned dependencies, plus ecdsa 0.19.1 and six 1.17.0. `dependency_lock.json` and `scalar_dependency_lock.json` record the original environment and provider provenance. `vendor/` is an ignored installation target; no third-party binaries or virtual environments are distributed. Other Python/platform combinations have not been certified by this release. Installation time is outside protocol timing.

For every command producing files, choose a fresh output directory. The wrapper refuses an existing directory and never runs a performance benchmark implicitly.

## 3. Verify the published data without new measurements

No crypto-provider installation is needed for the first command. It validates file hashes, all 2,640 saved trial records, scheduling, failures, trace-summary arithmetic, and the existing descriptive statistics in fresh copies:

```sh
python -X utf8 reproduce.py verify --output reproduced/data_check_001
```

After installing the pinned providers, also verify the measured provider-source hashes and reproduce the existing control comparison:

```sh
python -X utf8 reproduce.py verify --providers --output reproduced/full_check_001
```

The original `analyze_comparison_benchmark.py` and `analyze_p256_rep_control.py` write beside the run they analyze. The wrapper supplies copies under the new output path, protecting the published records. All numerical calculations use the existing analysis code. This is recomputation of preserved evidence, not new timing or inference. In data-only mode, provider-file checks and the provider-dependent comparison check are explicitly skipped; all saved timing populations are still checked.

`release_manifest.json` identifies the public file bytes. `.gitattributes` prevents checkout line-ending conversion because measured Python-source hashes include original line endings. `export_provenance.json` records original hashes and the four JSON metadata files whose absolute workstation paths were replaced by package-relative paths or explicit omitted-path markers. **Python source files and raw JSONL samples are byte-identical to the measured local originals.** Numerical fields were not redacted or changed.

## 4. Functional and boundary checks

The safe wrapper executes historical checks in a fresh copy so their result-writing behavior cannot overwrite the saved evidence:

```sh
# Minimal integration acceptance: 18 check groups.
python -X utf8 reproduce.py checks --suite harness --output reproduced/harness_check_001

# Optional full existing functional/boundary suites; no formal benchmark.
python -X utf8 reproduce.py checks --suite all --output reproduced/all_checks_001
```

The preserved checks comprise 33 original PS/Waters diagnostics, five additional boundary checks, 53 scalar groups, 35 Okamoto groups, 18 harness integration groups, four benchmark preflight groups using fake clocks, and 17 P-256-control groups. Their JSON reports remain historical evidence; current execution produces separate reports. Tests include zeros and identities, malformed/nonmember encodings, rejection timing, full-domain sampling and traces, same-coins functional comparisons, and failure retention. They are not proofs of the asymptotic games or distribution claims.

`comparison_harness.py --describe` reports the registry without timing. Its description may say “untimed” or “clock: none”: those fields describe the inner functional harness. The outer `benchmark_comparison.py` supplies the actual timer, scheduling and measurement metadata.

## 5. Preserved runs and statistical population

| Run directory | Configurations | Warm-up | Formal | Total saved | Failed |
| --- | ---: | ---: | ---: | ---: | ---: |
| [`comparison_benchmark_20261024_run01/`](comparison_benchmark_20261024_run01/) | 10 | 20/configuration | 200/configuration | 2,200 | 0 |
| [`p256_rep_control_20261024_run01/`](p256_rep_control_20261024_run01/) | 2 | 20/configuration | 200/configuration | 440 | 0 |

Each run contains `raw_samples.jsonl`, `run_metadata.json`, `summary.json`, `analysis.json`, and `results_tables.md`. The control run additionally contains `comparison.json` and `comparison_tables.md`. Tables already report mean, sample SD, and median; JSON retains min, max, and p95. Historical progress files describe completion, not a separate dataset.

- Every trial creates a fresh session, setup, CA, user and issuance nonce; within that trial, phases reuse those outputs.
- All warm-ups precede formal rounds. The ten-configuration run rotates its starting configuration modulo ten; each formal position occurs twenty times per configuration. The two-configuration control alternates its starting configuration, one hundred times per position.
- Fixed inputs: lambda=128; identity is the 128-bit ASCII string `0123456789abcdef`; Waters setup uses n=8, a different parameter from certificate identity length.
- The measured environment was CPython 3.12.14, Windows 11 build family 26300, 16 logical processors, AMD64 Family 23 Model 113, py-ecc 8.0.0 and ecdsa 0.19.1. Available host details are in metadata; missing physical-core/RAM/thermal information is not inferred from the separate JISA experiment.
- Formal trials use OSBits/`secrets.randbits`, not deterministic public seeds. Rejection sampling retains complete private traces during computation; exported JSON contains proposal/bit counts, not secret coin blocks. The exact historical secret draws cannot be replayed from a public seed. Reproduction means rerunning the procedure or recalculating saved evidence, not reproducing identical wall-clock times.
- `perf_counter_ns` uses Windows QueryPerformanceCounter in the recorded environment. Reported resolution is 100 ns; integer nanosecond storage does not claim 1 ns resolution.
- Sample SD uses n-1. P95 linearly interpolates at `0.95*(n-1)` in sorted samples. No outlier deletion, replacement trials, trimming, or winsorization is applied.
- Primary statistics condition on a complete successful trial and diagnostics. Failed-trial attempted timings and all-attempted populations are separately retained. Skipped phases have no timing and are never replaced by zero; empty populations are null.
- Completeness analysis checks 240 common-run and 48 control-run phase/population cells. The control comparison additionally checks the original P-256 phase statistics. Runs are never pooled or treated as paired samples.

Historical `benchmark_results.json` is an earlier four-configuration pilot, not the ten-configuration result. `finite_bounds.json/.csv` contains conditional finite-bound scenarios with assumed hardness inputs, not measured attack probabilities. Neither artifact is included in the formal runtime population.

## 6. Timing and setup contract

Setup and seven certificate phases are timed separately. Timer reads surround the unchanged harness once-wrapper and operation; wrapper overhead is included and no empty-loop overhead is subtracted.

| Phase | Included work |
| --- | --- |
| `group_setup` | Instance construction and validation after imports; Waters h/U sampling; Okamoto nonzero-base setup |
| `ca_keygen` | Full-domain CA secret sampling, key map, canonical secret/public encoding, complete trace |
| `ca_import` | Secret decoding/membership, public-key recomputation, service/hash construction |
| `user_prepare` | User sampling/trace, key map, request and secret encoding |
| `issue` | Request parse/membership, CA nonce/trace, commitment, certificate/hash/response, state retention |
| `completion` | Certificate and secret decoding, hash, secret arithmetic, output encoding |
| `reconstruction` | Certificate parsing/membership, hash, public arithmetic, canonical public encoding |
| `preimage_validation` | Candidate membership/key map and internally repeated reconstruction, `fresh=False` |

The last phase already includes reconstruction; adding standalone reconstruction again double-counts the necessary validation path. Waters retains its relation guards: CA import, completion and validation include 2/4/2 relation pairings respectively. A projection map does not make validation free.

Imports, metadata/source hashing, harness shape checks, independent correctness diagnostics, serialization of JSON, logging and statistics are outside the phase timers. They remain real end-to-end work. Default automatic GC is retained; affinity, frequency, temperature and background load were not controlled. Setup is not amortized. `group_setup`, `ca_keygen`, and `ca_import` must not be collapsed into a differently scoped “Setup” number from another source.

## 7. P-256 representation-control policy

`p256_rep_control.py` changes only the P-256 instance factory and representation policy inherited by the harness. All wire encodings, certificate formulas, full parsing/validation, sampling domains and trace policies remain intact.

Externally supplied affine points are fully validated before conversion to `PointJacobi` with Z=1 and `generator=False`. Non-identity key-map outputs are normalized and copied into independent non-generator points. Variable-base operands have no inherited precomputation table. Both modes share the provider's fixed-generator precomputation policy. Identity cases remain valid and follow explicit short circuits.

Let D denote the validated affine-to-Jacobian conversion; N denotes normalization/copy of a key-map output. For a normal non-identity trial:

| Phase | D | N |
| --- | ---: | ---: |
| setup | 0 | 0 |
| CA key generation | 0 | 1 |
| CA import | 0 | 1 |
| user preparation | 0 | 1 |
| issuance | 1 | 1 |
| completion | 1 | 0 |
| reconstruction | 1 | 0 |
| preimage validation | 1 | 1 |

These costs are inside their containing phase. No isolated conversion timer was added. Earlier normalization can save later encoding work, so cross-run differences are not the cost of a single conversion. The original large P-256 mode gap was not reproduced under this control policy; this does not establish equivalence, universal equal speed, a causal share, or a small percentage winner. The runs have independent randomness, time and workload schedules.

## 8. Codecs, validation, and mathematical scope

`w3_reference.py` supplies the common bitstring/identity and certificate framing; scalar/Okamoto adapters use the same framing. Exact fields and canonical parsing are specified by the executable codec functions, with boundary cases in the check scripts. Actual byte counts are retained per raw trial under `trial.bytes`, rather than inferred from abstract group-element counts. Reported component sizes are not full public-parameter transport or end-to-end communication sizes.

Full scalar domains include zero. PS/Okamoto retain both secret coordinates; Okamoto's map is genuinely non-injective and accepts alternate valid preimages. Waters uses its actual valid group-element pair, not freely known hidden scalar coordinates. Membership/guard checks are retained at input boundaries. Setup auxiliary information and the provider's publicly available groups/pairing context must match the applicable assumptions.

The fixed SHAKE certificate hash and test random oracle have distinct roles. A finite fixed hash is not an instantiation proof of the classical ROM. The certificate frame has no additional mode/CA binding, and this package makes no cross-mode/cross-CA security claim. `CertificateService` models role logic, not process access control. Python offers no secret erasure, constant-time or deployment isolation guarantee. Historical proposal caps are diagnostic limits, not a same-code bit-time clock; the formal common run uses uncapped full-domain sampling.

The package does not establish a uniform asymptotic setup family, measured OW hardness, signature-composition security, kernel-condition breakthroughs, or general performance superiority. Schnorr and Okamoto specialize existing conditional results. PS/Waters/GQ source attribution belongs in the paper; more test cases do not constitute new mathematical results.

## 9. Optional new measurements

These commands are **not** run by verification or tests. They create new observations and may take substantial time. Use a fresh run name and keep its results separate from the published evidence:

```sh
python -X utf8 benchmark_comparison.py --output local_runs/common_001 --warmups 20 --trials 200
python -X utf8 benchmark_p256_rep_control.py --output local_runs/control_001 --baseline comparison_benchmark_20261024_run01 --warmups 20 --trials 200
```

The full common run originally took about 42 minutes including warm-up, setup, diagnostics and output. This is not single-protocol latency. Do not use the shipped release auditor to bless smaller pilot runs as the prescribed experiment. Fresh runtime metadata may contain local paths; sanitize before any further publication, preserving source/raw hashes and disclosing transformations.

## 10. Relation to W2/JISA and citation

The separate JISA package has its own Python version, identity, phase boundaries, scheme scope and measurement history. W3's scalar baselines use the W3 interface. Cross-source timings are not interchangeable and must not be divided into a speed ranking. GQ is not part of either W3 run.

Cite the immutable Git commit (obtain it with `git rev-parse HEAD`) and the relevant run IDs; do not cite only moving `main`. The initial release tag is `w3-repro-20261025`. Use the repository URL together with that tag or, preferably, its full commit SHA. No DOI or final paper citation has been invented. The publication record should distinguish the artifact snapshot from the measured source, whose exact bytes are pinned in each run's metadata and this release's manifests.

Reproduction commands, full schemas, raw records, complete tables, environment details and implementation caveats live here. The paper can cite this artifact instead of reproducing these operational instructions, while retaining the methodology, main evidence and scope needed to assess its claims.

## 11. Files, historical evidence, and rights

The common core is `w3_reference.py`; adapters are `scalar_reference.py`, `okamoto_reference.py`, and `p256_rep_control.py`. `comparison_harness.py` defines the common phases. `benchmark_*.py` measure, `analyze_*.py` audit saved observations, `check_*.py` run synthetic functional/boundary fixtures, and `reproduce.py` provides safe output isolation. The `_source_manifest.json` and earlier verification reports preserve historical stages; release-wide integrity is governed by `release_manifest.json`.

No new open-source license is asserted without the author's choice. Publication here makes the research artifact inspectable; it does not automatically grant unrestricted redistribution. Dependencies retain their own licenses and are installed separately. Manuscripts, reviewer correspondence, private research notes, secrets, virtual environments and provider binaries are not included.
