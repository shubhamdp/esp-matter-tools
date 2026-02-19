# Security Review: `shubhamdp/esp-matter-tools`

## Repository Overview

This repository contains two Python tools:
1. **mfg_tool** (`esp-matter-mfg-tool`) - Generates Matter manufacturing partition images, including DAC certificates, SPAKE2+ verifiers, NVS partitions, and QR codes.
2. **dmv_tool** (`esp-matter-dm-validator`) - Validates Matter device data model conformance against the specification.

---

## FINDINGS

### SEVERITY: MEDIUM

#### 1. Use of `random` module for security-sensitive values (passcodes, discriminators)

**File:** `mfg_tool/sources/mfg_tool.py`, lines 121, 136, 184

The tool uses Python's `random.randint()` to generate passcodes and discriminators. The `random` module uses a Mersenne Twister PRNG which is **not cryptographically secure** -- its output is predictable if a sufficient number of outputs are observed (624 consecutive 32-bit outputs allow full state recovery). Passcodes and discriminators are commissioning credentials for Matter devices. Predictable passcodes allow unauthorized commissioning.

- **Line 121:** `passcode = random.randint(1, 99999998)` -- used when no passcode is specified by the user
- **Line 136:** `discriminators.append(random.randint(0x0000, 0x0FFF))` -- used when no discriminator is specified
- **Line 184:** `random.randint(10, 99)` for PAI common name suffix (low impact)

**Recommendation:** Replace `random.randint()` with `secrets.randbelow()` or `secrets.SystemRandom().randint()` for generating passcodes and discriminators since these are security-sensitive manufacturing credentials.

---

#### 2. Private key password argument (`--pwd`) is accepted but completely ignored

**File:** `mfg_tool/sources/mfg_tool.py`, line 742; `mfg_tool/sources/cert_utils.py`, line 100

The CLI accepts a `--pwd`/`--password` argument for a private key password, but it is **never used anywhere** in the codebase. The `load_key_from_file()` function always passes `password=None` when loading private keys. This means:
- Users who provide password-protected private keys will get silent failures or errors without understanding why.
- It creates a false sense of security -- users may believe their keys are being decrypted with the password when they are not.

**Recommendation:** Either implement password support in `load_key_from_file()` (pass `args.priv_key_pass` through to the `password=` parameter), or remove the `--pwd` argument entirely to avoid misleading users.

---

#### 3. Private keys exported without encryption (NoEncryption)

**File:** `mfg_tool/sources/cert_utils.py`, lines 128 and 304

All generated private keys (DAC, PAI) are saved to disk using `serialization.NoEncryption()`. This means:
- Private keys are stored in plaintext PEM/DER format on disk.
- Any process or user with file system access can read these keys.
- In a manufacturing environment, compromised DAC private keys can be used to impersonate devices.

**Recommendation:** This is somewhat expected for manufacturing tooling (keys often need to be embedded in firmware without passwords), but the tool should:
- Clearly document this behavior.
- Consider offering an option to encrypt output keys at rest.
- Ensure output directories have restrictive permissions (the tool does not set file permissions).

---

### SEVERITY: LOW

#### 4. Test private keys committed to the repository

**Files in `mfg_tool/test_data/`:**
- `DAC_key.pem`
- `DAC-FFF1-8000-Key.pem`
- `Chip-Test-PAI-FFF2-8001-Key.pem`
- `Chip-Test-PAA-NoVID-Key.pem`
- `DAC_key_No_UUID.der`

These are EC private keys committed to the public repository. They appear to be **well-known CHIP test keys** (from the connectedhomeip project, using test VID 0xFFF1/0xFFF2) used solely for testing purposes. They are not production credentials. This is acceptable practice for test data, but worth noting.

**Risk:** Minimal. These are standard Matter test credentials. However, if anyone mistakenly uses these test keys in production, devices would be trivially impersonable.

---

#### 5. `shell=True` in subprocess calls in test code

**Files:** `mfg_tool/tests/utils.py` line 93, `dmv_tool/tests/test_integration.py` line 49

Both test suites use `subprocess.run(command, shell=True, ...)`. While test-only code, `shell=True` can enable shell injection if command strings are constructed from untrusted input. In these cases, the commands come from a JSON test config file (`test_integration_inputs.json`) and hardcoded strings.

**Risk:** Low, since the input is developer-controlled test data. However, if someone adds tests with user-controllable input, this could become exploitable.

**Recommendation:** Use `shlex.split()` to tokenize commands and pass as a list instead of using `shell=True`.

---

#### 6. XML parsing with `xml.etree.ElementTree` (potential XXE / XML bomb)

**Files:** `dmv_tool/generators/xml_parser.py` line 19, `dmv_tool/generators/datamodel.py` line 16

The dmv_tool parses XML files from the connectedhomeip repository using `xml.etree.ElementTree`. Python's `ElementTree` has some built-in protections (it does **not** resolve external entities by default since Python 3.7.1), but it can still be vulnerable to:
- **Billion laughs attack** (entity expansion DoS)
- Other XML bomb variants

The input XML files are expected to come from a trusted source (the connectedhomeip SDK), but if a user points the tool at a maliciously crafted XML file, it could cause DoS.

**Recommendation:** Use `defusedxml.ElementTree` instead of `xml.etree.ElementTree` for defense-in-depth XML parsing.

---

#### 7. No file permission controls on sensitive output files

**Files:** `mfg_tool/sources/mfg_tool.py` and `mfg_tool/sources/cert_utils.py`

When the tool writes private keys, certificates, passcodes, and verifiers to disk, it does not set restrictive file permissions. The output files inherit the default umask, which typically allows group/other read access. For sensitive manufacturing data (private keys, passcodes), this is a concern.

**Recommendation:** Set restrictive permissions (e.g., `0o600`) on output files containing private keys and sensitive commissioning data. At minimum, set `0o700` on the output directories.

---

#### 8. Sensitive data written to CSV files in plaintext

**Files:** `mfg_tool/sources/mfg_tool.py` -- `generate_passcodes()` (lines 98-125), `generate_onboarding_data()` (lines 633-658), `generate_summary()` (lines 547-598)

The tool writes passcodes, SPAKE2+ salts, SPAKE2+ verifiers, discriminators, QR codes, and manual pairing codes to CSV files in plaintext. The summary CSV file (`summary-<timestamp>.csv`) aggregates all this sensitive data in one file. While this is the intended functionality of a manufacturing tool, these files remain on disk after generation with no warnings about cleanup.

**Recommendation:** Add prominent warnings in output about securing/deleting these files. Consider adding an option to auto-cleanup intermediate files.

---

#### 9. `setup.py` uses `subprocess.run` with `patch` command

**File:** `mfg_tool/setup.py`, lines 20-35

During package build, `setup.py` runs the `patch` command via `subprocess.run()` using `input=open(patch_file, "rb").read()`. The patch file path is derived from `pkg_resources.resource_filename()`. This is not directly exploitable since the patch files are distributed with the package, but it represents a supply chain concern -- if the package distribution is compromised, the build process could execute arbitrary code through a malicious patch file.

**Risk:** Low -- this is standard practice for patching vendored dependencies.

---

#### 10. Pinned dependency versions may have known vulnerabilities

**File:** `mfg_tool/requirements.txt`

Several dependencies are pinned to specific versions:
- `cryptography==44.0.1` -- Good, relatively recent
- `cffi==1.15.0` (for Python < 3.13) -- Older; consider updating
- `future==0.18.3` -- Has had security advisories in the past
- `pycparser==2.21` -- Older version

**Recommendation:** Regularly audit and update dependencies. Consider using tools like `pip-audit` or Dependabot.

---

## FINDINGS NOT PRESENT (Positive observations)

- **No hardcoded secrets, API keys, or tokens** found in the codebase.
- **No remote network calls** -- neither tool makes any HTTP requests, API calls, or connects to external services (except when flashing via UART serial port).
- **No use of dangerous functions** (`eval`, `exec`, `pickle.loads`, `os.system`) in any source code.
- **Proper use of `os.urandom()`** for cryptographic salt generation (line 114 of `mfg_tool.py`).
- **Proper SPAKE2+ implementation** using `hashlib.pbkdf2_hmac` with configurable iteration counts.
- **Certificate validation** is thorough -- VID/PID matching, chain validation, signature verification, key usage checks.
- **CI/CD pipeline** uses trusted publishing for PyPI (OIDC tokens, no stored API keys).
- **GitHub Actions** use pinned action versions (v3, v4), though SHA pinning would be more secure.
- The `dmv_tool` has no security-sensitive operations -- it only reads/parses log files and XML files for data model validation.

---

## Summary Table

| # | Finding | Severity | Component |
|---|---------|----------|-----------|
| 1 | Insecure PRNG (`random`) for passcodes/discriminators | Medium | mfg_tool |
| 2 | `--pwd` argument accepted but ignored | Medium | mfg_tool |
| 3 | Private keys saved without encryption | Medium | mfg_tool |
| 4 | Test private keys in repository | Low | mfg_tool |
| 5 | `shell=True` in test subprocess calls | Low | Both tools |
| 6 | XML parsing without defusedxml | Low | dmv_tool |
| 7 | No file permission controls on sensitive output | Low | mfg_tool |
| 8 | Sensitive data in plaintext CSV files | Low | mfg_tool |
| 9 | subprocess patch execution in setup.py | Low | mfg_tool |
| 10 | Potentially outdated pinned dependencies | Low | mfg_tool |

## Priority Actions

1. **Highest priority:** Replace `random.randint()` with `secrets` module for passcode and discriminator generation (Finding #1).
2. **High priority:** Fix or remove the ignored `--pwd`/`--password` argument (Finding #2).
3. **Medium priority:** Set restrictive file permissions on output files containing private keys (Finding #7).
4. **Medium priority:** Replace `xml.etree.ElementTree` with `defusedxml` (Finding #6).
5. **Lower priority:** Address test code `shell=True` usage, dependency updates, and documentation improvements.
