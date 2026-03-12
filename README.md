# ☄️ CosmicHammer

> *Rowhammer gave us attacker-induced bit flips. The universe has been doing it for free — and nobody has been listening.*

**CosmicHammer** is an open-source, sandboxed memory observatory that detects and classifies naturally-occurring bit flips induced by cosmic rays (high-energy particle strikes) in DRAM. It demonstrates their **exploitability potential** using Page Table Entry (PTE) analysis, and contributes anonymised flip statistics to a global distributed dataset.

This is **not an attack tool**. It does not hammer memory. It *listens*.

---

## ⚠️ DISCLAIMER — READ BEFORE RUNNING

> **CosmicRowhammer is a passive, sandboxed statistical observation tool. It will not harm your system in any way.**
>
> This program allocates a private, locked memory arena within its own user-space process and monitors it for naturally-occurring bit flips caused by cosmic rays or environmental radiation. It performs **no exploitation**, **no privilege escalation**, **no kernel access**, and **no modification of any memory outside its own allocation**. The PTE structures described in this documentation are **simulated entirely in user space** — the tool never touches real kernel page tables.
>
> The purpose of CosmicRowhammer is purely **statistical**: to measure how often natural bit flips occur in consumer DRAM, characterise their distribution, and assess their theoretical exploitability class if they were to land on real kernel structures. Running this program is no more dangerous than leaving your computer on.
>
> No data is transmitted unless you explicitly pass `--report-url`. Even then, only aggregate flip counts and platform metadata are sent — never memory contents, addresses, or anything that could identify your system or its workloads.
>
> If you are unsure, **run it without `--report-url`**. Everything stays local.

---

## ⚠️ AVISO — LEE ANTES DE EJECUTAR

> **CosmicRowhammer es una herramienta pasiva de observación estadística en entorno sandboxed. No dañará tu sistema de ninguna manera.**
>
> Este programa reserva un bloque de memoria privado y bloqueado dentro de su propio proceso en espacio de usuario y lo monitoriza en busca de bit flips producidos de forma natural por rayos cósmicos o radiación ambiental. No realiza **ningún tipo de explotación**, **escalada de privilegios**, **acceso al kernel**, ni **modificación de memoria fuera de su propia asignación**. Las estructuras PTE descritas en esta documentación están **simuladas íntegramente en espacio de usuario** — la herramienta nunca accede a las tablas de páginas reales del kernel.
>
> El propósito de CosmicRowhammer es puramente **estadístico**: medir con qué frecuencia se producen bit flips naturales en DRAM de consumidor, caracterizar su distribución y evaluar su clase de explotabilidad teórica si cayeran sobre estructuras reales del kernel. Ejecutar este programa es tan peligroso como dejar el ordenador encendido.
>
> No se transmite ningún dato a menos que pases explícitamente `--report-url`. Incluso en ese caso, solo se envían contadores agregados de flips y metadatos de plataforma — nunca contenidos de memoria, direcciones ni nada que pueda identificar tu sistema o sus cargas de trabajo.
>
> Si tienes dudas, **ejecútalo sin `--report-url`**. Todo permanece en local.

---

## Background

High-energy particles — primarily muons and neutrons from cosmic ray showers — continuously bombard computing hardware at sea level and above. When a particle strikes a DRAM cell, it can deposit enough charge to flip a stored bit. These Single Event Upsets (SEUs) are well-documented in aerospace and safety-critical systems but are **systematically understudied in consumer and server hardware security contexts**.

The [Rowhammer](https://en.wikipedia.org/wiki/Row_hammer) class of attacks demonstrated that DRAM-level bit manipulation is exploitable. CosmicRowhammer asks the logical follow-up question:

> **If the flip happens anyway — is it exploitable?**

The answer depends on *what* was stored at the flipped address. This tool is designed to find out — passively, safely, and with your explicit consent.

---

## How It Works

### 1. Memory Arena

A **512 MB block** is allocated and pinned into physical RAM using `mlock()` and `madvise(MADV_HUGEPAGE)`. The OS cannot swap it, remap it, or silently move it. What lives in DRAM, stays in DRAM.

### 2. Sentinel Pattern Layout

The arena is divided into four typed regions, each 128 MB, filled with canonical patterns that represent real-world security-relevant memory contents:

```
┌─────────────────────────────────────────────────────────────┐
│  0%  – 25%   POINTER_REGION     0x00007FFF12345678 (×words) │
│  25% – 50%   RETADDR_REGION     0x00007FFF87654321 (×words) │
│  50% – 75%   PERMISSION_REGION  0x0000000000000004 (×words) │
│  75% – 100%  DATA_REGION        0xAAAA… / 0x5555… (alt.)   │
└─────────────────────────────────────────────────────────────┘
```

Any deviation from the canonical value is an event worth classifying.

### 3. PTE Feasibility Demonstration

The most powerful part of CosmicHammer is its **Page Table Entry (PTE) simulation layer**.

In a real Linux kernel, PTEs control:
- Physical address mapping of virtual pages
- Read / Write / Execute permission bits
- User / Supervisor access level
- Present / Not-present flags

A single bit flip in a PTE can:

| Bit | Flip Direction | Impact |
|-----|---------------|--------|
| Present bit (P) | 1 → 0 | Page fault / DoS |
| Write bit (W) | 0 → 1 | Write to read-only mapping |
| User bit (U) | 1 → 0 | User page becomes supervisor-only |
| NX bit | 1 → 0 | Non-executable page becomes executable |
| Physical address bits | any | Arbitrary physical memory aliasing |

CosmicHammer fills a dedicated PTE simulation region with **structurally valid x86-64 PTE values** (4KB page, user-space, RW, present, NX set) and monitors for flips. Any flip is evaluated against the PTE bitfield and classified. **These are user-space simulations only — no real kernel structures are accessed.**

```
PTE_FLIP_CLASS:
  PTE_PRESENT_CLEAR   → Denial of service (page fault loop)
  PTE_WRITE_SET       → Sandbox escape (write to RO mapping)
  PTE_NX_CLEAR        → Code execution (RW page becomes RWX)
  PTE_PHYS_CORRUPT    → Physical aliasing (arbitrary read/write primitive)
  PTE_SUPERVISOR_ESC  → Privilege escalation
```

This demonstrates that **cosmic-ray-induced flips at PTE-shaped addresses represent real, classifiable exploit primitives** — not theoretical ones.

### 4. Read Spray

A periodic read-only stride pass across all rows keeps DRAM rows "hot" and reduces masking of marginal cells by the standard refresh cycle. **No writes are performed during the spray pass** — this cleanly separates observation from induction.

### 5. Flip Detection & Reporting

Every `N` seconds (default: 5), the full arena is scanned word-by-word. Any word deviating from its expected sentinel value triggers:

1. Immediate classification (see below)
2. Console log entry
3. Accumulation into the 72-hour anonymised report buffer
4. Sentinel restoration (to avoid re-reporting the same flip)

---

## Flip Classification

```
BENIGN          — multi-bit or statistically implausible (likely noise)
DATA_CORRUPTION — flip in data region, no control-flow implication
PTR_HIJACK      — 0→1 flip in pointer-shaped region (potential CFI bypass)
PRIV_ESC        — 0→1 flip in permission/flag region
CODE_PAGE       — any flip in return-address-shaped region
PTE_*           — PTE-specific classes (see above)
```

Flip direction is always recorded:
- **0→1** flips are generally more dangerous (null → valid, clear → set)
- **1→0** flips can clear present/NX bits — equally dangerous in PTEs

---

## Anonymised Reporting

Every **72 hours**, CosmicRowhammer emits (and optionally POSTs) an anonymised JSON report. **No memory contents, no addresses, no host identifiers are transmitted.** Only aggregate flip statistics:

```json
{
  "schema_version": "1.0",
  "window_hours": 72,
  "window_start": "2025-03-01T00:00:00Z",
  "window_end":   "2025-03-04T00:00:00Z",
  "platform": {
    "arch":       "x86_64",
    "os":         "Linux 6.8.0",
    "ram_mb":     32768,
    "ecc":        false,
    "altitude_m": null
  },
  "flip_totals": {
    "total_bits_observed":   3,
    "zero_to_one":           2,
    "one_to_zero":           1
  },
  "by_class": {
    "BENIGN":          0,
    "DATA_CORRUPTION": 1,
    "PTR_HIJACK":      1,
    "PRIV_ESC":        0,
    "CODE_PAGE":       0,
    "PTE_PRESENT_CLEAR":  0,
    "PTE_WRITE_SET":      0,
    "PTE_NX_CLEAR":       1,
    "PTE_PHYS_CORRUPT":   0,
    "PTE_SUPERVISOR_ESC": 0
  },
  "by_region": {
    "POINTER":    1,
    "RETADDR":    0,
    "PERMISSION": 0,
    "DATA":       1,
    "PTE_SIM":    1
  },
  "dram_rows_affected": 3,
  "multi_bit_events":   0,
  "scan_cycles":        103680
}
```

No IP address is logged server-side beyond the standard 24-hour nginx rolling window. Participation is entirely **opt-in** via `--report-url`.

---

## Build

### Linux

```bash
# Dependencies: gcc, glibc, libcurl (optional, for remote reporting)
git clone https://github.com/fuzz-society/cosmic-rowhammer
cd cosmic-rowhammer
make

# With remote reporting support
make WITH_CURL=1
```

### Windows (MinGW/MSYS2)

```powershell
# Dependencies: gcc (MinGW-w64), mingw32-make, libcurl (optional)
git clone https://github.com/fuzz-society/cosmic-rowhammer
cd cosmic-rowhammer
mingw32-make -f Makefile.windows

# With remote reporting support
mingw32-make -f Makefile.windows WITH_CURL=1
```

### Requirements

| | Minimum | Recommended |
|---|---|---|
| RAM | 1 GB free | 2 GB free |
| Privileges | user | elevated shell for page locking (`mlock`/`VirtualLock`) |
| OS | Linux 4.x+ or Windows 10+ | Linux 6.x / Windows 11 |
| Arch | x86_64 | x86_64 / ARM64 |

> **Root is recommended** to guarantee physical page pinning via `mlock()`. Without it, the OS may silently swap or remap pages, producing false negatives.
>
> On Windows, running in an elevated terminal similarly improves page locking reliability via `VirtualLock()`.

---

## Run

### Linux

```bash
# Local observation only
sudo ./cosmic_rowhammer

# With 72-hour anonymous reporting
sudo ./cosmic_rowhammer --report-url https://data.cosmicrowhammer.io/report

# Custom scan interval (seconds)
sudo ./cosmic_rowhammer --interval 10

# Higher altitude? Tell us
sudo ./cosmic_rowhammer --altitude 2300 --report-url http://cosmos.fuzzsociety.org/report

# Hyper conservative mode (capabilities)

sudo setcap cap_ipc_lock+ep ./cosmic_rowhammer
./cosmic_rowhammer   # no sudo needed, ever again

example report every 3days
./cosmic_rowhammer --report-url http://cosmos.fuzzsociety.org:5000/report --report-window 3d
```

### Windows

```powershell
# Local observation only
.\cosmic_rowhammer.exe

# With 72-hour anonymous reporting
.\cosmic_rowhammer.exe --report-url https://data.cosmicrowhammer.io/report

# Custom scan interval (seconds)
.\cosmic_rowhammer.exe --interval 10

# Report window example
.\cosmic_rowhammer.exe --report-window 3d --report-url http://cosmos.fuzzsociety.org:5000/report
```

### Example Output

```
═══════════════════════════════════════════════════
  CosmicRowhammer v0.1.0  —  FuzzSociety
═══════════════════════════════════════════════════
  Host:     Linux 6.8.0 x86_64
  RAM:      32768 MB total
  Arena:    512 MB  (mlock=yes)
  Regions:  POINTER | RETADDR | PERMISSION | DATA | PTE_SIM
  Interval: 5 s
═══════════════════════════════════════════════════

[*] Allocating 512 MB arena...
[+] Arena at 0x7f3a00000000
[*] Writing sentinel patterns...
[+] Arena ready. Starting observation loop.

[2025-03-01T14:32:11Z] Scan #8640 — no flips detected
[2025-03-02T09:17:44Z] FLIP @ offset=0x01a3f4c080  bit=52  dir=0→1
         region=PTE_SIM     class=PTE_NX_CLEAR
         expected=0x8000000012345067  observed=0x0000000012345067
         dram_row=3398296
```

---

## The PTE Attack Scenario
To understand why PTE flips matter, consider not a single target but the full physical memory landscape of a running Linux system:

Physical DRAM
┌──────────────────────────────────────────────────────────────────┐
│  PD page │ data │ PT page │ PD page │ data │ PT page │ PT page   │
│      ↑              ↑          ↑                 ↑               │
│                any of these can be hit                           │
└──────────────────────────────────────────────────────────────────┘
                         ↑
               cosmic ray hits anywhere

A loaded Linux system has thousands of page table pages scattered across physical DRAM. A cosmic ray does not need to target a specific PTE — it just needs to land in any of the many physical locations containing page table structures.
The impact scales with the level of the page table hierarchy hit:

```
leaf PTE flip:    1 page  (4KB)  remapped  →  limited impact
PD entry flip:    512 pages (2MB) remapped  →  entire PT subtree injected
PDPT entry flip:  1GB remapped              →  massive VA range hijacked
PML4 entry flip:  512GB remapped            →  essentially full process space
```

A single bit flip at a higher page table level does not remap one page — it grafts an entire crafted subtree into the victim process's virtual address space. The process walks right into it, none the wiser: no segfault, no permission violation, no kernel alarm — because the page table walk succeeds, just not where the process expected.
The attack surface is not a point. It is a distribution over physical memory — which is exactly what CosmicRowhammer measures.
CosmicRowhammer does not access real kernel PTEs (that would require ring 0). Instead, it demonstrates that structurally valid PTE values, distributed across a wide observable DRAM region, are susceptible to exactly this class of flip — and quantifies the spatial and temporal probability distribution of such events across real hardware.

---

## Research Context

This tool is part of ongoing research into naturally-occurring hardware fault exploitation, first presented at:

- **RE//verse 2026** — *"The Limit Is the Sky... (Or Not)? — Cosmic Fault Injection as an Attack Vector"*

Related work: [Fuzzing Against the Machine](https://nostarch.com/fuzzing-against-machine) — A. Nappa, E. Blázquez (No Starch Press, 2023)

If CosmicRowhammer contributes to your research, please cite:

```bibtex
@software{cosmicrowhammer2025,
  author    = {Nappa, Antonio},
  title     = {CosmicRowhammer: Distributed Cosmic Ray Bit Flip Observatory},
  year      = {2025},
  publisher = {FuzzSociety},
  url       = {https://github.com/fuzz-society/cosmic-rowhammer}
}
```

---

## Contributing

Pull requests welcome. Particularly interested in:

- **ARM64 / Apple Silicon** port (different DRAM geometry)
- **ECC detection** — identifying which flips ECC silently corrected
- **Altitude correlation** — runs above 2000m are especially valuable
- **DRAM vendor fingerprinting** — manufacturer-specific flip rate analysis
- **Windows port** — `VirtualLock()` equivalent path

---

## Responsible Use

CosmicRowhammer is a **passive observer**. It does not:
- Write to memory outside its own allocated arena
- Exploit any vulnerability
- Transmit any data without explicit `--report-url` opt-in
- Identify or fingerprint the host beyond CPU architecture and OS version

This tool is designed for security researchers, system administrators, and curious people who want to contribute to a real-world dataset of hardware-level events.

---

## License

MIT — see [LICENSE](LICENSE)

---

*Built with curiosity and a healthy fear of muons.*  
**[FuzzSociety](https://fuzz.society)** · Dr. Antonio Nappa
