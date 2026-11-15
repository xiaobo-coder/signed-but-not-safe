#!/usr/bin/env python3
"""Regenerate every result table and number of

    Signed but Not Safe: Requirement Integrity in Multi-Agent LLM Handoffs (arXiv:2611.07483, v2)

from data/ alone, write them to out/tables/ and compare them with the files the paper was compiled from
(data/paper-reference.json). Standard library only; no model calls, no network.

    python3 reproduce_tables.py          # about a minute (10,000-draw cluster bootstraps)

The statistics (paired contrasts, task-clustered bootstrap, exact McNemar, Holm), the verdict rules and the LaTeX
formatting are the authors' frozen analysis code, collected here into one file; the full audit archive (see README)
holds the original scripts, the per-version freeze manifests and the raw-run reproduction.
Prints MATCH/MISMATCH per file and for the abstract's headline numbers; exit code 0 iff everything matches."""
from __future__ import annotations

import gzip
import json
import math
import random
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DATA, OUT = HERE / "data", HERE / "out" / "tables"


def load(name):
    with gzip.open(DATA / name, "rt", encoding="utf-8") as f:
        return [json.loads(line) for line in f]


# ============================== statistics (frozen preregistered scorer) ==============================
ATTACKS = ("T2a", "T3", "T4")
H2_MIN_PAIRS = 60


def mean(xs):
    xs = [x for x in xs if x is not None]
    return (sum(xs) / len(xs)) if xs else None


def mcnemar_exact(b, c):
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    p = sum(math.comb(n, i) for i in range(0, k + 1)) / 2 ** n
    return min(1.0, 2 * p)


def paired(rows, sel, arm_x, arm_y, field, key=("family", "task", "threat")):
    idx = {}
    for r in rows:
        if sel(r) and field in r:
            idx.setdefault(tuple(r[k] for k in key), {})[r["arm"]] = r
    return [(k, int(d[arm_x][field]), int(d[arm_y][field])) for k, d in idx.items() if arm_x in d and arm_y in d]


def within(rows, sel, fx, fy):
    return [((r["family"], r["task"], r["threat"]), int(r[fx]), int(r[fy])) for r in rows if sel(r) and fx in r and fy in r]


def contrast(pairs, B, seed):
    if not pairs:
        return {"n_pairs": 0}
    diff = mean([x - y for _, x, y in pairs])
    b = sum(1 for _, x, y in pairs if x == 1 and y == 0)
    c = sum(1 for _, x, y in pairs if x == 0 and y == 1)
    clusters = {}
    for k, x, y in pairs:
        clusters.setdefault((k[0], k[1]), []).append(x - y)
    keys = sorted(clusters)
    rng = random.Random(seed)
    boots = []
    for _ in range(B):
        s = [d for kk in (rng.choice(keys) for _ in keys) for d in clusters[kk]]
        boots.append(sum(s) / len(s))
    boots.sort()
    lo, hi = boots[int(0.025 * (B - 1))], boots[int(0.975 * (B - 1))]
    lo90, hi90 = boots[int(0.05 * (B - 1))], boots[int(0.95 * (B - 1))]
    return {"n_pairs": len(pairs), "clusters": len(keys), "diff_x_minus_y": diff, "ci95": [lo, hi], "ci90": [lo90, hi90],
            "discordant_x1y0": b, "discordant_x0y1": c, "mcnemar_p": mcnemar_exact(b, c)}


def holm(ps):
    order = sorted(ps, key=lambda k: ps[k])
    out, running = {}, 0.0
    for i, k in enumerate(order):
        running = max(running, min(1.0, (len(ps) - i) * ps[k]))
        out[k] = running
    return out


def analyze(rows, B=10000, seed=20261017, margin=0.05):
    an = {}
    an["H1_unsafe_J_minus_MS"] = contrast(paired(rows, lambda r: r["threat"] in ATTACKS, "J", "MS", "unsafe_commit"), B, seed)
    an["H2_detect_verifier_vs_shadow"] = contrast(within(rows, lambda r: r["arm"] == "MS" and r["threat"] in ("T3", "T4")
                                                         and r.get("first_violation"), "verifier_flag_first", "shadow_flag_first"), B, seed)
    an["H2_false_alarm_verifier_vs_shadow"] = contrast(within(rows, lambda r: r["arm"] == "MS" and r["threat"] in ("T0", "T1")
                                                              and r.get("first_final_ok") and not r.get("first_violation"),
                                                              "verifier_flag_first", "shadow_flag_first"), B, seed)
    an["H3a_unsafe_M_minus_MS_T2a"] = contrast(paired(rows, lambda r: r["threat"] == "T2a", "M", "MS", "unsafe_commit"), B, seed)
    h3b = contrast(paired(rows, lambda r: r["threat"] == "T0", "M", "MS", "conformant_commit"), B, seed)
    if h3b.get("n_pairs"):
        h3b["equivalent_within_margin"] = -margin < h3b["ci90"][0] and h3b["ci90"][1] < margin
    an["H3b_utility_M_vs_MS_benign_TOST"] = h3b
    an["S1_utility_M_minus_J_T0T1"] = contrast(paired(rows, lambda r: r["threat"] in ("T0", "T1"), "M", "J", "conformant_commit"), B, seed)
    an["S2_utility_MS_minus_J_all"] = contrast(paired(rows, lambda r: True, "MS", "J", "conformant_commit"), B, seed)
    an["S3_unsafe_JL_minus_MS_attacks"] = contrast(paired(rows, lambda r: r["threat"] in ATTACKS, "JL", "MS", "unsafe_commit"), B, seed)
    an["S4_unsafe_MS_minus_MSO_all"] = contrast(paired(rows, lambda r: True, "MS", "MSO", "unsafe_commit"), B, seed)
    family = ["H1_unsafe_J_minus_MS", "H3a_unsafe_M_minus_MS_T2a"]
    an["H2_in_holm_family"] = an["H2_detect_verifier_vs_shadow"].get("n_pairs", 0) >= H2_MIN_PAIRS
    if an["H2_in_holm_family"]:
        family.append("H2_detect_verifier_vs_shadow")
    ps = {k: an[k]["mcnemar_p"] for k in family if an[k].get("n_pairs")}
    an["holm_adjusted"] = holm(ps) if ps else {}
    return an


def pooled(*runs):
    """Shared cells (arms J/JL/M/MS x threats T0/T2a/T3/T4 x tasks present in every family), as preregistered."""
    shared_arms, shared_thr = {"J", "JL", "M", "MS"}, {"T0", "T2a", "T3", "T4"}
    rows = [r for rs in runs for r in rs if r["arm"] in shared_arms and r["threat"] in shared_thr]
    by = {}
    for r in rows:
        by.setdefault(r["family"], set()).add((r["arm"], r["threat"], r["task"]))
    cells = set.intersection(*by.values())
    return [r for r in rows if (r["arm"], r["threat"], r["task"]) in cells]


# ============================== main results tables ==============================
ARMS = ["S", "J", "JL", "M", "MS", "MSO"]
THREATS = ["T0", "T1", "T2a", "T3", "T4"]
HOLM = ["H1_unsafe_J_minus_MS", "H2_detect_verifier_vs_shadow", "H3a_unsafe_M_minus_MS_T2a"]
LABEL = {
    "H1_unsafe_J_minus_MS": ("H1", "Unsafe commit, \\arm{J}$-$\\arm{MS}, \\thr{T2a}--\\thr{T4}"),
    "H2_detect_verifier_vs_shadow": ("H2", "Detection, verifier$-$shadow LLM, \\arm{MS}, \\thr{T3}/\\thr{T4}, violating first decisions"),
    "H3a_unsafe_M_minus_MS_T2a": ("H3a", "Unsafe commit, \\arm{M}$-$\\arm{MS}, \\thr{T2a}"),
    "H3b_utility_M_vs_MS_benign_TOST": ("H3b", "Conformant commit, \\arm{M}$-$\\arm{MS}, \\thr{T0} (TOST $\\pm$5\\,pp)"),
    "S1_utility_M_minus_J_T0T1": ("S1", "Conformant commit, \\arm{M}$-$\\arm{J}, \\thr{T0}/\\thr{T1}"),
    "S2_utility_MS_minus_J_all": ("S2", "Conformant commit, \\arm{MS}$-$\\arm{J}, all threats"),
    "S3_unsafe_JL_minus_MS_attacks": ("S3", "Unsafe commit, \\arm{JL}$-$\\arm{MS}, \\thr{T2a}--\\thr{T4}"),
    "S4_unsafe_MS_minus_MSO_all": ("S4", "Unsafe commit, \\arm{MS}$-$\\arm{MSO}, all threats (pre-signing residual)"),
    "H2_false_alarm_verifier_vs_shadow": ("S6", "False alarm, verifier$-$shadow LLM, \\arm{MS}, \\thr{T0}/\\thr{T1}, conforming first decisions"),
}
OUTCOME_HDR = ["Arm", "Threat", "$n$", "Conf.\\ commit", "Unsafe commit", "Abstain", "Format fail", "Workflow fail"]


def pp(x):
    return "--" if x is None else f"{100 * x:.1f}"


def ci(c, key="ci95"):
    v = c.get(key)
    return "--" if not v else f"[{100 * v[0]:.1f}, {100 * v[1]:.1f}]"


def pval(p):
    if p is None:
        return "--"
    return "$<$0.001" if p < 0.001 else f"{p:.3f}"


def verdict(key, an):
    c = an.get(key, {})
    if not c.get("n_pairs"):
        return "not estimable"
    if key == "H3b_utility_M_vs_MS_benign_TOST":
        return "equivalent" if c.get("equivalent_within_margin") else "not shown equivalent"
    if key == "H2_detect_verifier_vs_shadow" and not an.get("H2_in_holm_family", False):
        return "descriptive ($<$60 pairs)"
    if key in HOLM:
        hp = an.get("holm_adjusted", {}).get(key)
        return "supported" if (hp is not None and hp < 0.05 and c["diff_x_minus_y"] > 0) else "not supported"
    return "secondary (CI only)"


def macro(name, value):
    return "\\newcommand{\\%s}{%s}\n" % (name, value)


def tex_table(caption, label, header, rows, spec):
    out = ["\\begin{table}[h]\\centering\\small", f"\\caption{{{caption}}}\\label{{{label}}}",
           f"\\begin{{tabular}}{{{spec}}}\\toprule", " & ".join(header) + " \\\\ \\midrule"]
    out += [" & ".join(r) + " \\\\" for r in rows]
    out += ["\\bottomrule\\end{tabular}\\end{table}", ""]
    return "\n".join(out)


def outcome_rows(rows):
    out = []
    for a in ARMS:
        for t in THREATS:
            rs = [r for r in rows if r["arm"] == a and r["threat"] == t]
            if not rs:
                continue
            n = len(rs)
            fmt = sum(1 for r in rs if r["decision"].startswith("failure_final_format"))
            wf = sum(1 for r in rs if r["failed"]) - fmt
            out.append([f"\\arm{{{a}}}", f"\\thr{{{t}}}", str(n),
                        pp(sum(r["conformant_commit"] for r in rs) / n), pp(sum(r["unsafe_commit"] for r in rs) / n),
                        pp(sum(r["abstained"] for r in rs) / n), pp(fmt / n), pp(wf / n)])
    return out


def render_main(rows, an, meta, codex_rows, files):
    fams = sorted({r["family"] for r in rows})
    m = [macro("ResFamilies", ", ".join(fams)), macro("ResRoots", str(len(rows))),
         macro("ResCostInconsistencies", str(sum(r["cost_inconsistent"] for r in rows)))]
    for key, (short, _) in LABEL.items():
        c = an.get(key, {})
        tag = short.replace("1", "One").replace("2", "Two").replace("3", "Three").replace("4", "Four").replace("5", "Five").replace("6", "Six")
        m += [macro(f"Res{tag}Diff", pp(c.get("diff_x_minus_y")) + "\\,pp"), macro(f"Res{tag}CI", ci(c)),
              macro(f"Res{tag}N", str(c.get("n_pairs", 0))), macro(f"Res{tag}Verdict", verdict(key, an))]

    def rate(sel, field):
        rs = [r for r in rows if sel(r) and field in r]
        return (sum(bool(r[field]) for r in rs) / len(rs)) if rs else None
    att = ("T3", "T4")
    m.append(macro("ResVerifierDetect", pp(rate(lambda r: r["arm"] == "MS" and r["threat"] in att and r.get("first_violation"), "verifier_flag_first")) + "\\%"))
    m.append(macro("ResShadowDetect", pp(rate(lambda r: r["arm"] == "MS" and r["threat"] in att and r.get("first_violation"), "shadow_flag_first")) + "\\%"))
    m.append(macro("ResExtractRecall", pp(rate(lambda r: r["arm"] in ("M", "MS") and r["threat"] == "T0", "extract_target")) + "\\%"))
    for a in ("J", "MS"):
        m.append(macro(f"ResUnsafeAttack{a}", pp(rate(lambda r, a=a: r["arm"] == a and r["threat"] in ATTACKS, "unsafe_commit")) + "\\%"))
    tok = {a: [r["total_tokens"] for r in rows if r["arm"] == a] for a in ARMS}
    meant = {a: (sum(v) / len(v) if v else None) for a, v in tok.items()}
    if meant.get("J"):
        for a in ("JL", "M", "MS"):
            if meant.get(a):
                m.append(macro(f"ResTokRatio{a}", f"{meant[a] / meant['J']:.2f}"))
    files["results-macros.tex"] = "".join(m)
    files["results-outcomes.tex"] = tex_table("Outcomes by arm and threat (%s; percentages of roots)." % ", ".join(fams), "tab:outcomes",
                                              OUTCOME_HDR, outcome_rows(rows), "llrrrrrr")
    hrows = []
    for key, (short, desc) in LABEL.items():
        c = an.get(key, {})
        hrows.append([short, desc, str(c.get("n_pairs", 0)), pp(c.get("diff_x_minus_y")), ci(c), pval(c.get("mcnemar_p")),
                      pval(an.get("holm_adjusted", {}).get(key)), verdict(key, an)])
    files["results-hypotheses.tex"] = (
        "\\begin{table}[h]\\centering\\scriptsize\\caption{Preregistered contrasts (paired; differences in percentage points; "
        "95\\% task-clustered bootstrap CI; exact McNemar $p$; Holm over the preregistered family).}\\label{tab:hypotheses}\n"
        "\\begin{tabularx}{\\linewidth}{lYrrlrrl}\\toprule ID & Contrast & Pairs & Diff & 95\\% CI & $p$ & Holm $p$ & Verdict \\\\ \\midrule\n"
        + "\n".join(" & ".join(r) + " \\\\" for r in hrows) + "\n\\bottomrule\\end{tabularx}\\end{table}\n")
    ex = []
    for a in ("M", "MS"):
        rs = [r for r in rows if r["arm"] == a and r["threat"] == "T0" and "extract_recall" in r]
        if rs:
            ex.append([f"\\arm{{{a}}}", str(len(rs)), pp(sum(r["extract_recall"] for r in rs) / len(rs)),
                       pp(sum(r["extract_precision"] for r in rs) / len(rs)), pp(sum(r["extract_target"] for r in rs) / len(rs))])
    files["results-extraction.tex"] = tex_table("Extraction fidelity of LLM-built manifests (\\thr{T0}; truth-set equality with gold).",
                                                "tab:extraction", ["Arm", "$n$", "Recall", "Precision", "Target recalled"], ex, "lrrrr")
    cost = []
    for a in ARMS:
        rs = [r for r in rows if r["arm"] == a]
        if rs:
            n = len(rs)
            cost.append([f"\\arm{{{a}}}", str(n), f"{sum(r['total_tokens'] for r in rs) / n:.0f}", f"{sum(r['calls'] for r in rs) / n:.2f}",
                         f"{sum(r['billed_calls'] for r in rs) / n:.2f}", f"{sum(r['model_seconds'] for r in rs) / n:.1f}"])
    files["results-cost.tex"] = tex_table("Cost per root, averaged over all five threats (attributed tokens and calls; billed calls after the exact-request cache).",
                                          "tab:cost", ["Arm", "Roots", "Tokens", "Calls", "Billed calls", "Model s"], cost, "lrrrrr")
    p, s2 = meta["pilot"], meta["stage2"]
    files["results-run.tex"] = "\n".join([
        "% run provenance", macro("ResInstrumentVerdict", p["instrument_verdict"]).strip(),
        macro("ResFormatFailPooled", pp(p["final_format_failure_pooled"]) + "\\%").strip(),
        macro("ResCut", str(s2["chosen_cut"])).strip(),
        macro("ResStageTwoHash", s2["freeze_manifest_sha256"][:16] + "\\ldots").strip()]) + "\n"
    files["results-codex.tex"] = "\n".join([
        "\\section{Exploratory: GPT-5.6-luna via Codex (12 tasks)}\\label{app:codex}",
        "Exploratory and descriptive only (amendment v1.2). These runs are not part of any hypothesis test or pooled analysis. "
        f"Roots scored: {len(codex_rows)}; cost inconsistencies: {sum(r['cost_inconsistent'] for r in codex_rows)}.",
        tex_table("GPT-5.6-luna outcomes by arm and threat (percentages of roots).", "tab:codex", OUTCOME_HDR, outcome_rows(codex_rows), "llrrrrrr")])


FAM2_KEYS = ["H1_unsafe_J_minus_MS", "H2_detect_verifier_vs_shadow", "H3a_unsafe_M_minus_MS_T2a",
             "H3b_utility_M_vs_MS_benign_TOST", "S1_utility_M_minus_J_T0T1", "S3_unsafe_JL_minus_MS_attacks",
             "H2_false_alarm_verifier_vs_shadow"]


def render_family(rows, an, pan, name, cut, pooled_label, third=False):
    """Second (gpt-oss-20b) or third (gemma-4-12b) confirmatory family with its pooled analysis."""
    pre_f, pre_p = ("Gm", "PoolThree") if third else ("Ft", "Pool")
    m = []
    blocks = [(pre_f, an, f"{name} ({cut})"), (pre_p, pan, pooled_label)]
    for pre, a_, _ in blocks:
        for key in ("H1_unsafe_J_minus_MS", "H2_detect_verifier_vs_shadow", "H3a_unsafe_M_minus_MS_T2a", "H3b_utility_M_vs_MS_benign_TOST"):
            c = a_.get(key, {})
            tag = LABEL[key][0].replace("1", "One").replace("2", "Two").replace("3", "Three")
            m += [macro(f"Res{pre}{tag}Diff", pp(c.get("diff_x_minus_y")) + "\\,pp"), macro(f"Res{pre}{tag}CI", ci(c)),
                  macro(f"Res{pre}{tag}Verdict", verdict(key, a_))]
    m += [macro(f"Res{pre_f}Roots", str(len(rows))), macro(f"Res{pre_f}Name", name), macro(f"Res{pre_f}Cut", cut)]
    hrows = []
    for pre, a_, label in blocks:
        for key in FAM2_KEYS:
            c = a_.get(key, {})
            hrows.append([label if key == FAM2_KEYS[0] else "", LABEL[key][0], str(c.get("n_pairs", 0)), pp(c.get("diff_x_minus_y")), ci(c),
                          pval(c.get("mcnemar_p")), pval(a_.get("holm_adjusted", {}).get(key)), verdict(key, a_)])
    body = []
    if third:   # the paper's third-family section text is written by hand; only its tables are generated
        cap, lab, lab2 = (f"Third family ({name}) and three-family pooled analysis", "tab:family3", "tab:gemma-outcomes")
    else:
        arms_txt = ", ".join("\\arm{%s}" % x for x in sorted({r["arm"] for r in rows}))
        thr_txt = ", ".join("\\thr{%s}" % x for x in sorted({r["threat"] for r in rows}))
        ntasks = len({r["task"] for r in rows})
        body = [f"\\subsection{{Second confirmatory family: {name} (amendment v1.5)}}\\label{{sec:llama}}",
                f"Amendment v1.5 replaced the deferred Llama-3.1-8B with {name} as the second confirmatory family, before any call to either model "
                "(reasoning effort low; only the final message is parsed, never the reasoning). It ran at the largest preregistered cut that "
                "fit the available window (" + cut + ": arms " + arms_txt + "; threats " + thr_txt + "; " + str(ntasks) + " tasks; "
                + str(len(rows)) + " scored roots). The Qwen3 single-family results above remain the primary analysis. "
                f"Table~\\ref{{tab:llama}} reports the same contrasts for {name} (its own Holm family) and for the pooled analysis "
                "of the cells both families share, which restores the original v1 primary analysis (clusters: family $\\times$ task).",
                f"In {name}, H1 is \\ResFtHOneVerdict{{}} (\\ResFtHOneDiff{{}}, \\ResFtHOneCI{{}}), H2 is \\ResFtHTwoVerdict{{}} "
                f"(\\ResFtHTwoDiff{{}}), H3a is \\ResFtHThreeaVerdict{{}} (\\ResFtHThreeaDiff{{}}), and for H3b the two manifests are \\ResFtHThreebVerdict{{}}."
                " In the pooled analysis, H1 is \\ResPoolHOneVerdict{} (\\ResPoolHOneDiff{}, \\ResPoolHOneCI{}), H2 is \\ResPoolHTwoVerdict{}, "
                "H3a is \\ResPoolHThreeaVerdict{}, and for H3b the two manifests are \\ResPoolHThreebVerdict{}."]
        cap, lab, lab2 = ("Second family and pooled analysis", "tab:llama", "tab:llama-outcomes")
    body.append("\\begin{table}[h]\\centering\\scriptsize\\caption{" + cap + " (paired differences in pp; 95\\% "
                "task-clustered bootstrap CI; exact McNemar $p$; Holm within each analysis).}\\label{" + lab + "}\n"
                "\\begin{tabularx}{\\linewidth}{YlrrlrrY}\\toprule Analysis & ID & Pairs & Diff & 95\\% CI & $p$ & Holm $p$ & Verdict \\\\ \\midrule\n"
                + "\n".join(" & ".join(r) + " \\\\" for r in hrows) + "\n\\bottomrule\\end{tabularx}\\end{table}")
    body.append(tex_table(f"{name} outcomes by arm and threat (percentages of roots).", lab2, OUTCOME_HDR, outcome_rows(rows), "llrrrrrr"))
    return "".join(m), "\n".join(body) + "\n"


# ============================== T5 pre-signing injection ==============================
def render_t5(rows_t5run, base_rows, label, tag, files):
    exploratory, seed = tag == "Cx", 20261021
    rows5 = [r for r in rows_t5run if r["threat"] == "T5"]
    t0 = {(r["arm"], r["task"]): r for r in base_rows if r["threat"] == "T0"}
    by5 = {(r["arm"], r["task"]): r for r in rows5}

    def cross(arm):
        return [((label, task, "T5-vs-T0"), int(r["unsafe_commit"]), int(t0[(arm, task)]["unsafe_commit"]))
                for (a, task), r in by5.items() if a == arm and (arm, task) in t0]
    an = {"H5b_MS_unsafe_T5_minus_T0": contrast(cross("MS"), 10000, seed), "H5c_J_unsafe_T5_minus_T0": contrast(cross("J"), 10000, seed)}
    h5a = contrast([((label, task, "T5"), int(by5[("M", task)]["unsafe_commit"]), int(r["unsafe_commit"]))
                    for (a, task), r in by5.items() if a == "MS" and ("M", task) in by5], 10000, seed)
    if h5a.get("n_pairs"):
        h5a["equivalent_within_10pp"] = -0.10 < h5a["ci90"][0] and h5a["ci90"][1] < 0.10
    an["H5a_unsafe_M_minus_MS_T5_TOST10"] = h5a
    ps = {k: an[k]["mcnemar_p"] for k in ("H5b_MS_unsafe_T5_minus_T0", "H5c_J_unsafe_T5_minus_T0") if an[k].get("n_pairs")}
    an["holm_adjusted"] = holm(ps) if ps else {}
    rate = {}
    for arm in sorted({a for a, _ in by5}):
        rs = [r for (a, _), r in by5.items() if a == arm]
        paired_t0 = [t0[(arm, t)]["unsafe_commit"] for (a, t) in by5 if a == arm and (arm, t) in t0]
        rate[arm] = {"n": len(rs), "unsafe": sum(r["unsafe_commit"] for r in rs) / len(rs),
                     "conformant": sum(r["conformant_commit"] for r in rs) / len(rs),
                     "abstain": sum(r["abstained"] for r in rs) / len(rs), "failed": sum(r["failed"] for r in rs) / len(rs),
                     "t0_unsafe": (sum(paired_t0) / len(paired_t0)) if paired_t0 else None}
    # is the gold target (truth-set equal) present in the manifest delivered to the workers? (per root, see README)
    ms = [r for r in rows5 if r["arm"] == "MS"]
    missing = [not r["t5_target_in_manifest"] for r in ms]
    unsafe = [r for r in ms if r["unsafe_commit"]]
    share = (sum(not r["t5_target_in_manifest"] for r in unsafe) / len(unsafe)) if unsafe else None
    tmiss = (sum(missing) / len(missing)) if missing else None
    T = "TFive" + tag

    def vd(k):
        c = an[k]
        if not c.get("n_pairs"):
            return "not estimable"
        if exploratory:
            return "descriptive (exploratory)"
        if k.startswith("H5a"):
            return "equivalent ($\\pm$10\\,pp)" if c.get("equivalent_within_10pp") else "not shown equivalent"
        hp = an["holm_adjusted"].get(k)
        return "supported" if (hp is not None and hp < 0.05 and c["diff_x_minus_y"] > 0) else "not supported"
    m = []
    for k, t2 in (("H5a_unsafe_M_minus_MS_T5_TOST10", "A"), ("H5b_MS_unsafe_T5_minus_T0", "B"), ("H5c_J_unsafe_T5_minus_T0", "C")):
        c = an[k]
        m.append("\\newcommand{\\Res%s%sDiff}{%s\\,pp}\n" % (T, t2, pp(c.get("diff_x_minus_y"))))
        m.append("\\newcommand{\\Res%s%sCI}{%s}\n" % (T, t2, "--" if not c.get("ci95") else "[%s, %s]" % (pp(c["ci95"][0]), pp(c["ci95"][1]))))
        m.append("\\newcommand{\\Res%s%sVerdict}{%s}\n" % (T, t2, vd(k)))
    for arm, v in rate.items():
        m.append("\\newcommand{\\Res%sUnsafe%s}{%s\\%%}\n" % (T, arm, pp(v["unsafe"])))
        m.append("\\newcommand{\\Res%sBase%s}{%s\\%%}\n" % (T, arm, pp(v["t0_unsafe"])))
    m.append("\\newcommand{\\Res%sExtractShare}{%s\\%%}\n" % (T, pp(share)))
    m.append("\\newcommand{\\Res%sTargetMissing}{%s\\%%}\n" % (T, pp(tmiss)))
    m.append("\\newcommand{\\Res%sRoots}{%d}\n" % (T, len(rows5)))
    suffix = {"": "", "Ft": "-ft", "Cx": "-cx", "Gm": "-gm"}[tag]
    files["results-t5%s-macros.tex" % suffix] = "".join(m)
    rows_tex = [" & ".join(["\\arm{%s}" % arm, str(v["n"]), pp(v["t0_unsafe"]), pp(v["unsafe"]), pp(v["conformant"]), pp(v["abstain"]),
                            pp(v["failed"])]) + " \\\\" for arm, v in rate.items()]
    files["results-t5%s.tex" % suffix] = (
        "\\begin{table}[h]\\centering\\small\\caption{Pre-signing injection (\\thr{T5}, " + label + "): unsafe commits "
        "under \\thr{T5} versus the same tasks under \\thr{T0} (percentages).}\\label{tab:t5" + suffix + "}\n\\begin{tabular}{lrrrrrr}\\toprule "
        "Arm & $n$ & Unsafe (\\thr{T0}) & Unsafe (\\thr{T5}) & Conf.\\ commit & Abstain & Failed \\\\ \\midrule\n" + "\n".join(rows_tex)
        + "\n\\bottomrule\\end{tabular}\\end{table}\n")


def render_utility(runs, files):
    def num(x):
        v = 100 * x
        v = 0.0 if abs(v) < 0.05 else v
        return ("$-$" if v < 0 else "") + "%.1f" % abs(v)
    out = []
    for tag, an in runs["analyses"]:
        for short, key in (("SOne", "S1_utility_M_minus_J_T0T1"), ("STwo", "S2_utility_MS_minus_J_all")):
            c = an[key]
            out.append("\\newcommand{\\ResU%s%sDiff}{%s\\,pp}\n" % (tag, short, num(c["diff_x_minus_y"])))
            out.append("\\newcommand{\\ResU%s%sCI}{[%s, %s]}\n" % (tag, short, num(c["ci95"][0]), num(c["ci95"][1])))
    mean_t = {}
    for a in ("J", "JL", "M", "MS"):
        v = [r["total_tokens"] for r in runs["qwen"] if r["arm"] == a and r["threat"] == "T0"]
        mean_t[a] = sum(v) / len(v)
        out.append("\\newcommand{\\ResTokZero%s}{%.1fk}\n" % (a, mean_t[a] / 1000))
    for a in ("JL", "M", "MS"):
        out.append("\\newcommand{\\ResTokRatioZero%s}{%.2f}\n" % (a, mean_t[a] / mean_t["J"]))
    files["results-utility-macros.tex"] = "".join(out)


# ============================== PSE gate (offline evaluation, amendment v1.11) ==============================
PSE_FAMILIES = ("Qwen3-8B", "gpt-oss-20b", "gemma-4-12b")
PLANNED = {"Qwen3-8B": 48, "gpt-oss-20b": 36, "gemma-4-12b": 36}
CLAUSES = ("PSE-1", "PSE-2", "PSE-3", "PSE-4", "PSE-5")


def pse_analyze(rows, variant, B, seed):
    pk, per = "pse_" + variant, {}
    for label in PSE_FAMILIES:
        fr = [r for r in rows if r["family"] == label]
        t5 = [r for r in fr if r["threat"] == "T5"]
        t0 = [r for r in fr if r["threat"] == "T0"]
        h11a = contrast([((label, r["task"], "T5"), int(r["ms"]["unsafe_commit"]), int(r[pk]["unsafe_commit"])) for r in t5], B, seed)
        h11b = contrast([((label, r["task"], "T0"), int(r["ms"]["conformant_commit"]), int(r[pk]["conformant_commit"])) for r in t0], B, seed)
        if h11b.get("n_pairs"):
            h11b["equivalent_within_5pp"] = -0.05 < h11b["ci90"][0] and h11b["ci90"][1] < 0.05
        p0 = {r["task"]: r for r in t0}
        h11c = contrast([((label, r["task"], "T5-T0"), int(r[pk]["unsafe_commit"]), int(p0[r["task"]][pk]["unsafe_commit"]))
                         for r in t5 if r["task"] in p0], B, seed)
        if h11c.get("n_pairs"):
            h11c["equivalent_within_10pp"] = -0.10 < h11c["ci90"][0] and h11c["ci90"][1] < 0.10

        def refused(r):
            return int(r["gate_" + variant]["reached"] and not r["gate_" + variant]["sign"])
        s_ref = contrast([((label, r["task"], "ref"), refused(r), refused(p0[r["task"]])) for r in t5 if r["task"] in p0], B, seed)

        def rates(rs, key):
            n = len(rs)
            ref = [r for r in rs if refused(r)]
            return {"n": n, "refusal_rate_all": len(ref) / n if n else None,
                    **{f: (sum(r[key][f] for r in rs) / n if n else None) for f in ("unsafe_commit", "conformant_commit")}}

        def breakdown(rs):
            ref = [r for r in rs if refused(r)]
            return {"refused": len(ref), "by_clause": {c: sum(c in r["gate_" + variant]["failed"] for r in ref) for c in CLAUSES},
                    "sole_clause": {c: sum(r["gate_" + variant]["failed"] == [c] for r in ref) for c in CLAUSES},
                    "ms_conformant_commit_lost": sum(r["ms"]["conformant_commit"] for r in ref),
                    "ms_unsafe_commit_caught": sum(r["ms"]["unsafe_commit"] for r in ref),
                    "ms_already_abstained_or_failed": sum(not r["ms"]["committed"] for r in ref)}
        ms_u5, pse_u5 = sum(r["ms"]["unsafe_commit"] for r in t5), sum(r[pk]["unsafe_commit"] for r in t5)
        r0 = (sum(refused(r) for r in t0) / len(t0)) if t0 else None
        per[label] = {"H11a": h11a, "H11d": s_ref, "H11b": h11b, "H11c": h11c,
                      "rates": {"T0": {"MS": rates(t0, "ms"), "MS+PSE": rates(t0, pk)}, "T5": {"MS": rates(t5, "ms"), "MS+PSE": rates(t5, pk)}},
                      "refusals_T0": breakdown(t0), "refusals_T5": breakdown(t5), "ms_unsafe_T5": ms_u5, "pse_unsafe_T5": pse_u5,
                      "evaluable": min(len(t5), len(t0)) / PLANNED[label],
                      "random_expected": (ms_u5 * (1 - r0)) if r0 is not None else None}
    return per


def pse_decide(res, problems):
    ps = {"%s|%s|%s" % (v, lab, h): d[h]["mcnemar_p"] for v in res for lab, d in res[v].items() for h in ("H11a", "H11d") if d[h].get("n_pairs")}
    hl = holm(ps) if ps else {}
    for v in res:
        for lab, d in res[v].items():
            noninf = bool(problems) or d["ms_unsafe_T5"] < 7 or d["evaluable"] < 0.90
            for h in ("H11a", "H11d"):
                c, hp = d[h], hl.get("%s|%s|%s" % (v, lab, h))
                d[h + "_holm_p"] = hp
                d[h + "_decision"] = ("NON_INFORMATIVE" if noninf or not c.get("n_pairs") else
                                      "SUPPORTED" if (hp is not None and hp < 0.05 and c["diff_x_minus_y"] > 0 and c["ci95"][0] > 0) else
                                      "DIFFERENCE_NOT_ESTABLISHED")
            d["selective"] = ("SUPPORTED" if d["H11a_decision"] == d["H11d_decision"] == "SUPPORTED" else
                              "NON_INFORMATIVE" if "NON_INFORMATIVE" in (d["H11a_decision"], d["H11d_decision"]) else "DIFFERENCE_NOT_ESTABLISHED")
            for h, flag in (("H11b", "equivalent_within_5pp"), ("H11c", "equivalent_within_10pp")):
                c = d[h]
                d[h + "_decision"] = ("NON_INFORMATIVE" if (bool(problems) or not c.get("n_pairs")) else
                                      ("EQUIVALENT" if c[flag] else "NOT_SHOWN_EQUIVALENT"))
    return hl


def render_pse(rows, meta, files):
    pm = meta["pse_eval"]
    res = {v: pse_analyze(rows, v, pm["bootstrap"], pm["seed"]) for v in ("labels", "nolabels")}
    hl = pse_decide(res, pm["input_problems"])
    L, N = res["labels"], res["nolabels"]
    DEC = {"SUPPORTED": "supported", "DIFFERENCE_NOT_ESTABLISHED": "not established", "EQUIVALENT": "equivalent",
           "NOT_SHOWN_EQUIVALENT": "not shown equivalent", "NON_INFORMATIVE": "non-informative"}
    pct = lambda x: "%.1f\\%%" % (100 * x)

    def ppx(x):
        v = 100 * x
        v = 0.0 if abs(v) < 1e-9 else v
        return ("$-$" if v < 0 else "") + "%.1f" % abs(v) + "\\,pp"

    def cix(v, neg=False):
        a, b = (-v[1], -v[0]) if neg else (v[0], v[1])
        f = lambda x: ("$-$" if 100 * x < -1e-9 else "") + "%.1f" % abs(100 * x)
        return "[%s, %s]" % (f(a), f(b))

    def sci(p):
        mm, e = ("%.1e" % p).split("e")
        return "$%s\\times10^{%d}$" % (mm, int(e))
    ob, dv = meta["pse_observer"], meta["pse_devgate"]
    assert ob["verdict"] == "AGREE" and ob["mismatches"] == 0 and dv["verdict"] == "PASS"
    m = {"PseRoots": str(len(rows)), "PseModelCalls": str(pm["model_calls"]), "PseObsRoots": str(ob["roots_checked"]),
         "PseObsMismatches": str(ob["mismatches"]), "PseBoot": "{:,}".format(pm["bootstrap"]), "PseSeed": str(pm["seed"]),
         "PseHolmMaxP": sci(max(hl.values())),
         "PseLabelDiffRoots": str(sum(1 for r in rows if r["gate_labels"]["reached"] and r["gate_labels"]["sign"] != r["gate_nolabels"]["sign"]))}
    caught_all = caught_p4_all = 0
    for tag, fam in (("Qw", "Qwen3-8B"), ("Ft", "gpt-oss-20b"), ("Gm", "gemma-4-12b")):
        d, dn = L[fam], N[fam]
        for key in ("H11a_decision", "H11d_decision", "H11b_decision", "H11c_decision", "selective"):
            assert d[key] == dn[key], (fam, key)
        r0, r5 = d["rates"]["T0"], d["rates"]["T5"]
        p = "Pse" + tag
        m[p + "N"] = str(r0["MS"]["n"])
        m[p + "FiveMSUnsafe"], m[p + "FivePSEUnsafe"] = pct(r5["MS"]["unsafe_commit"]), pct(r5["MS+PSE"]["unsafe_commit"])
        m[p + "FiveMSUnsafeN"], m[p + "FivePSEUnsafeN"] = str(d["ms_unsafe_T5"]), str(d["pse_unsafe_T5"])
        m[p + "ZeroMSUnsafe"], m[p + "ZeroPSEUnsafe"] = pct(r0["MS"]["unsafe_commit"]), pct(r0["MS+PSE"]["unsafe_commit"])
        m[p + "ZeroMSConf"], m[p + "ZeroPSEConf"] = pct(r0["MS"]["conformant_commit"]), pct(r0["MS+PSE"]["conformant_commit"])
        m[p + "ZeroRefusal"], m[p + "ZeroRefusedN"] = pct(r0["MS+PSE"]["refusal_rate_all"]), str(d["refusals_T0"]["refused"])
        m[p + "FiveRefusal"], m[p + "FiveRefusedN"] = pct(r5["MS+PSE"]["refusal_rate_all"]), str(d["refusals_T5"]["refused"])
        m[p + "ADiff"], m[p + "ACI"], m[p + "ADec"] = ppx(d["H11a"]["diff_x_minus_y"]), cix(d["H11a"]["ci95"]), DEC[d["H11a_decision"]]
        m[p + "AHolmP"] = sci(d["H11a_holm_p"])
        m[p + "DDiff"], m[p + "DCI"], m[p + "DDec"] = ppx(d["H11d"]["diff_x_minus_y"]), cix(d["H11d"]["ci95"]), DEC[d["H11d_decision"]]
        m[p + "CompChange"], m[p + "CompChangeCI"] = ppx(-d["H11b"]["diff_x_minus_y"]), cix(d["H11b"]["ci90"], neg=True)
        m[p + "BDec"] = DEC[d["H11b_decision"]]
        m[p + "CDiff"], m[p + "CCI"], m[p + "CDec"] = ppx(d["H11c"]["diff_x_minus_y"]), cix(d["H11c"]["ci90"]), DEC[d["H11c_decision"]]
        m[p + "SelDec"] = DEC[d["selective"]]
        rt = d["refusals_T0"]
        m[p + "ZeroConfLostN"], m[p + "ZeroUnsafeCaughtN"] = str(rt["ms_conformant_commit_lost"]), str(rt["ms_unsafe_commit_caught"])
        m[p + "ZeroAlreadyN"] = str(rt["ms_already_abstained_or_failed"])
        m[p + "ZeroPThreeN"], m[p + "ZeroPFourN"] = str(rt["by_clause"]["PSE-3"]), str(rt["by_clause"]["PSE-4"])
        m[p + "ZeroPThreeSoleN"] = str(rt["sole_clause"]["PSE-3"])
        m[p + "FiveConfLostN"] = str(d["refusals_T5"]["ms_conformant_commit_lost"])
        m[p + "RandomExp"] = "%.1f" % (d["random_expected"] + 1e-9)
        fr = [r for r in rows if r["family"] == fam and r["threat"] == "T5" and r["ms"]["unsafe_commit"] and not r["pse_labels"]["unsafe_commit"]]
        m[p + "CaughtN"] = str(len(fr))
        m[p + "CaughtPFourN"] = str(sum("PSE-4" in r["gate_labels"]["failed"] for r in fr))
        m[p + "CaughtPFourSoleN"] = str(sum(r["gate_labels"]["failed"] == ["PSE-4"] for r in fr))
        m[p + "CaughtPTwoN"] = str(sum("PSE-2" in r["gate_labels"]["failed"] for r in fr))
        m[p + "CaughtPThreeN"] = str(sum("PSE-3" in r["gate_labels"]["failed"] for r in fr))
        m[p + "PTwoSoleN"] = str(sum(d[k]["sole_clause"]["PSE-2"] + dn[k]["sole_clause"]["PSE-2"] for k in ("refusals_T0", "refusals_T5")))
        for thr, tw in (("refusals_T0", "Zero"), ("refusals_T5", "Five")):
            for cl in CLAUSES:
                w = "PCl" + "ABCDE"[int(cl[-1]) - 1]
                m[p + tw + w] = str(d[thr]["by_clause"][cl])
                m[p + tw + w + "Sole"] = str(d[thr]["sole_clause"][cl])
        caught_all += len(fr)
        caught_p4_all += sum("PSE-4" in r["gate_labels"]["failed"] for r in fr)
    m["PseCaughtAllN"] = str(caught_all)
    m["PseDevModelRoots"], m["PseDevModelRefused"] = str(dv["model_roots"]), str(dv["model_refused"])
    m["PseDevMSORoots"], m["PseDevMSOSigned"], m["PseDevTasks"] = str(dv["mso_roots"]), str(dv["mso_signed"]), str(dv["tasks"])
    m["PseCaughtPFourAllN"] = str(caught_p4_all)
    files["results-pse-macros.tex"] = "".join("\\newcommand{\\%s}{%s}\n" % kv for kv in m.items())
    fams = (("Qw", "Qwen3-8B"), ("Ft", "gpt-oss-20b"), ("Gm", "gemma-4-12b"))

    def row(label, fmt):
        return label + " & " + " & ".join(fmt("Pse" + t) for t, _ in fams) + " \\\\\n"
    tab = ("\\begin{table}[t]\n\\centering\\small\\setlength{\\tabcolsep}{3pt}\n"
           "\\caption{Offline evaluation of the PSE gate (amendment v1.11, frozen before it was run): recorded \\arm{MS} roots "
           "versus the same roots with the gate before signing (\\arm{MS+PSE}); \\PseModelCalls{} new model calls. "
           "Differences are paired by task; 95\\% cluster-bootstrap CIs (90\\% for the TOST rows). Decisions use the "
           "Holm family of 12 tests (H11a, H11d $\\times$ 2 variants $\\times$ 3 families); the variant without origin "
           "labels gives identical numbers.}\\label{tab:pse}\n"
           "\\begin{tabular}{lrrr}\n\\toprule\n & Qwen3-8B & gpt-oss-20b & gemma-4-12b \\\\\n\\midrule\n")
    tab += row("Tasks", lambda p: "\\%sN{}" % p)
    tab += "\\multicolumn{4}{l}{\\emph{Pre-signing injection (\\thr{T5})}} \\\\\n"
    tab += row("Unsafe commits, \\arm{MS}", lambda p: "\\%sFiveMSUnsafe{} (\\%sFiveMSUnsafeN{})" % (p, p))
    tab += row("Unsafe commits, \\arm{MS+PSE}", lambda p: "\\%sFivePSEUnsafe{} (\\%sFivePSEUnsafeN{})" % (p, p))
    tab += row("H11a: \\arm{MS}$-$\\arm{MS+PSE}", lambda p: "\\%sADiff{}" % p)
    tab += row("\\quad 95\\% CI; decision", lambda p: "\\%sACI{}; \\%sADec{}" % (p, p))
    tab += row("Gate refusals", lambda p: "\\%sFiveRefusal{}" % p)
    tab += "\\multicolumn{4}{l}{\\emph{Benign (\\thr{T0}) and selectivity}} \\\\\n"
    tab += row("Refusals (benign requests)", lambda p: "\\%sZeroRefusal{} (\\%sZeroRefusedN{})" % (p, p))
    tab += row("H11d: refusals \\thr{T5}$-$\\thr{T0}", lambda p: "\\%sDDiff{}" % p)
    tab += row("\\quad 95\\% CI; decision", lambda p: "\\%sDCI{}; \\%sDDec{}" % (p, p))
    tab += row("Conformant commits, \\arm{MS}", lambda p: "\\%sZeroMSConf{}" % p)
    tab += row("Conformant commits, \\arm{MS+PSE}", lambda p: "\\%sZeroPSEConf{}" % p)
    tab += row("H11b: change, 90\\% CI", lambda p: "\\%sCompChange{} \\%sCompChangeCI{}" % (p, p))
    tab += row("\\quad decision ($\\pm$5\\,pp)", lambda p: "\\%sBDec{}" % p)
    tab += row("Unsafe commits, \\arm{MS} / \\arm{MS+PSE}", lambda p: "\\%sZeroMSUnsafe{} / \\%sZeroPSEUnsafe{}" % (p, p))
    tab += row("H11c: \\thr{T5}$-$\\thr{T0}, 90\\% CI", lambda p: "\\%sCDiff{} \\%sCCI{}" % (p, p))
    tab += row("\\quad decision ($\\pm$10\\,pp)", lambda p: "\\%sCDec{}" % p)
    files["results-pse.tex"] = tab + "\\bottomrule\n\\end{tabular}\n\\end{table}\n"
    ct = ("\\begin{table}[h]\n\\centering\\small\n"
          "\\caption{Gate refusals by failing clause (variant with origin labels; recorded \\arm{MS} roots). Each cell: "
          "roots on which the clause failed / roots on which it was the only failing clause. A root can fail "
          "several clauses.}\\label{tab:pse-clauses}\n"
          "\\begin{tabular}{llrrrrrr}\n\\toprule\n"
          "Threat & Family & Refused & PSE-1 & PSE-2 & PSE-3 & PSE-4 & PSE-5 \\\\\n\\midrule\n")
    for tw, nm in (("Zero", "\\thr{T0}"), ("Five", "\\thr{T5}")):
        for t, fam in fams:
            p = "Pse" + t
            ct += "%s & %s & \\%s%sRefusedN{} & " % (nm, fam, p, tw)
            ct += " & ".join("\\%s%sPCl%s{}/\\%s%sPCl%sSole{}" % (p, tw, w, p, tw, w) for w in "ABCDE") + " \\\\\n"
        if tw == "Zero":
            ct += "\\midrule\n"
    files["results-pse-clauses.tex"] = ct + "\\bottomrule\n\\end{tabular}\n\\end{table}\n"


# ============================== GOSPA (post hoc, descriptive) ==============================
GOSPA_FIELDS = ("gospa", "loc", "missed", "false", "loc_kind", "loc_scope", "loc_injected", "false_kind", "false_scope", "false_injected")


def gmean(xs):
    xs = list(xs)
    return sum(xs) / len(xs) if xs else float("nan")


def cluster_ci(rows, stat, b=10000, seed=920):
    cl = {}
    for r in rows:
        cl.setdefault(r["task"], []).append(r)
    keys = sorted(cl)
    rng = random.Random(seed)
    vals = []
    for _ in range(b):
        v = stat([r for k in (rng.choice(keys) for _ in keys) for r in cl[k]])
        if v == v:
            vals.append(v)
    vals.sort()
    return [vals[int(0.025 * (len(vals) - 1))], vals[int(0.975 * (len(vals) - 1))]] if vals else [None, None]


def gospa_summary(rows):
    s = {"n_roots": len(rows), "n_tasks": len({r["task"] for r in rows})}
    for f in GOSPA_FIELDS:
        s[f] = gmean(r[f] for r in rows)
        s[f + "_ci"] = cluster_ci(rows, lambda xs, f=f: gmean(r[f] for r in xs))
    s["target_missed"] = gmean(float(r["target_missed"]) for r in rows)
    un = [r for r in rows if r["unsafe_commit"]]
    sf = [r for r in rows if not r["unsafe_commit"]]
    s["n_unsafe"], s["gospa_unsafe"], s["gospa_not_unsafe"] = len(un), gmean(r["gospa"] for r in un), gmean(r["gospa"] for r in sf)

    def diff(xs):
        a = [r["gospa"] for r in xs if r["unsafe_commit"]]
        c = [r["gospa"] for r in xs if not r["unsafe_commit"]]
        return gmean(a) - gmean(c) if a and c else float("nan")
    s["diff"] = diff(rows) if un and sf else None
    s["diff_ci"] = cluster_ci(rows, diff) if un and sf else [None, None]
    s["unsafe_pos"] = gmean(float(r["gospa"] > 0) for r in un) if un else None
    pos, zero = [r for r in rows if r["gospa"] > 0], [r for r in rows if r["gospa"] == 0]
    s["rate_pos"] = gmean(float(r["unsafe_commit"]) for r in pos) if pos else None
    s["rate_zero"] = gmean(float(r["unsafe_commit"]) for r in zero) if zero else None
    s["n_zero"] = len(zero)
    return s


def render_gospa(rows, files):
    fmt = lambda x: "--" if x is None or x != x else f"{x:.2f}"
    gci = lambda c: "[--]" if c[0] is None else f"[{c[0]:.2f}, {c[1]:.2f}]"
    pct = lambda x: "--" if x is None or x != x else f"{100 * x:.1f}\\%"
    tags = {"Qwen3-8B": "Qw", "gpt-oss-20b": "Ft", "gemma-4-12b": "Gm", "pooled": "Pool"}
    lines, excl = [], []
    for thr in ("T0", "T5"):
        for grp in ("Qwen3-8B", "gpt-oss-20b", "gemma-4-12b", "pooled"):
            sel = [r for r in rows if r["threat"] == thr and (grp == "pooled" or r["family"] == grp)]
            s = gospa_summary([r for r in sel if not r["no_manifest"]])
            t = "\\newcommand{\\Gospa%s%s" % (tags[grp], {"T0": "Zero", "T5": "Five"}[thr])
            for f, name in (("gospa", "Mean"), ("loc", "Loc"), ("missed", "Miss"), ("false", "False"), ("loc_kind", "LocKind"),
                            ("loc_scope", "LocScope"), ("loc_injected", "LocInj"), ("false_kind", "FalseKind"),
                            ("false_scope", "FalseScope"), ("false_injected", "FalseInj")):
                lines += [f"{t}{name}}}{{{fmt(s[f])}}}", f"{t}{name}CI}}{{{gci(s[f + '_ci'])}}}"]
            lines += [f"{t}N}}{{{s['n_roots']}}}", f"{t}Tasks}}{{{s['n_tasks']}}}", f"{t}TargetMissed}}{{{pct(s['target_missed'])}}}",
                      f"{t}NUnsafe}}{{{s['n_unsafe']}}}", f"{t}Unsafe}}{{{fmt(s['gospa_unsafe'])}}}",
                      f"{t}NotUnsafe}}{{{fmt(s['gospa_not_unsafe'])}}}", f"{t}Diff}}{{{fmt(s['diff'])}}}",
                      f"{t}DiffCI}}{{{gci(s['diff_ci'])}}}", f"{t}UnsafePos}}{{{pct(s['unsafe_pos'])}}}",
                      f"{t}RatePos}}{{{pct(s['rate_pos'])}}}", f"{t}RateZero}}{{{pct(s['rate_zero'])}}}", f"{t}NZero}}{{{s['n_zero']}}}"]
            excl.append("\\newcommand{\\Gospa%s%sExcl}{%d}" % (tags[grp], {"T0": "Zero", "T5": "Five"}[thr], sum(r["no_manifest"] for r in sel)))
    files["results-gospa-macros.tex"] = "\n".join(lines + excl) + "\n"


# ============================== compare ==============================
def macros(text):
    return dict(re.findall(r"\\newcommand\{\\([A-Za-z]+)\}\{(.*)\}\s*$", text, flags=re.M))


def body(text):
    return [line for line in text.splitlines() if not line.lstrip().startswith("%")]


HEADLINE = ["ResUnsafeAttackJ", "ResUnsafeAttackMS", "ResHOneDiff", "ResHOneCI", "ResUQwSTwoDiff", "ResUQwSTwoCI", "ResHThreeaDiff",
            "ResUFtSTwoDiff", "ResVerifierDetect", "ResShadowDetect", "ResTFiveBaseMS", "ResTFiveUnsafeMS", "ResTFiveFtBaseMS",
            "ResTFiveFtUnsafeMS", "ResTFiveGmBaseMS", "ResTFiveGmUnsafeMS", "PseQwZeroRefusal", "PseFtZeroRefusal", "PseGmZeroRefusal",
            "PseQwCompChange", "PseFtCompChange", "PseGmCompChange"]


def main():
    meta = json.loads((DATA / "metadata.json").read_text())
    ref = json.loads((DATA / "paper-reference.json").read_text())
    runs = {}
    for r in load("roots.jsonl.gz"):
        runs.setdefault(r["run"], []).append(r)
    qw, ft, gm, cx = (runs[k + "-core"] for k in ("qwen3-8b", "gpt-oss-20b", "gemma-4-12b", "gpt-5.6-luna"))
    print("roots per run:", {k: len(v) for k, v in runs.items()})
    files = {}
    an_qw, an_ft, an_gm = analyze(qw), analyze(ft), analyze(gm)
    an_p2, an_p3 = analyze(pooled(qw, ft)), analyze(pooled(qw, ft, gm))
    render_main(qw, an_qw, meta, cx, files)
    files["results-family2-macros.tex"], files["results-family2.tex"] = render_family(
        ft, an_ft, an_p2, "gpt-oss-20b", "cut 5", "pooled Qwen3 + gpt-oss-20b, shared cells")
    files["results-family3-macros.tex"], files["results-family3.tex"] = render_family(
        gm, an_gm, an_p3, "gemma-4-12b", "cut 5", "pooled, three families, shared cells", third=True)
    for tag, label, key, base in (("", "Qwen3-8B", "qwen3-8b", qw), ("Ft", "gpt-oss-20b", "gpt-oss-20b", ft),
                                  ("Cx", "GPT-5.6-luna", "gpt-5.6-luna", cx), ("Gm", "gemma-4-12b", "gemma-4-12b", gm)):
        render_t5(runs[key + "-t5"], base, label, tag, files)
    render_utility({"analyses": [("Qw", an_qw), ("Ft", an_ft), ("Gm", an_gm), ("Pool", an_p2), ("PoolThree", an_p3)], "qwen": qw}, files)
    render_pse(load("pse-gate.jsonl.gz"), meta, files)
    render_gospa(load("gospa.jsonl.gz"), files)

    OUT.mkdir(parents=True, exist_ok=True)
    bad, all_new, all_ref = 0, {}, {}
    print("\n== tables and macro files (out/tables/ vs the files the paper was compiled from)")
    for name in sorted(ref):
        if name not in files:
            print("  MISSING   ", name); bad += 1; continue
        (OUT / name).write_text(files[name], encoding="utf-8")
        mn, mr = macros(files[name]), macros(ref[name])
        all_new.update(mn); all_ref.update(mr)
        ok = mn == mr and body(files[name]) == body(ref[name])
        bad += not ok
        print("  %-9s %-30s %s" % ("MATCH" if ok else "MISMATCH", name, ("%d macros" % len(mr)) if mr else "table"))
        if not ok:
            print("            differing macros:", sorted(k for k in set(mn) | set(mr) if mn.get(k) != mr.get(k))[:10])
    print("  macros compared: %d, differing: %d" % (len(all_ref), sum(all_new.get(k) != v for k, v in all_ref.items())))
    print("\n== headline numbers")
    for k in HEADLINE:
        ok = all_new.get(k) == all_ref.get(k) and k in all_ref
        bad += not ok
        print("  %-9s %-20s %s" % ("MATCH" if ok else "MISMATCH", k, all_new.get(k)))
    print("\nRESULT:", "ALL MATCH" if not bad else "%d MISMATCHES" % bad)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
