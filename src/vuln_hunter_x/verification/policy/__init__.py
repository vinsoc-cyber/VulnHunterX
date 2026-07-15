# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Rule-family evidence-closure policy layer.

A family policy declares the decisive fact slots for a vulnerability family and
a declarative TP/FP/NMD entailment over those facts. Findings whose CWE / rule
selects a policy are verified through the evidence-closure path (mandatory
retrieval + policy entailment) instead of the legacy model-verdict path.
"""
