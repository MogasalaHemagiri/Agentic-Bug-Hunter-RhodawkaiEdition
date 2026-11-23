// Canonical Go module path for this repository (matches GitHub's go-import meta).
//
// Release tags v1–v6 were published before this file existed, so the Go module
// proxy recorded them as github.com/shuvonsec/claude-bug-bounty …+incompatible
// (the pre-rename / pre-transfer path). New versions use this path.
//
// Old require lines keep working via the GitHub repo redirect; new consumers
// should depend on github.com/Rhodawk-AI/Agentic-Bug-Hunter-RhodawkaiEdition.
//
// RhodawkAI Edition fork note: the Go module path is UNCHANGED from upstream
// (intentional — changing it would break existing requires and Go tooling).
// This edition only adds the reconFTW capability-delegation layer in Python
// (bughunter/tools/capability_registry.py + rtw_adapter.py); no Go code differs
// from upstream at this tag.
module github.com/Rhodawk-AI/Agentic-Bug-Hunter-RhodawkaiEdition

go 1.22
