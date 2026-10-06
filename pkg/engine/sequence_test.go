package engine

import "testing"

func TestInferIntentReputation(t *testing.T) {
	ctx := ParseString("0ad4d7e750c2607ecc9dc4ce5f84d57bfccca1ede2756909d4933c4dab12cd34")
	if got := InferIntent(ctx); got != IntentReputation {
		t.Fatalf("lone hash intent = %q, want Reputation", got)
	}
}

func TestInferIntentPostMortem(t *testing.T) {
	ctx := ParseString("Program received signal SIGSEGV\n0x00007ffff7a0d1c2 in __libc_start_main\nrip 0x401136")
	if got := InferIntent(ctx); got != IntentPostMortem {
		t.Fatalf("crash intent = %q, want Post-Mortem", got)
	}
}

func TestInferIntentContainment(t *testing.T) {
	ctx := ParseString("Oct 05 10:00:01 host sshd[1]: Failed password for root from 203.0.113.9\nOct 05 10:00:02 host sshd[2]: Failed password for root from 203.0.113.9\n")
	if ctx.Format != FormatLog {
		t.Fatalf("expected log format, got %q", ctx.Format)
	}
	if got := InferIntent(ctx); got != IntentContainment {
		t.Fatalf("active-failure intent = %q, want Containment", got)
	}
}

func TestInferIntentNone(t *testing.T) {
	ctx := ParseString("just connected to example.com over https")
	if got := InferIntent(ctx); got != IntentNone {
		t.Fatalf("intent = %q, want none", got)
	}
}

// report helper
func mkReport(tools ...ToolRec) *Report {
	return &Report{
		Context: &Context{Entities: map[EntityKind][]string{}},
		Recommendations: []Recommendation{
			{PluginID: "p", Name: "P", Domain: tools[0].Domain, Tools: tools},
		},
	}
}

func TestSequenceOrdersByStepNonDestructiveFirst(t *testing.T) {
	r := mkReport(
		ToolRec{Name: "exploit", Domain: "reversing", Step: 4, Installed: true},
		ToolRec{Name: "triage", Domain: "reversing", Step: 1, Installed: true},
		ToolRec{Name: "static", Domain: "reversing", Step: 2, Installed: true},
	)
	seq := BuildSequence(r, "reversing", IntentNone)
	if len(seq.Phases) != 3 {
		t.Fatalf("want 3 phases, got %d", len(seq.Phases))
	}
	// Phases must be ordered 1,2,4 (ascending step).
	if seq.Phases[0].Tools[0].Tool.Name != "triage" {
		t.Fatalf("first phase tool = %q, want triage", seq.Phases[0].Tools[0].Tool.Name)
	}
	if seq.Phases[len(seq.Phases)-1].Tools[0].Tool.Name != "exploit" {
		t.Fatalf("last phase tool should be the exploit step")
	}
}

func TestSequenceInfersStepWhenUnset(t *testing.T) {
	r := mkReport(
		ToolRec{Name: "crack", Binary: "hashcat", Command: "hashcat -m 0 h wl", Domain: "crypto"},
		ToolRec{Name: "ident", Binary: "file", Command: "file x", Domain: "crypto"},
	)
	seq := BuildSequence(r, "", IntentNone)
	// file (passive) should land in an earlier phase than hashcat (active).
	var fileStep, hashStep int
	for _, ph := range seq.Phases {
		for _, st := range ph.Tools {
			if st.Tool.Name == "ident" {
				fileStep = st.Step
			}
			if st.Tool.Name == "crack" {
				hashStep = st.Step
			}
		}
	}
	if !(fileStep < hashStep) {
		t.Fatalf("passive file (step %d) should precede active hashcat (step %d)", fileStep, hashStep)
	}
}

func TestIntentReputationDemotesCracking(t *testing.T) {
	vt := ToolRec{Name: "vt", Binary: "vt", Command: "vt file abc", Purpose: "VirusTotal reputation", Domain: "general"}
	jc := ToolRec{Name: "john", Binary: "john", Command: "john hash", Domain: "crypto"}
	rep := classifyStep(vt, IntentReputation)
	crk := classifyStep(jc, IntentReputation)
	if rep != 1 {
		t.Fatalf("reputation tool step = %d, want 1", rep)
	}
	if crk < 3 {
		t.Fatalf("cracking step under reputation intent = %d, want >=3", crk)
	}
}
