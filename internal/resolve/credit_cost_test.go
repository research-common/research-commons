package resolve

import (
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/research-common/research-commons/internal/keylog"
)

func creditCostTask(n int) *Task {
	task := &Task{}
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("%064x", i)
		task.Submissions = append(task.Submissions, &Submission{Statement: id, Signer: "key", Counts: true, Verdict: "accept"})
		task.Decisions = append(task.Decisions, &Decision{Statement: "d" + id, Counts: true, Verdict: "accept", Submissions: []string{id}})
	}
	return task
}

func TestCreditDecisionIndexMatchesWalk(t *testing.T) {
	task := creditCostTask(12)
	task.Submissions[0].Signer = "other"
	task.Submissions[1].Counts = false
	task.Decisions[2].Counts = false
	task.Decisions[3].SupersededBy = "later"
	task.Decisions[4].Submissions = append(task.Decisions[4].Submissions, task.Submissions[5].Statement)
	for _, key := range []string{"key", "other", "absent"} {
		got, want := &Credit{}, &Credit{}
		gc, wc := map[string]bool{}, map[string]bool{}
		gv, wv := map[string]string{}, map[string]string{}
		got.taskCredit(key, task, gc, gv)
		want.scanTaskCredit(key, task, wc, wv)
		if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(gc, wc) || !reflect.DeepEqual(gv, wv) {
			t.Fatalf("credit index changed %s: %+v %+v", key, got, want)
		}
	}
}

// Isolate the per-submission decision lookup from Task construction and crypto. The
// helper is the production Credit path, and includes building the per-task index.
func TestCreditDecisionCostIsLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("cost comparison")
	}
	build := func(n int) func() {
		task := creditCostTask(n)
		return func() {
			c := &Credit{}
			c.taskCredit("key", task, map[string]bool{}, map[string]string{})
			if len(c.Explain) != n {
				t.Fatal("missing settled decisions")
			}
		}
	}
	wantLinear(t, 8, build(1000), build(8000))
}

func (c *Credit) scanTaskCredit(key string, t *Task, counted map[string]bool, verdict map[string]string) {
	mine := map[string]bool{}
	for _, s := range t.Submissions {
		mine[s.Statement] = s.Signer == key
	}
	for _, d := range t.Decisions {
		if d.Counts {
			counted[d.Statement] = true
		}
		if d.Counts && d.SupersededBy != "" {
			for _, s := range d.Submissions {
				if !mine[s] {
					continue
				}
				c.Explain = append(c.Explain, fmt.Sprintf("decision %s (%s %s) superseded by %s: kept in the log, no longer counted", keylog.Short(d.Statement), d.Verdict, keylog.Short(s), keylog.Short(d.SupersededBy)))
			}
		}
	}
	for _, s := range t.Submissions {
		if s.Signer == key && s.Counts && s.Verdict != "" {
			verdict[s.Statement] = s.Verdict
			for _, d := range t.Decisions {
				if d.Counts && d.SupersededBy == "" && slices.Contains(d.Submissions, s.Statement) {
					c.Explain = append(c.Explain, fmt.Sprintf("submission %s: %s by decision %s", keylog.Short(s.Statement), d.Verdict, keylog.Short(d.Statement)))
				}
			}
		}
	}
}
