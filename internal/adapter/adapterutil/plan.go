package adapterutil

import (
	"context"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

// SingleStepPlan строит план из одного шага. Description показывается в UI и
// не должен содержать секретов.
func SingleStepPlan(change adapter.DesiredChange, kind, desc string, attrs map[string]any) *adapter.Plan {
	return &adapter.Plan{
		Change: change,
		Steps: []adapter.PlanStep{{
			Kind:        kind,
			Description: desc,
			Attributes:  attrs,
		}},
	}
}

// VerifyResult строит Verification с человекочитаемыми Details без секретов.
func VerifyResult(ok bool, what string) *adapter.Verification {
	if ok {
		return &adapter.Verification{Verified: true, Details: "verified: " + what}
	}
	return &adapter.Verification{Verified: false, Details: "not in expected state: " + what}
}

// ApplySteps выполняет шаги плана по общему для adapters протоколу: шаги
// применяются по порядку через apply; первая ошибка помечает шаг StepFailed
// (текст без секретов), все последующие шаги получают StepUnknown и не
// выполняются. client — engine-специфичный клиент/подключение, переданный
// apply без изменений (fail-fast семантика идентична прежним per-engine
// циклам Apply). Открытие клиента и его закрытие (defer) остаются в вызывающем
// методе Apply.
func ApplySteps[C any](
	ctx context.Context,
	plan adapter.Plan,
	client C,
	apply func(context.Context, C, adapter.DesiredChange, adapter.PlanStep) (adapter.StepStatus, error),
) *adapter.Result {
	res := &adapter.Result{Steps: make([]adapter.StepResult, 0, len(plan.Steps))}
	failed := false
	for _, step := range plan.Steps {
		if failed {
			res.Steps = append(res.Steps, adapter.StepResult{Step: step, Status: adapter.StepUnknown})
			continue
		}
		status, stepErr := apply(ctx, client, plan.Change, step)
		sr := adapter.StepResult{Step: step, Status: status}
		if stepErr != nil {
			sr.Status = adapter.StepFailed
			sr.Error = stepErr.Error()
			failed = true
		}
		res.Steps = append(res.Steps, sr)
	}
	return res
}
