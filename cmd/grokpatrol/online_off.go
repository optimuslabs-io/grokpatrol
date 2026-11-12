//go:build !online

package main

import (
	"context"

	"github.com/optimuslabs-io/grokpatrol/internal/engine"
	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

// The standard build has no online flags and no network code. These stubs keep
// run() identical across builds; make verify-deps proves nothing here links net.

func registerOnlineFlags() {}

func configureOnline(*engine.Env) error { return nil }

func runOnline(context.Context, *engine.Env, *model.Report, engine.Progress) {}
