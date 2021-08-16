/*
Copyright 2021 Jetstack Ltd.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"flag"
	"os"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"

	"sandbox.jakexks.dev/acmsync/internal/controller"
)

func main() {
	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	logf.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	log := logf.Log.WithName("acmsync")
	log.Info("acmsync starting...")

	ctx := signals.SetupSignalHandler()

	mgr, err := controller.New(log)
	if err != nil {
		log.Error(err, "couldn't build controller")
	}

	if err := mgr.Start(ctx); err != nil {
		log.Error(err, "controller manager failed")
		os.Exit(1)
	}
}
