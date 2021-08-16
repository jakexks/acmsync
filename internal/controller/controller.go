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

package controller

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

const (
	SyncAnnotationKey   = "experimental.cert-manager.io/acm-sync"
	SyncAnnotationValue = "true"
	ARNAnnotationKey    = "experimental.cert-manager.io/acm-arn"
)

func New(log logr.Logger) (manager.Manager, error) {
	// construct Kube config and interface
	cfg := config.GetConfigOrDie()
	kubeClient := kubernetes.NewForConfigOrDie(cfg)

	// check for AWS credentials
	awsSession, err := session.NewSession()
	if err != nil {
		return nil, fmt.Errorf("couldn't construct AWS session: %w", err)
	}

	mgr, err := manager.New(cfg, manager.Options{
		Logger: log.WithName("manager"),
	})
	if err != nil {
		return nil, err
	}

	err = builder.ControllerManagedBy(mgr).
		For(&corev1.Secret{},
			builder.OnlyMetadata,
			builder.WithPredicates(
				predicate.NewPredicateFuncs(func(object client.Object) bool {
					value, found := object.GetAnnotations()[SyncAnnotationKey]
					if found && value == SyncAnnotationValue {
						return true
					}
					return false
				}),
			),
		).
		Complete(&ACMSyncer{
			log:        log.WithName("acmsyncer"),
			client:     kubeClient,
			recorder:   mgr.GetEventRecorderFor("acmsyncer"),
			awsSession: awsSession,
		})
	if err != nil {
		return nil, err
	}

	return mgr, nil
}
