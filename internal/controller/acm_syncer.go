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
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/acm"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	EventTypeNormal  = "Normal"
	EventTypeWarning = "Warning"
	EventTypeError   = "Error"

	ReasonAWSAPIError = "AWSReturnedError"
	ReasonSuccessfulSync = "ACMSuccessfulSync"
)

type ACMSyncer struct {
	log      logr.Logger
	client   kubernetes.Interface
	recorder record.EventRecorder

	awsSession *session.Session
}

func (a *ACMSyncer) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	a.log.V(10).Info("Processing secret", "namespace", req.Namespace, "name", req.Name)

	secret, err := a.client.CoreV1().Secrets(req.Namespace).Get(ctx, req.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return reconcile.Result{}, nil
	}

	shouldUpdate, err := a.ShouldSyncCert(ctx, secret)
	if err != nil {
		return reconcile.Result{}, err
	}
	if !shouldUpdate {
		return reconcile.Result{}, nil
	}
	outARN, err := a.Sync(ctx, secret)
	if err != nil {
		return reconcile.Result{}, err
	}
	a.recorder.Eventf(secret, EventTypeNormal, ReasonSuccessfulSync, "successfully synced certificate ARN %s", outARN)
	return reconcile.Result{}, nil
}

func (a *ACMSyncer) ShouldSyncCert(ctx context.Context, secret *corev1.Secret) (bool, error) {
	log := a.log.WithValues("name", secret.Name, "namespace", secret.Namespace)
	// check if there is any certificate data at all. If not someone has pre-created
	// the certificate and we should ignore it.
	certData := secret.Data["tls.crt"]
	if len(certData) == 0 {
		return false, nil
	}
	// get the first certificate in the block, which is the leaf cert.
	// if there's nothing, we ignore it
	block, _ := pem.Decode(certData)
	if block == nil {
		log.Info("No PEM data found in secret, ignoring")
		return false, nil
	}
	if block.Type != "CERTIFICATE" {
		log.Info("non-certificate found in secret, ignoring")
		return false, nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Error(err, "could not parse certificate, ignoring")
		return false, nil
	}

	// Now we have parsed the cert, check whether it has been synced before (has an ARN annotation)
	arn, found := secret.Annotations[ARNAnnotationKey]
	if !found {
		return true, nil
	}

	acmClient := acm.New(a.awsSession)
	output, err := acmClient.GetCertificateWithContext(ctx, &acm.GetCertificateInput{CertificateArn: pointer.String(arn)})
	if err != nil {
		switch err.(type) {
		case *acm.InvalidArnException, *acm.ResourceNotFoundException:
			// arn is invalid. We should delete the ARN annotation then re-sync
			retry.RetryOnConflict(retry.DefaultRetry, func() error {
				oldSecret, err := a.client.CoreV1().Secrets(secret.Namespace).Get(ctx, secret.Name, metav1.GetOptions{})
				if apierrors.IsNotFound(err) {
					return nil
				}
				if err != nil {
					return err
				}
				newSecret := oldSecret.DeepCopy()
				delete(newSecret.Annotations, ARNAnnotationKey)
				_, err = a.client.CoreV1().Secrets(newSecret.Namespace).Update(ctx, newSecret, metav1.UpdateOptions{})
				return err
			})
			return false, fmt.Errorf("invalid ARN: %s. resyncing %s/%s", secret.Annotations[ARNAnnotationKey], secret.Namespace, secret.Name)
		default:
			log.Error(err, "AWS ACM returned an error")
			a.recorder.Event(secret, EventTypeError, ReasonAWSAPIError, err.Error())
			return false, err
		}
	}
	block, _ = pem.Decode([]byte(*output.Certificate))
	if block == nil {
		log.Info("No PEM data found in AWS ACM Response, syncing cert")
		return true, nil
	}
	if block.Type != "CERTIFICATE" {
		log.Info("non-certificate found in AWS ACM response, syncing cert")
		return true, nil
	}
	awsCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Error(err, "could not parse certificate from AWS ACM, syncing cert")
		return true, nil
	}
	if cert.SerialNumber.Cmp(awsCert.SerialNumber) == 0 {
		log.Info("Certificate is already synced to ACM (found identical serial)", "serial", cert.SerialNumber.String())
		return false, nil
	}
	log.Info("ACM certificate differs, syncing cert", "expectedSerial", cert.SerialNumber, "actualSerial", awsCert.SerialNumber)
	return true, nil
}

func (a *ACMSyncer) Sync(ctx context.Context, secret *corev1.Secret) (string, error) {
	var arn *string
	if s, found := secret.Annotations[ARNAnnotationKey]; found {
		arn = pointer.String(s)
	}
	cert, chain := leafChainFromSecret(secret)

	acmClient := acm.New(a.awsSession)
	out, err := acmClient.ImportCertificateWithContext(ctx, &acm.ImportCertificateInput{
		Certificate:      cert,
		CertificateArn:   arn,
		CertificateChain: chain,
		PrivateKey:       secret.Data["tls.key"],
	})
	if err != nil {
		return "", err
	}
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		oldSecret, err := a.client.CoreV1().Secrets(secret.Namespace).Get(ctx, secret.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		newSecret := oldSecret.DeepCopy()
		newSecret.Annotations[ARNAnnotationKey] = *out.CertificateArn
		_, err = a.client.CoreV1().Secrets(newSecret.Namespace).Update(ctx, newSecret, metav1.UpdateOptions{})
		return err
	})
	if err != nil {
		return *out.CertificateArn, err
	}
	return *out.CertificateArn, nil
}

func leafChainFromSecret(secret *corev1.Secret) (cert, chain []byte) {
	pemdata := secret.Data["tls.crt"]
	block, rest := pem.Decode(pemdata)
	cert = pem.EncodeToMemory(block)

	chainBuf := &bytes.Buffer{}
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		chainBuf.Write(pem.EncodeToMemory(block))
		chainBuf.WriteRune('\n')
	}

	// bleh
	if ca, found := secret.Data["ca.crt"]; found {
		chainBuf.Write(ca)
	}
	return cert, chainBuf.Bytes()
}
