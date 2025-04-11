/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mocks

import (
	"encoding/json"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/postgres"
	commErr "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/err"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
)

var tcMap = map[string]string{
	"fda6105d-a340-42da-bc35-0555e7a5e360": `{"id":"fda6105d-a340-42da-bc35-0555e7a5e360","certificate":"MIIEPzCCAqegAwIBAgIQMvsf7QVxA6d0zhxOSC9kUDANBgkqhkiG9w0BAQwFADAxMS8wLQYDVQQDDCYTJDU2ZGZmZTZmLTU3ZjgtNGY0Yy05Yzk4LTdjNmVmOWNjMGM4YzAeFw0yMDA3MDUwNzI1NTFaFw0yMTA3MDUwNzI1NTFaMDExLzAtBgNVBAMMJhMkNTZkZmZlNmYtNTdmOC00ZjRjLTljOTgtN2M2ZWY5Y2MwYzhjMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAp7SFWXQkhnxPOAUoQtPzY2wfgvH8HUnM2A0iN8WtQomnfd+Hzh/qwuWR4dpHMICtV5kMUrXWlJ6haOKa+vBmCqKVTHCxbagZAzjkmGwrCRlVbfwU2I5IvLF7PLSSUsg+PE3RlF0Jh7O2cpfYLAIwnAV26CPqt9rl1wfv/12ezMlqXmBFBo7zP2wqWSujuNZINxqjUVmfrbqFiSaIAHdXytcD87orY2MDpuODsWgAF+HBy2x8gindJQA8D5+YAvD2MCTVf3EAKUwBBmr53CjCnxODR/5yO1DW9yr12L/qNyyCu44pNVtt1lvteD+aZElBRR7TQG1KNpwpghvxKpzdflqCdCGtxCFzVA+OW/w0lgC1ig1fIpsu1H6XESP/bHnprO1/9rn3KXgbztUJ26HBYlvyeBAdWBzzxTLZPJ/nkfGtyP9Jrm/aUvS3FontUgrdF9c36DJEJ9Y0Ww206YgCNWAiJfxiduY0QaGgKS/8F25uAKMKs0mk9WnqueC2TGJfAgMBAAGjUzBRMCQGBVUEhhUBAQH/BBgwFhMITG9jYXRpb24TClNhbnRhQ2xhcmEwKQYFVQSGFQEBAf8EHTAbEwdDb21wYW55ExBJbnRlbENvcnBvcmF0aW9uMA0GCSqGSIb3DQEBDAUAA4IBgQAh6oGgiZ8Pt6A87U5j8v4IO8adNtqy1muouHiCrmnSeICGllM4HK76pla+JPD6hprW8zSyNGzzPR0+zZ9gAqnrNhukUdOsR41i3HpUINIqN21VcTVxoFhOthfVMQBeSjHWBx2Ypi6XJ1vAbbqvVuxntHQ2uUwtTu60quSLO5poomoWjHG1/53/yIIl3TgDnB9qH1uKWYtiDVStAlJT8OjS4fWHaUSarJSSIJFjyQuCFNU9RG61leryX61K9NsNsKySFiwep53g4QYHb7X7DuSJrbHUED9/Xfe8t2lrlOCDPZ+GZh6HfU+ypI6h8pVPDU7pyHrGBOeGdtSSHXE1qgOG4v9KoBTTd1s50kOYXleDd9SSO8JAm7GtUQTy448ciZ2WyahqN8ZpQhwO4ZXRAlacZUxU6y8wmdr/a7CAzQrQUlRBki/Crnm6PM1qXSTEJ1s9OUE5uudmUN4nnWo0ru1UJCbjzcaSKmNSzg4JUZqlIZmY8cViuHAve5P6doU4y6Y=","subject":"00ecd3ab-9af4-e711-906e-001560a04062","issuer":"CN=asset-tag-service","not_before":"` + time.Now().Add(-TimeDuration30Mins).Format(time.RFC3339) + `","not_after":"` + time.Now().AddDate(1, 0, 0).Format(time.RFC3339) + `","hardware_uuid":"80ecce40-04b8-e811-906e-00163566263e"}`,
	"3966e9e8-4f44-4a9e-9231-b4a83743de55": `{"id":"3966e9e8-4f44-4a9e-9231-b4a83743de55","certificate":"MIIEPzCCAqegAwIBAgIQMvsf7QVxA6d0zhxOSC9kUDANBgkqhkiG9w0BAQwFADAxMS8wLQYDVQQDDCYTJDU2ZGZmZTZmLTU3ZjgtNGY0Yy05Yzk4LTdjNmVmOWNjMGM4YzAeFw0yMDA3MDUwNzI1NTFaFw0yMTA3MDUwNzI1NTFaMDExLzAtBgNVBAMMJhMkNTZkZmZlNmYtNTdmOC00ZjRjLTljOTgtN2M2ZWY5Y2MwYzhjMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAp7SFWXQkhnxPOAUoQtPzY2wfgvH8HUnM2A0iN8WtQomnfd+Hzh/qwuWR4dpHMICtV5kMUrXWlJ6haOKa+vBmCqKVTHCxbagZAzjkmGwrCRlVbfwU2I5IvLF7PLSSUsg+PE3RlF0Jh7O2cpfYLAIwnAV26CPqt9rl1wfv/12ezMlqXmBFBo7zP2wqWSujuNZINxqjUVmfrbqFiSaIAHdXytcD87orY2MDpuODsWgAF+HBy2x8gindJQA8D5+YAvD2MCTVf3EAKUwBBmr53CjCnxODR/5yO1DW9yr12L/qNyyCu44pNVtt1lvteD+aZElBRR7TQG1KNpwpghvxKpzdflqCdCGtxCFzVA+OW/w0lgC1ig1fIpsu1H6XESP/bHnprO1/9rn3KXgbztUJ26HBYlvyeBAdWBzzxTLZPJ/nkfGtyP9Jrm/aUvS3FontUgrdF9c36DJEJ9Y0Ww206YgCNWAiJfxiduY0QaGgKS/8F25uAKMKs0mk9WnqueC2TGJfAgMBAAGjUzBRMCQGBVUEhhUBAQH/BBgwFhMITG9jYXRpb24TClNhbnRhQ2xhcmEwKQYFVQSGFQEBAf8EHTAbEwdDb21wYW55ExBJbnRlbENvcnBvcmF0aW9uMA0GCSqGSIb3DQEBDAUAA4IBgQAh6oGgiZ8Pt6A87U5j8v4IO8adNtqy1muouHiCrmnSeICGllM4HK76pla+JPD6hprW8zSyNGzzPR0+zZ9gAqnrNhukUdOsR41i3HpUINIqN21VcTVxoFhOthfVMQBeSjHWBx2Ypi6XJ1vAbbqvVuxntHQ2uUwtTu60quSLO5poomoWjHG1/53/yIIl3TgDnB9qH1uKWYtiDVStAlJT8OjS4fWHaUSarJSSIJFjyQuCFNU9RG61leryX61K9NsNsKySFiwep53g4QYHb7X7DuSJrbHUED9/Xfe8t2lrlOCDPZ+GZh6HfU+ypI6h8pVPDU7pyHrGBOeGdtSSHXE1qgOG4v9KoBTTd1s50kOYXleDd9SSO8JAm7GtUQTy448ciZ2WyahqN8ZpQhwO4ZXRAlacZUxU6y8wmdr/a7CAzQrQUlRBki/Crnm6PM1qXSTEJ1s9OUE5uudmUN4nnWo0ru1UJCbjzcaSKmNSzg4JUZqlIZmY8cViuHAve5P6doU4y6Y=","issuer":"CN=asset-tag-service","not_before":"` + time.Now().Add(-TimeDuration30Mins).Format(time.RFC3339) + `","not_after":"` + time.Now().AddDate(1, 0, 0).Format(time.RFC3339) + `","hardware_uuid":"80ecce40-04b8-e811-906e-00163566263e"}`,
	"a4b46350-d60b-44db-88e8-6d1ada16e282": `{"id":"a4b46350-d60b-44db-88e8-6d1ada16e282","certificate":"MIIEPzCCAqegAwIBAgIQMvsf7QVxA6d0zhxOSC9kUDANBgkqhkiG9w0BAQwFADAxMS8wLQYDVQQDDCYTJDU2ZGZmZTZmLTU3ZjgtNGY0Yy05Yzk4LTdjNmVmOWNjMGM4YzAeFw0yMDA3MDUwNzI1NTFaFw0yMTA3MDUwNzI1NTFaMDExLzAtBgNVBAMMJhMkNTZkZmZlNmYtNTdmOC00ZjRjLTljOTgtN2M2ZWY5Y2MwYzhjMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAp7SFWXQkhnxPOAUoQtPzY2wfgvH8HUnM2A0iN8WtQomnfd+Hzh/qwuWR4dpHMICtV5kMUrXWlJ6haOKa+vBmCqKVTHCxbagZAzjkmGwrCRlVbfwU2I5IvLF7PLSSUsg+PE3RlF0Jh7O2cpfYLAIwnAV26CPqt9rl1wfv/12ezMlqXmBFBo7zP2wqWSujuNZINxqjUVmfrbqFiSaIAHdXytcD87orY2MDpuODsWgAF+HBy2x8gindJQA8D5+YAvD2MCTVf3EAKUwBBmr53CjCnxODR/5yO1DW9yr12L/qNyyCu44pNVtt1lvteD+aZElBRR7TQG1KNpwpghvxKpzdflqCdCGtxCFzVA+OW/w0lgC1ig1fIpsu1H6XESP/bHnprO1/9rn3KXgbztUJ26HBYlvyeBAdWBzzxTLZPJ/nkfGtyP9Jrm/aUvS3FontUgrdF9c36DJEJ9Y0Ww206YgCNWAiJfxiduY0QaGgKS/8F25uAKMKs0mk9WnqueC2TGJfAgMBAAGjUzBRMCQGBVUEhhUBAQH/BBgwFhMITG9jYXRpb24TClNhbnRhQ2xhcmEwKQYFVQSGFQEBAf8EHTAbEwdDb21wYW55ExBJbnRlbENvcnBvcmF0aW9uMA0GCSqGSIb3DQEBDAUAA4IBgQAh6oGgiZ8Pt6A87U5j8v4IO8adNtqy1muouHiCrmnSeICGllM4HK76pla+JPD6hprW8zSyNGzzPR0+zZ9gAqnrNhukUdOsR41i3HpUINIqN21VcTVxoFhOthfVMQBeSjHWBx2Ypi6XJ1vAbbqvVuxntHQ2uUwtTu60quSLO5poomoWjHG1/53/yIIl3TgDnB9qH1uKWYtiDVStAlJT8OjS4fWHaUSarJSSIJFjyQuCFNU9RG61leryX61K9NsNsKySFiwep53g4QYHb7X7DuSJrbHUED9/Xfe8t2lrlOCDPZ+GZh6HfU+ypI6h8pVPDU7pyHrGBOeGdtSSHXE1qgOG4v9KoBTTd1s50kOYXleDd9SSO8JAm7GtUQTy448ciZ2WyahqN8ZpQhwO4ZXRAlacZUxU6y8wmdr/a7CAzQrQUlRBki/Crnm6PM1qXSTEJ1s9OUE5uudmUN4nnWo0ru1UJCbjzcaSKmNSzg4JUZqlIZmY8cViuHAve5P6doU4y6Y=","subject":"80ecce40-04b8-e811-906e-00163566263e","issuer":"CN=asset-tag-service","not_before":"` + time.Now().AddDate(-1, 0, 0).Format(time.RFC3339) + `","not_after":"` + time.Now().AddDate(0, 6, 0).Format(time.RFC3339) + `","hardware_uuid":"af937bc3-c381-42a6-bd17-bfe054c023aa"}`,
	"dbed7b6b-3d01-4e53-82e7-d1c62f8b6a5c": `{"id":"dbed7b6b-3d01-4e53-82e7-d1c62f8b6a5c","certificate":"MIIEPzCCAqegAwIBAgIQMvsf7QVxA6d0zhxOSC9kUDANBgkqhkiG9w0BAQwFADAxMS8wLQYDVQQDDCYTJDU2ZGZmZTZmLTU3ZjgtNGY0Yy05Yzk4LTdjNmVmOWNjMGM4YzAeFw0yMDA3MDUwNzI1NTFaFw0yMTA3MDUwNzI1NTFaMDExLzAtBgNVBAMMJhMkNTZkZmZlNmYtNTdmOC00ZjRjLTljOTgtN2M2ZWY5Y2MwYzhjMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAp7SFWXQkhnxPOAUoQtPzY2wfgvH8HUnM2A0iN8WtQomnfd+Hzh/qwuWR4dpHMICtV5kMUrXWlJ6haOKa+vBmCqKVTHCxbagZAzjkmGwrCRlVbfwU2I5IvLF7PLSSUsg+PE3RlF0Jh7O2cpfYLAIwnAV26CPqt9rl1wfv/12ezMlqXmBFBo7zP2wqWSujuNZINxqjUVmfrbqFiSaIAHdXytcD87orY2MDpuODsWgAF+HBy2x8gindJQA8D5+YAvD2MCTVf3EAKUwBBmr53CjCnxODR/5yO1DW9yr12L/qNyyCu44pNVtt1lvteD+aZElBRR7TQG1KNpwpghvxKpzdflqCdCGtxCFzVA+OW/w0lgC1ig1fIpsu1H6XESP/bHnprO1/9rn3KXgbztUJ26HBYlvyeBAdWBzzxTLZPJ/nkfGtyP9Jrm/aUvS3FontUgrdF9c36DJEJ9Y0Ww206YgCNWAiJfxiduY0QaGgKS/8F25uAKMKs0mk9WnqueC2TGJfAgMBAAGjUzBRMCQGBVUEhhUBAQH/BBgwFhMITG9jYXRpb24TClNhbnRhQ2xhcmEwKQYFVQSGFQEBAf8EHTAbEwdDb21wYW55ExBJbnRlbENvcnBvcmF0aW9uMA0GCSqGSIb3DQEBDAUAA4IBgQAh6oGgiZ8Pt6A87U5j8v4IO8adNtqy1muouHiCrmnSeICGllM4HK76pla+JPD6hprW8zSyNGzzPR0+zZ9gAqnrNhukUdOsR41i3HpUINIqN21VcTVxoFhOthfVMQBeSjHWBx2Ypi6XJ1vAbbqvVuxntHQ2uUwtTu60quSLO5poomoWjHG1/53/yIIl3TgDnB9qH1uKWYtiDVStAlJT8OjS4fWHaUSarJSSIJFjyQuCFNU9RG61leryX61K9NsNsKySFiwep53g4QYHb7X7DuSJrbHUED9/Xfe8t2lrlOCDPZ+GZh6HfU+ypI6h8pVPDU7pyHrGBOeGdtSSHXE1qgOG4v9KoBTTd1s50kOYXleDd9SSO8JAm7GtUQTy448ciZ2WyahqN8ZpQhwO4ZXRAlacZUxU6y8wmdr/a7CAzQrQUlRBki/Crnm6PM1qXSTEJ1s9OUE5uudmUN4nnWo0ru1UJCbjzcaSKmNSzg4JUZqlIZmY8cViuHAve5P6doU4y6Y=","subject":"80ecce40-04b8-e811-906e-00163566263e","issuer":"CN=asset-tag-service","not_before":"` + time.Now().AddDate(-1, 0, 0).Format(time.RFC3339) + `","not_after":"` + time.Now().AddDate(1, 4, 15).Format(time.RFC3339) + `","hardware_uuid":"af937bc3-c381-42a6-bd17-bfe054c023aa"}`,
	"390784a9-d83f-4fa1-b6b5-a77bd13a3c7b": `{"id":"390784a9-d83f-4fa1-b6b5-a77bd13a3c7b","certificate":"MIIEPzCCAqegAwIBAgIQMvsf7QVxA6d0zhxOSC9kUDANBgkqhkiG9w0BAQwFADAxMS8wLQYDVQQDDCYTJDU2ZGZmZTZmLTU3ZjgtNGY0Yy05Yzk4LTdjNmVmOWNjMGM4YzAeFw0yMDA3MDUwNzI1NTFaFw0yMTA3MDUwNzI1NTFaMDExLzAtBgNVBAMMJhMkNTZkZmZlNmYtNTdmOC00ZjRjLTljOTgtN2M2ZWY5Y2MwYzhjMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAp7SFWXQkhnxPOAUoQtPzY2wfgvH8HUnM2A0iN8WtQomnfd+Hzh/qwuWR4dpHMICtV5kMUrXWlJ6haOKa+vBmCqKVTHCxbagZAzjkmGwrCRlVbfwU2I5IvLF7PLSSUsg+PE3RlF0Jh7O2cpfYLAIwnAV26CPqt9rl1wfv/12ezMlqXmBFBo7zP2wqWSujuNZINxqjUVmfrbqFiSaIAHdXytcD87orY2MDpuODsWgAF+HBy2x8gindJQA8D5+YAvD2MCTVf3EAKUwBBmr53CjCnxODR/5yO1DW9yr12L/qNyyCu44pNVtt1lvteD+aZElBRR7TQG1KNpwpghvxKpzdflqCdCGtxCFzVA+OW/w0lgC1ig1fIpsu1H6XESP/bHnprO1/9rn3KXgbztUJ26HBYlvyeBAdWBzzxTLZPJ/nkfGtyP9Jrm/aUvS3FontUgrdF9c36DJEJ9Y0Ww206YgCNWAiJfxiduY0QaGgKS/8F25uAKMKs0mk9WnqueC2TGJfAgMBAAGjUzBRMCQGBVUEhhUBAQH/BBgwFhMITG9jYXRpb24TClNhbnRhQ2xhcmEwKQYFVQSGFQEBAf8EHTAbEwdDb21wYW55ExBJbnRlbENvcnBvcmF0aW9uMA0GCSqGSIb3DQEBDAUAA4IBgQAh6oGgiZ8Pt6A87U5j8v4IO8adNtqy1muouHiCrmnSeICGllM4HK76pla+JPD6hprW8zSyNGzzPR0+zZ9gAqnrNhukUdOsR41i3HpUINIqN21VcTVxoFhOthfVMQBeSjHWBx2Ypi6XJ1vAbbqvVuxntHQ2uUwtTu60quSLO5poomoWjHG1/53/yIIl3TgDnB9qH1uKWYtiDVStAlJT8OjS4fWHaUSarJSSIJFjyQuCFNU9RG61leryX61K9NsNsKySFiwep53g4QYHb7X7DuSJrbHUED9/Xfe8t2lrlOCDPZ+GZh6HfU+ypI6h8pVPDU7pyHrGBOeGdtSSHXE1qgOG4v9KoBTTd1s50kOYXleDd9SSO8JAm7GtUQTy448ciZ2WyahqN8ZpQhwO4ZXRAlacZUxU6y8wmdr/a7CAzQrQUlRBki/Crnm6PM1qXSTEJ1s9OUE5uudmUN4nnWo0ru1UJCbjzcaSKmNSzg4JUZqlIZmY8cViuHAve5P6doU4y6Y=","subject":"80ecce40-04b8-e811-906e-00163566263e","issuer":"CN=asset-tag-service","not_before":"` + time.Now().AddDate(-3, 0, 0).Format(time.RFC3339) + `","not_after":"` + time.Now().AddDate(-1, 0, 0).Format(time.RFC3339) + `","hardware_uuid":"af937bc3-c381-42a6-bd17-bfe054c023aa"}`,
	"cf197a51-8362-465f-9ec1-d88ad0023a27": `{"id":"cf197a51-8362-465f-9ec1-d88ad0023a27","certificate":"MIIEPzCCAqegAwIBAgIQMvsf7QVxA6d0zhxOSC9kUDANBgkqhkiG9w0BAQwFADAxMS8wLQYDVQQDDCYTJDU2ZGZmZTZmLTU3ZjgtNGY0Yy05Yzk4LTdjNmVmOWNjMGM4YzAeFw0yMDA3MDUwNzI1NTFaFw0yMTA3MDUwNzI1NTFaMDExLzAtBgNVBAMMJhMkNTZkZmZlNmYtNTdmOC00ZjRjLTljOTgtN2M2ZWY5Y2MwYzhjMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAp7SFWXQkhnxPOAUoQtPzY2wfgvH8HUnM2A0iN8WtQomnfd+Hzh/qwuWR4dpHMICtV5kMUrXWlJ6haOKa+vBmCqKVTHCxbagZAzjkmGwrCRlVbfwU2I5IvLF7PLSSUsg+PE3RlF0Jh7O2cpfYLAIwnAV26CPqt9rl1wfv/12ezMlqXmBFBo7zP2wqWSujuNZINxqjUVmfrbqFiSaIAHdXytcD87orY2MDpuODsWgAF+HBy2x8gindJQA8D5+YAvD2MCTVf3EAKUwBBmr53CjCnxODR/5yO1DW9yr12L/qNyyCu44pNVtt1lvteD+aZElBRR7TQG1KNpwpghvxKpzdflqCdCGtxCFzVA+OW/w0lgC1ig1fIpsu1H6XESP/bHnprO1/9rn3KXgbztUJ26HBYlvyeBAdWBzzxTLZPJ/nkfGtyP9Jrm/aUvS3FontUgrdF9c36DJEJ9Y0Ww206YgCNWAiJfxiduY0QaGgKS/8F25uAKMKs0mk9WnqueC2TGJfAgMBAAGjUzBRMCQGBVUEhhUBAQH/BBgwFhMITG9jYXRpb24TClNhbnRhQ2xhcmEwKQYFVQSGFQEBAf8EHTAbEwdDb21wYW55ExBJbnRlbENvcnBvcmF0aW9uMA0GCSqGSIb3DQEBDAUAA4IBgQAh6oGgiZ8Pt6A87U5j8v4IO8adNtqy1muouHiCrmnSeICGllM4HK76pla+JPD6hprW8zSyNGzzPR0+zZ9gAqnrNhukUdOsR41i3HpUINIqN21VcTVxoFhOthfVMQBeSjHWBx2Ypi6XJ1vAbbqvVuxntHQ2uUwtTu60quSLO5poomoWjHG1/53/yIIl3TgDnB9qH1uKWYtiDVStAlJT8OjS4fWHaUSarJSSIJFjyQuCFNU9RG61leryX61K9NsNsKySFiwep53g4QYHb7X7DuSJrbHUED9/Xfe8t2lrlOCDPZ+GZh6HfU+ypI6h8pVPDU7pyHrGBOeGdtSSHXE1qgOG4v9KoBTTd1s50kOYXleDd9SSO8JAm7GtUQTy448ciZ2WyahqN8ZpQhwO4ZXRAlacZUxU6y8wmdr/a7CAzQrQUlRBki/Crnm6PM1qXSTEJ1s9OUE5uudmUN4nnWo0ru1UJCbjzcaSKmNSzg4JUZqlIZmY8cViuHAve5P6doU4y6Y=","subject":"80ecce40-04b8-e811-906e-00163566263e","issuer":"CN=asset-tag-service","not_before":"` + time.Now().Add(-TimeDuration30Mins).Format(time.RFC3339) + `","not_after":"` + time.Now().AddDate(1, 0, 0).Format(time.RFC3339) + `","hardware_uuid":"7a569dad-2d82-49e4-9156-069b0065b262"}`,
	"7ce60664-faa3-4c2e-8c45-41e209e4f1db": `{"id":"7ce60664-faa3-4c2e-8c45-41e209e4f1db","certificate":"MIIEPzCCAqegAwIBAgIQMvsf7QVxA6d0zhxOSC9kUDANBgkqhkiG9w0BAQwFADAxMS8wLQYDVQQDDCYTJDU2ZGZmZTZmLTU3ZjgtNGY0Yy05Yzk4LTdjNmVmOWNjMGM4YzAeFw0yMDA3MDUwNzI1NTFaFw0yMTA3MDUwNzI1NTFaMDExLzAtBgNVBAMMJhMkNTZkZmZlNmYtNTdmOC00ZjRjLTljOTgtN2M2ZWY5Y2MwYzhjMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAp7SFWXQkhnxPOAUoQtPzY2wfgvH8HUnM2A0iN8WtQomnfd+Hzh/qwuWR4dpHMICtV5kMUrXWlJ6haOKa+vBmCqKVTHCxbagZAzjkmGwrCRlVbfwU2I5IvLF7PLSSUsg+PE3RlF0Jh7O2cpfYLAIwnAV26CPqt9rl1wfv/12ezMlqXmBFBo7zP2wqWSujuNZINxqjUVmfrbqFiSaIAHdXytcD87orY2MDpuODsWgAF+HBy2x8gindJQA8D5+YAvD2MCTVf3EAKUwBBmr53CjCnxODR/5yO1DW9yr12L/qNyyCu44pNVtt1lvteD+aZElBRR7TQG1KNpwpghvxKpzdflqCdCGtxCFzVA+OW/w0lgC1ig1fIpsu1H6XESP/bHnprO1/9rn3KXgbztUJ26HBYlvyeBAdWBzzxTLZPJ/nkfGtyP9Jrm/aUvS3FontUgrdF9c36DJEJ9Y0Ww206YgCNWAiJfxiduY0QaGgKS/8F25uAKMKs0mk9WnqueC2TGJfAgMBAAGjUzBRMCQGBVUEhhUBAQH/BBgwFhMITG9jYXRpb24TClNhbnRhQ2xhcmEwKQYFVQSGFQEBAf8EHTAbEwdDb21wYW55ExBJbnRlbENvcnBvcmF0aW9uMA0GCSqGSIb3DQEBDAUAA4IBgQAh6oGgiZ8Pt6A87U5j8v4IO8adNtqy1muouHiCrmnSeICGllM4HK76pla+JPD6hprW8zSyNGzzPR0+zZ9gAqnrNhukUdOsR41i3HpUINIqN21VcTVxoFhOthfVMQBeSjHWBx2Ypi6XJ1vAbbqvVuxntHQ2uUwtTu60quSLO5poomoWjHG1/53/yIIl3TgDnB9qH1uKWYtiDVStAlJT8OjS4fWHaUSarJSSIJFjyQuCFNU9RG61leryX61K9NsNsKySFiwep53g4QYHb7X7DuSJrbHUED9/Xfe8t2lrlOCDPZ+GZh6HfU+ypI6h8pVPDU7pyHrGBOeGdtSSHXE1qgOG4v9KoBTTd1s50kOYXleDd9SSO8JAm7GtUQTy448ciZ2WyahqN8ZpQhwO4ZXRAlacZUxU6y8wmdr/a7CAzQrQUlRBki/Crnm6PM1qXSTEJ1s9OUE5uudmUN4nnWo0ru1UJCbjzcaSKmNSzg4JUZqlIZmY8cViuHAve5P6doU4y6Y=","subject":"80ecce40-04b8-e811-906e-00163566263e","issuer":"CN=asset-tag-service","not_before":"2015-09-28T09:08:33.913Z","not_after":"2050-09-28T09:08:33.913Z","hardware_uuid":"00e4d709-8d72-44c3-89ae-c5edc395d6fe"}`,
	"00b61da0-5ada-e811-906e-00163566263e": `{"id":"00b61da0-5ada-e811-906e-00163566263e","certificate":"MIIEPzCCAqegAwIBAgIQMvsf7QVxA6d0zhxOSC9kUDANBgkqhkiG9w0BAQwFADAxMS8wLQYDVQQDDCYTJDU2ZGZmZTZmLTU3ZjgtNGY0Yy05Yzk4LTdjNmVmOWNjMGM4YzAeFw0yMDA3MDUwNzI1NTFaFw0yMTA3MDUwNzI1NTFaMDExLzAtBgNVBAMMJhMkNTZkZmZlNmYtNTdmOC00ZjRjLTljOTgtN2M2ZWY5Y2MwYzhjMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAp7SFWXQkhnxPOAUoQtPzY2wfgvH8HUnM2A0iN8WtQomnfd+Hzh/qwuWR4dpHMICtV5kMUrXWlJ6haOKa+vBmCqKVTHCxbagZAzjkmGwrCRlVbfwU2I5IvLF7PLSSUsg+PE3RlF0Jh7O2cpfYLAIwnAV26CPqt9rl1wfv/12ezMlqXmBFBo7zP2wqWSujuNZINxqjUVmfrbqFiSaIAHdXytcD87orY2MDpuODsWgAF+HBy2x8gindJQA8D5+YAvD2MCTVf3EAKUwBBmr53CjCnxODR/5yO1DW9yr12L/qNyyCu44pNVtt1lvteD+aZElBRR7TQG1KNpwpghvxKpzdflqCdCGtxCFzVA+OW/w0lgC1ig1fIpsu1H6XESP/bHnprO1/9rn3KXgbztUJ26HBYlvyeBAdWBzzxTLZPJ/nkfGtyP9Jrm/aUvS3FontUgrdF9c36DJEJ9Y0Ww206YgCNWAiJfxiduY0QaGgKS/8F25uAKMKs0mk9WnqueC2TGJfAgMBAAGjUzBRMCQGBVUEhhUBAQH/BBgwFhMITG9jYXRpb24TClNhbnRhQ2xhcmEwKQYFVQSGFQEBAf8EHTAbEwdDb21wYW55ExBJbnRlbENvcnBvcmF0aW9uMA0GCSqGSIb3DQEBDAUAA4IBgQAh6oGgiZ8Pt6A87U5j8v4IO8adNtqy1muouHiCrmnSeICGllM4HK76pla+JPD6hprW8zSyNGzzPR0+zZ9gAqnrNhukUdOsR41i3HpUINIqN21VcTVxoFhOthfVMQBeSjHWBx2Ypi6XJ1vAbbqvVuxntHQ2uUwtTu60quSLO5poomoWjHG1/53/yIIl3TgDnB9qH1uKWYtiDVStAlJT8OjS4fWHaUSarJSSIJFjyQuCFNU9RG61leryX61K9NsNsKySFiwep53g4QYHb7X7DuSJrbHUED9/Xfe8t2lrlOCDPZ+GZh6HfU+ypI6h8pVPDU7pyHrGBOeGdtSSHXE1qgOG4v9KoBTTd1s50kOYXleDd9SSO8JAm7GtUQTy448ciZ2WyahqN8ZpQhwO4ZXRAlacZUxU6y8wmdr/a7CAzQrQUlRBki/Crnm6PM1qXSTEJ1s9OUE5uudmUN4nnWo0ru1UJCbjzcaSKmNSzg4JUZqlIZmY8cViuHAve5P6doU4y6Y=","subject":"00ecd3ab-9af4-e711-906e-001560a04062","issuer":"CN=asset-tag-service","not_before":"` + time.Now().Add(-TimeDuration30Mins).Format(time.RFC3339) + `","not_after":"` + time.Now().AddDate(1, 0, 0).Format(time.RFC3339) + `","hardware_uuid":"00b61da0-5ada-e811-906e-00163566263e"}`,
}

var tcCols = []string{"id", "hardware_uuid", "certificate", "subject", "issuer", "notbefore", "notafter"}

// MockTagCertificateStore provides a mocked implementation of interface hvs.TagCertificateStore
type MockTagCertificateStore struct {
	Mock                sqlmock.Sqlmock
	TagCertificateStore *postgres.TagCertificateStore
}

// Create mocks TagCertificate Create Response
func (store *MockTagCertificateStore) Create(tc *hvs.TagCertificate) (*hvs.TagCertificate, error) {
	// any of the options below can be applied
	store.Mock.MatchExpectationsInOrder(false)

	store.Mock.ExpectBegin()

	newUuid, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new UUID")
	}
	store.Mock.ExpectQuery(`INSERT INTO "tag_certificate" (.+)`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(newUuid.String()))

	store.Mock.ExpectCommit()

	return store.TagCertificateStore.Create(tc)
}

// Retrieve mocks TagCertificate Retrieve Response
func (store *MockTagCertificateStore) Retrieve(id uuid.UUID) (*hvs.TagCertificate, error) {
	// any of the options below can be applied
	store.Mock.MatchExpectationsInOrder(false)

	// mock for returned objects
	for k, v := range tcMap {
		var tc hvs.TagCertificate
		_ = json.Unmarshal([]byte(v), &tc)

		store.Mock.ExpectQuery(`SELECT \* FROM "tag_certificate"  WHERE  \("tag_certificate"."id"" = \$1\)`).
			WithArgs(k).
			WillReturnRows(sqlmock.NewRows(tcCols).
				AddRow(tc.ID.String(), tc.HardwareUUID.String(), string(tc.Certificate), tc.Subject, tc.Issuer, tc.NotBefore, tc.NotAfter))
	}

	// Mock error in retrieve
	store.Mock.ExpectQuery(`SELECT \* FROM "tag_certificate"  WHERE \("tag_certificate"."id" = \$1\)`).
		WithArgs("c00135a8-f5e9-4860-ae6c-4acce525d340").WillReturnError(errors.New(commErr.RowsNotFound))

	// Mock retrieve for Deploy Tag Cert
	var rtc hvs.TagCertificate
	tcString := `{"id":"c00135a8-f5e9-4860-ae6c-4acce525d340","certificate":"MIIEPzCCAqegAwIBAgIQMvsf7QVxA6d0zhxOSC9kUDANBgkqhkiG9w0BAQwFADAxMS8wLQYDVQQDDCYTJDU2ZGZmZTZmLTU3ZjgtNGY0Yy05Yzk4LTdjNmVmOWNjMGM4YzAeFw0yMDA3MDUwNzI1NTFaFw0yMTA3MDUwNzI1NTFaMDExLzAtBgNVBAMMJhMkNTZkZmZlNmYtNTdmOC00ZjRjLTljOTgtN2M2ZWY5Y2MwYzhjMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAp7SFWXQkhnxPOAUoQtPzY2wfgvH8HUnM2A0iN8WtQomnfd+Hzh/qwuWR4dpHMICtV5kMUrXWlJ6haOKa+vBmCqKVTHCxbagZAzjkmGwrCRlVbfwU2I5IvLF7PLSSUsg+PE3RlF0Jh7O2cpfYLAIwnAV26CPqt9rl1wfv/12ezMlqXmBFBo7zP2wqWSujuNZINxqjUVmfrbqFiSaIAHdXytcD87orY2MDpuODsWgAF+HBy2x8gindJQA8D5+YAvD2MCTVf3EAKUwBBmr53CjCnxODR/5yO1DW9yr12L/qNyyCu44pNVtt1lvteD+aZElBRR7TQG1KNpwpghvxKpzdflqCdCGtxCFzVA+OW/w0lgC1ig1fIpsu1H6XESP/bHnprO1/9rn3KXgbztUJ26HBYlvyeBAdWBzzxTLZPJ/nkfGtyP9Jrm/aUvS3FontUgrdF9c36DJEJ9Y0Ww206YgCNWAiJfxiduY0QaGgKS/8F25uAKMKs0mk9WnqueC2TGJfAgMBAAGjUzBRMCQGBVUEhhUBAQH/BBgwFhMITG9jYXRpb24TClNhbnRhQ2xhcmEwKQYFVQSGFQEBAf8EHTAbEwdDb21wYW55ExBJbnRlbENvcnBvcmF0aW9uMA0GCSqGSIb3DQEBDAUAA4IBgQAh6oGgiZ8Pt6A87U5j8v4IO8adNtqy1muouHiCrmnSeICGllM4HK76pla+JPD6hprW8zSyNGzzPR0+zZ9gAqnrNhukUdOsR41i3HpUINIqN21VcTVxoFhOthfVMQBeSjHWBx2Ypi6XJ1vAbbqvVuxntHQ2uUwtTu60quSLO5poomoWjHG1/53/yIIl3TgDnB9qH1uKWYtiDVStAlJT8OjS4fWHaUSarJSSIJFjyQuCFNU9RG61leryX61K9NsNsKySFiwep53g4QYHb7X7DuSJrbHUED9/Xfe8t2lrlOCDPZ+GZh6HfU+ypI6h8pVPDU7pyHrGBOeGdtSSHXE1qgOG4v9KoBTTd1s50kOYXleDd9SSO8JAm7GtUQTy448ciZ2WyahqN8ZpQhwO4ZXRAlacZUxU6y8wmdr/a7CAzQrQUlRBki/Crnm6PM1qXSTEJ1s9OUE5uudmUN4nnWo0ru1UJCbjzcaSKmNSzg4JUZqlIZmY8cViuHAve5P6doU4y6Y=","subject":"00ecd3ab-9af4-e711-906e-001560a04062","issuer":"CN=asset-tag-service","not_before":"` + time.Now().Add(-TimeDuration30Mins).Format(time.RFC3339) + `","not_after":"` + time.Now().AddDate(1, 0, 0).Format(time.RFC3339) + `","hardware_uuid":"7a569dad-2d82-49e4-9156-069b0065b262"}`
	_ = json.Unmarshal([]byte(tcString), &rtc)

	store.Mock.ExpectQuery(`SELECT \* FROM "tag_certificate"  WHERE \("tag_certificate"."id" = \$1\)`).
		WithArgs("cf197a51-8362-465f-9ec1-d88ad0023a27").
		WillReturnRows(sqlmock.NewRows(tcCols).
			AddRow(rtc.ID.String(), rtc.HardwareUUID.String(), string(rtc.Certificate), rtc.Subject, rtc.Issuer, rtc.NotBefore, rtc.NotAfter))

	store.Mock.ExpectQuery(`SELECT \* FROM "tag_certificate"  WHERE \("tag_certificate"."id" = \$1\)`).
		WithArgs("fda6105d-a340-42da-bc35-0555e7a5e360").
		WillReturnRows(sqlmock.NewRows(tcCols).
			AddRow("fda6105d-a340-42da-bc35-0555e7a5e360", rtc.HardwareUUID.String(), string(rtc.Certificate), rtc.Subject, rtc.Issuer, rtc.NotBefore, rtc.NotAfter))

	store.Mock.ExpectQuery(`SELECT \* FROM "tag_certificate"  WHERE \("tag_certificate"."id" = \$1\)`).
		WithArgs("7ce60664-faa3-4c2e-8c45-41e209e4f1db").
		WillReturnRows(sqlmock.NewRows(tcCols).
			AddRow("7ce60664-faa3-4c2e-8c45-41e209e4f1db", "00e4d709-8d72-44c3-89ae-c5edc395d6fe", string(rtc.Certificate), rtc.Subject, rtc.Issuer, rtc.NotBefore, rtc.NotAfter))

	return store.TagCertificateStore.Retrieve(id)
}

// Delete deletes TagCertificate from the store
func (store *MockTagCertificateStore) Delete(tagCertId uuid.UUID) error {
	// any of the options below can be applied
	store.Mock.MatchExpectationsInOrder(false)

	store.Mock.ExpectBegin()

	// mock for returned objects
	for k, v := range tcMap {
		var tc hvs.TagCertificate
		_ = json.Unmarshal([]byte(v), &tc)
		deleteResult := sqlmock.NewResult(1, 1)
		store.Mock.ExpectExec(`DELETE FROM "tag_certificate"  WHERE "tag_certificate"."id" = \$1`).
			WithArgs(k).
			WillReturnResult(deleteResult)
	}

	// mock for error in Retrieve
	store.Mock.ExpectExec(`DELETE FROM "tag_certificate"  WHERE "tag_certificate"."id" = \$1`).
		WithArgs("fda6105d-a340-42da-bc35-0555e7a5e360").
		WillReturnError(errors.New(commErr.RowsNotFound))

	store.Mock.ExpectCommit()

	return store.TagCertificateStore.Delete(tagCertId)
}

// Search returns a filtered list of TagCertificates per the provided TagCertificateFilterCriteria
func (store *MockTagCertificateStore) Search(criteria *models.TagCertificateFilterCriteria) ([]*hvs.TagCertificate, error) {
	// any of the options below can be applied
	store.Mock.MatchExpectationsInOrder(false)

	// search without filter
	// start with all rows
	allRows := sqlmock.NewRows(tcCols)
	for _, v := range tcMap {
		var tc hvs.TagCertificate
		_ = json.Unmarshal([]byte(v), &tc)
		allRows.AddRow(tc.ID.String(), tc.HardwareUUID.String(), string(tc.Certificate), tc.Subject, tc.Issuer, tc.NotBefore, tc.NotAfter)
	}
	store.Mock.ExpectQuery(`SELECT \* FROM "tag_certificate"   ORDER BY "subject"`).WillReturnRows(allRows)

	// search by id
	for k, v := range tcMap {
		var tc hvs.TagCertificate
		_ = json.Unmarshal([]byte(v), &tc)
		store.Mock.ExpectQuery(`SELECT \* FROM "tag_certificate"  WHERE \(id = \$1\)`).
			WithArgs(k).
			WillReturnRows(sqlmock.NewRows(tcCols).
				AddRow(tc.ID.String(), tc.HardwareUUID.String(), string(tc.Certificate), tc.Subject, tc.Issuer, tc.NotBefore, tc.NotAfter))
	}

	// search by non-existent id
	store.Mock.ExpectQuery(`SELECT \* FROM "tag_certificate"  WHERE \(id = \$1\)`).
		WithArgs("b47a13b1-0af2-47d6-91d0-717094bfda2d").
		WillReturnRows(sqlmock.NewRows(tcCols))

	// search by hardware uuid
	var tcHWUUID hvs.TagCertificate
	_ = json.Unmarshal([]byte(tcMap["fda6105d-a340-42da-bc35-0555e7a5e360"]), &tcHWUUID)

	store.Mock.ExpectQuery(`SELECT \* FROM "tag_certificate"  WHERE \(hardware_uuid = \$1\)`).
		WithArgs("80ecce40-04b8-e811-906e-00163566263e").
		WillReturnRows(sqlmock.NewRows(tcCols).
			AddRow(tcHWUUID.ID.String(), tcHWUUID.HardwareUUID.String(), string(tcHWUUID.Certificate), tcHWUUID.Subject, tcHWUUID.Issuer, tcHWUUID.NotBefore, tcHWUUID.NotAfter))

	store.Mock.ExpectQuery(`SELECT \* FROM "tag_certificate"  WHERE \(hardware_uuid = \$1\)`).
		WithArgs("00b61da0-5ada-e811-906e-00163566263e").
		WillReturnRows(sqlmock.NewRows(tcCols).
			AddRow(tcHWUUID.ID.String(), tcHWUUID.HardwareUUID.String(), string(tcHWUUID.Certificate), tcHWUUID.Subject, tcHWUUID.Issuer, tcHWUUID.NotBefore, tcHWUUID.NotAfter))

	// search by non-existent id
	store.Mock.ExpectQuery(`SELECT \* FROM "tag_certificate"  WHERE \(hardware_uuid = \$1\)`).
		WithArgs("b47a13b1-0af2-47d6-91d0-717094bfda2d").
		WillReturnRows(sqlmock.NewRows(tcCols))

	// Search by subjectEqualTo which exists
	var tcm []string
	tcm = append(tcm, tcMap["a4b46350-d60b-44db-88e8-6d1ada16e282"])
	tcm = append(tcm, tcMap["dbed7b6b-3d01-4e53-82e7-d1c62f8b6a5c"])

	subjectEqualToRows := sqlmock.NewRows(tcCols)
	for _, v := range tcm {
		var tc hvs.TagCertificate
		_ = json.Unmarshal([]byte(v), &tc)
		subjectEqualToRows.AddRow(tc.ID.String(), tc.HardwareUUID.String(), string(tc.Certificate), tc.Subject, tc.Issuer, tc.NotBefore, tc.NotAfter)
	}
	store.Mock.ExpectQuery(`SELECT \* FROM "tag_certificate"  WHERE \(lower\(subject\) = \$1\) ORDER BY "subject"`).
		WithArgs("00ecd3ab-9af4-e711-906e-001560a04062").
		WillReturnRows(subjectEqualToRows)

	// Search by subjectEqualTo which does not exists
	store.Mock.ExpectQuery(`SELECT \* FROM "tag_certificate"  WHERE \(lower\(subject\) = \$1\) ORDER BY "subject"`).
		WithArgs("afc82547-0691-4be1-8b14-bcebfce86fd6").
		WillReturnRows(sqlmock.NewRows(tcCols))

	// SubjectContains filter - which exists
	store.Mock.ExpectQuery(`SELECT \* FROM "tag_certificate"  WHERE \(lower\(subject\) like \$1\) ORDER BY "subject"`).
		WithArgs("%001560a04062%").
		WillReturnRows(subjectEqualToRows)

	// SubjectContains filter - which does not exists
	store.Mock.ExpectQuery(`SELECT \* FROM "tag_certificate"  WHERE \(lower\(subject\) like \$1\) ORDER BY "subject"`).
		WithArgs("%7a466a5beff9%").
		WillReturnRows(sqlmock.NewRows(tcCols))

	// IssuerEqualTo filter - which exists
	store.Mock.ExpectQuery(`SELECT \* FROM "tag_certificate"  WHERE \(lower\(issuer\) = \$1\) ORDER BY "subject"`).
		WithArgs("cn=asset-tag-service").
		WillReturnRows(allRows)

	// IssuerEqualTo filter - which does not exist
	store.Mock.ExpectQuery(`SELECT \* FROM "tag_certificate"  WHERE \(lower\(issuer\) = \$1\) ORDER BY "subject"`).
		WithArgs("cn=nonexistent-tag-service").
		WillReturnRows(sqlmock.NewRows(tcCols))

	// IssuerContains filter - which exists
	store.Mock.ExpectQuery(`SELECT \* FROM "tag_certificate"  WHERE \(lower\(issuer\) like \$1\) ORDER BY "subject"`).
		WithArgs("%asset-tag%").
		WillReturnRows(allRows)

	// IssuerContains filter - which does not exist
	store.Mock.ExpectQuery(`SELECT \* FROM "tag_certificate"  WHERE \(lower\(issuer\) like \$1\) ORDER BY "subject"`).
		WithArgs("%nonexistent-tag-service%").
		WillReturnRows(sqlmock.NewRows(tcCols))

	// ValidOn - with a valid value
	var tcValidOn1 hvs.TagCertificate
	_ = json.Unmarshal([]byte(tcMap["7ce60664-faa3-4c2e-8c45-41e209e4f1db"]), &tcValidOn1)
	store.Mock.ExpectQuery(`SELECT \* FROM "tag_certificate"  WHERE \(CAST\(notbefore AS TIMESTAMP\) <= CAST\(\$1 AS TIMESTAMP\) AND CAST\(\$2 AS TIMESTAMP\) <= CAST\(notafter AS TIMESTAMP\)\) ORDER BY "subject"`).
		WithArgs("2016-09-28T09:08:33.913Z", "2016-09-28T09:08:33.913Z").
		WillReturnRows(sqlmock.NewRows(tcCols).
			AddRow(tcValidOn1.ID.String(), tcValidOn1.HardwareUUID.String(), string(tcValidOn1.Certificate), tcValidOn1.Subject, tcValidOn1.Issuer, tcValidOn1.NotBefore, tcValidOn1.NotAfter))

	// ValidBefore - with a valid value
	var tcValidOn2 hvs.TagCertificate
	_ = json.Unmarshal([]byte(tcMap["7ce60664-faa3-4c2e-8c45-41e209e4f1db"]), &tcValidOn2)
	store.Mock.ExpectQuery(`SELECT \* FROM "tag_certificate"  WHERE \(CAST\(\$1 as timestamp\) >= notbefore\) ORDER BY "subject"`).
		WithArgs("2016-09-28T09:08:33.913Z").
		WillReturnRows(sqlmock.NewRows(tcCols).
			AddRow(tcValidOn2.ID.String(), tcValidOn2.HardwareUUID.String(), string(tcValidOn2.Certificate), tcValidOn2.Subject, tcValidOn2.Issuer, tcValidOn2.NotBefore, tcValidOn2.NotAfter))

	// ValidAfter - with a valid value
	var tcValidOn3 hvs.TagCertificate
	_ = json.Unmarshal([]byte(tcMap["7ce60664-faa3-4c2e-8c45-41e209e4f1db"]), &tcValidOn3)
	store.Mock.ExpectQuery(`SELECT \* FROM "tag_certificate"  WHERE \(CAST\(\$1 as timestamp\) <= notafter\) ORDER BY "subject"`).
		WithArgs("2040-09-28T09:08:33.913Z").
		WillReturnRows(sqlmock.NewRows(tcCols).
			AddRow(tcValidOn3.ID.String(), tcValidOn3.HardwareUUID.String(), string(tcValidOn3.Certificate), tcValidOn3.Subject, tcValidOn3.Issuer, tcValidOn3.NotBefore, tcValidOn3.NotAfter))

	// call the real store
	return store.TagCertificateStore.Search(criteria)
}

// NewMockTagCertificateStore initializes the mock datastore
func NewMockTagCertificateStore() *MockTagCertificateStore {
	datastore, mock := postgres.NewSQLMockDataStore()

	return &MockTagCertificateStore{
		Mock:                mock,
		TagCertificateStore: postgres.NewTagCertificateStore(datastore),
	}
}
