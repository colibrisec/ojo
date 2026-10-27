package misconfig

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/colibrisec/ojo/internal/fpcorpus"
)

// False-positive regression corpus: triaged false positives (source says
// where) next to must-fire twins. want is one of fpcorpus.Check's values.
var misconfigFPCorpus = []struct {
	name, source, file, content, rule, want string
}{
	{
		name:   "ENV block with TOKENIZERS_PARALLELISM",
		source: "triaged false positive",
		file:   "Dockerfile",
		rule:   "dockerfile-secret-env",
		want:   "none",
		content: `FROM python:3.11-slim@sha256:abc
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    TOKENIZERS_PARALLELISM=false \
    HF_HUB_OFFLINE=1 \
    HF_HOME=/tmp/huggingface
`,
	},
	{
		name:    "secret word only in a value",
		source:  "triaged false positive",
		file:    "Dockerfile",
		rule:    "dockerfile-secret-env",
		want:    "none",
		content: "FROM alpine:3.20\nENV HINT=see-password-manager\nARG BUILD_NOTE=\"no token needed\"\n",
	},
	{
		name:    "*_FILE points at a secret instead of holding one",
		source:  "Docker secrets convention",
		file:    "Dockerfile",
		rule:    "dockerfile-secret-env",
		want:    "none",
		content: "FROM postgres:17\nENV POSTGRES_PASSWORD_FILE=/run/secrets/db\n",
	},
	{
		name:    "ENV key=value secret name",
		source:  "twin",
		file:    "Dockerfile",
		rule:    "dockerfile-secret-env",
		want:    "fire",
		content: "FROM alpine:3.20\nENV PATH=/x GITHUB_TOKEN=abc\n",
	},
	{
		name:    "legacy ENV key value form",
		source:  "twin",
		file:    "Dockerfile",
		rule:    "dockerfile-secret-env",
		want:    "fire",
		content: "FROM alpine:3.20\nENV API_KEY abc def\n",
	},
	{
		name:    "ARG without default",
		source:  "twin",
		file:    "Dockerfile",
		rule:    "dockerfile-secret-env",
		want:    "fire",
		content: "FROM alpine:3.20\nARG DB_PASSWORD\n",
	},
	{
		name:    "ENV from build arg",
		source:  "twin",
		file:    "Dockerfile",
		rule:    "dockerfile-secret-env",
		want:    "fire",
		content: "FROM alpine:3.20\nENV DB_PASSWORD=${DB_PASSWORD}\n",
	},
	{
		name:    "camelCase ARG",
		source:  "twin",
		file:    "Dockerfile",
		rule:    "dockerfile-secret-env",
		want:    "fire",
		content: "FROM alpine:3.20\nARG npmToken\n",
	},
	{
		name:   "FROM resolved through a pinned ARG default",
		source: "triaged false positive",
		file:   "Dockerfile",
		rule:   "dockerfile-latest-tag",
		want:   "none",
		content: `ARG PYTHON_IMAGE=python:3.11-slim-bookworm@sha256:abc
FROM ${PYTHON_IMAGE} AS build
FROM $PYTHON_IMAGE
`,
	},
	{
		name:    "FROM ARG with an unpinned default",
		source:  "twin",
		file:    "Dockerfile",
		rule:    "dockerfile-latest-tag",
		want:    "fire",
		content: "ARG BASE=python\nFROM ${BASE}\n",
	},
	{
		name:    "FROM ARG with no default",
		source:  "twin",
		file:    "Dockerfile",
		rule:    "dockerfile-latest-tag",
		want:    "fire",
		content: "ARG BASE\nFROM ${BASE}\n",
	},
	{
		name:    "FROM scratch",
		source:  "triaged false positive",
		file:    "Dockerfile",
		rule:    "dockerfile-latest-tag",
		want:    "none",
		content: "FROM golang:1.25@sha256:abc AS build\nFROM scratch\n",
	},
	{
		name:    "FROM an earlier build stage",
		source:  "triaged false positive",
		file:    "Dockerfile",
		rule:    "dockerfile-latest-tag",
		want:    "none",
		content: "FROM node:22-alpine AS base\nFROM base AS development\nFROM base AS build\n",
	},
	{
		name:    "registry port is not a tag",
		source:  "twin",
		file:    "Dockerfile",
		rule:    "dockerfile-latest-tag",
		want:    "fire",
		content: "FROM registry.local:5000/app\n",
	},
	{
		name:    "FROM :latest",
		source:  "twin",
		file:    "Dockerfile",
		rule:    "dockerfile-latest-tag",
		want:    "fire",
		content: "FROM ubuntu:latest\n",
	},
	{
		name:   "pod-level runAsNonRoot",
		source: "triaged false positive",
		file:   "deploy.yaml",
		rule:   "k8s-run-as-root",
		want:   "none",
		content: `apiVersion: apps/v1
kind: Deployment
metadata: {name: api}
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
      containers:
        - name: api
          image: api:1
          securityContext:
            allowPrivilegeEscalation: false
        - name: sidecar
          image: side:1
`,
	},
	{
		name:   "container-level non-zero runAsUser",
		source: "Kubernetes semantics",
		file:   "deploy.yaml",
		rule:   "k8s-run-as-root",
		want:   "none",
		content: `apiVersion: v1
kind: Pod
metadata: {name: p}
spec:
  containers:
    - name: c
      image: c:1
      securityContext: {runAsUser: 1000}
`,
	},
	{
		name:   "container overrides pod runAsNonRoot with false",
		source: "twin",
		file:   "deploy.yaml",
		rule:   "k8s-run-as-root",
		want:   "fire",
		content: `apiVersion: v1
kind: Pod
metadata: {name: p}
spec:
  securityContext: {runAsNonRoot: true}
  containers:
    - name: c
      image: c:1
      securityContext: {runAsNonRoot: false}
`,
	},
	{
		name:   "no securityContext anywhere",
		source: "twin",
		file:   "deploy.yaml",
		rule:   "k8s-run-as-root",
		want:   "fire",
		content: `apiVersion: v1
kind: Pod
metadata: {name: p}
spec:
  containers:
    - name: c
      image: c:1
`,
	},
}

func TestMisconfigFalsePositiveCorpus(t *testing.T) {
	for _, c := range misconfigFPCorpus {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, c.file), []byte(c.content), 0o644); err != nil {
				t.Fatal(err)
			}
			issues, err := Scan(dir)
			if err != nil {
				t.Fatal(err)
			}
			fpcorpus.Check(t, c.rule, c.want, c.source, issues)
		})
	}
}
