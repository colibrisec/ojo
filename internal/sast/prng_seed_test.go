package sast

import (
	"os"
	"path/filepath"
	"testing"
)

const goPRNGSeedFixture = `package main

import (
	"crypto/rand"
	"math/big"
	mrand "math/rand"
)

func unsafe() {
	mrand.Seed(1234)
}

func unsafeSource() {
	mrand.NewSource(1234)
}

func safe() {
	n, _ := rand.Int(rand.Reader, big.NewInt(100))
	_ = n
}
`

func TestGoPredictablePRNGSeed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(goPRNGSeedFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "go-predictable-prng-seed" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 go-predictable-prng-seed issues (Seed + NewSource), got %d: %+v", count, issues)
	}
}

const pyPRNGSeedFixture = `import random

def unsafe():
    random.seed(1234)

def safe():
    random.seed()
`

func TestPythonPredictablePRNGSeed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(pyPRNGSeedFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "py-predictable-prng-seed" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 py-predictable-prng-seed issue, got %d: %+v", count, issues)
	}
}

const rubyPRNGSeedFixture = `srand(1234)
srand
`

func TestRubyPredictablePRNGSeed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.rb"), []byte(rubyPRNGSeedFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "ruby-predictable-prng-seed" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 ruby-predictable-prng-seed issue, got %d: %+v", count, issues)
	}
}

const phpPRNGSeedFixture = `<?php
srand(1234);
mt_srand(5678);
srand();
`

func TestPHPPredictablePRNGSeed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.php"), []byte(phpPRNGSeedFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "php-predictable-prng-seed" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 php-predictable-prng-seed issues (srand + mt_srand, not the no-arg srand()), got %d: %+v", count, issues)
	}
}

const javaPRNGSeedFixture = `import java.util.Random;

class C {
	void unsafe() {
		Random r = new Random(1234);
	}

	void safe() {
		Random r = new Random();
	}
}
`

func TestJavaPredictablePRNGSeed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "C.java"), []byte(javaPRNGSeedFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "java-predictable-prng-seed" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 java-predictable-prng-seed issue, got %d: %+v", count, issues)
	}
}
