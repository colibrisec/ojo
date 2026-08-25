package sast

import (
	"os"
	"path/filepath"
	"testing"
)

const pyXXEFixture = `from lxml import etree

def unsafe():
    parser = etree.XMLParser(resolve_entities=True)
    return etree.parse("input.xml", parser)

def safe():
    parser = etree.XMLParser(resolve_entities=False)
    return etree.parse("input.xml", parser)
`

func TestPythonXXE(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(pyXXEFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "py-xxe" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 py-xxe issue, got %d: %+v", count, issues)
	}
}

const phpXXEFixture = `<?php
function unsafe() {
	libxml_disable_entity_loader(false);
	return simplexml_load_string($xml);
}

function safe() {
	libxml_disable_entity_loader(true);
	return simplexml_load_string($xml);
}
`

func TestPHPXXE(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.php"), []byte(phpXXEFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "php-xxe" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 php-xxe issue, got %d: %+v", count, issues)
	}
}

const rubyXXEFixture = `class Parser
  def unsafe_const
    Nokogiri::XML(data, nil, nil, Nokogiri::XML::ParseOptions::NOENT)
  end

  def unsafe_block
    Nokogiri::XML(data) do |config|
      config.noent
    end
  end

  def safe
    Nokogiri::XML(data) { |config| config.nonet }
  end
end
`

func TestRubyXXE(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.rb"), []byte(rubyXXEFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "ruby-xxe" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 ruby-xxe issues (const + block-call, not safe/nonet), got %d: %+v", count, issues)
	}
}
