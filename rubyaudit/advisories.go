// rubyaudit/advisories.go
package rubyaudit

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/Masterminds/semver/v3"
	"gopkg.in/yaml.v3"
)

const AdvisoryPath = ".config/vulndb"

// Advisory represents the structure of an advisory in the YAML files
type Advisory struct {
	Gem                string   `yaml:"gem"`
	Title              string   `yaml:"title"`
	URL                string   `yaml:"url"`
	Date               string   `yaml:"date"`
	Description        string   `yaml:"description"`
	CVE                string   `yaml:"cve"`
	GHSA               string   `yaml:"ghsa"`
	PatchedVersions    []string `yaml:"patched_versions"`
	UnaffectedVersions []string `yaml:"unaffected_versions"`
}

// LoadAdvisories loads all YAML files in the advisory directory
func LoadAdvisories() ([]Advisory, error) {
	advisoryDir := filepath.Join(os.Getenv("HOME"), AdvisoryPath)

	// Check if the advisory database is present
	if _, err := os.Stat(advisoryDir); os.IsNotExist(err) {
		log.Print("Advisory database not found. Downloading...")
		updateDB()
	}

	var advisories []Advisory

	// Walk through the directory and parse each YAML file
	err := filepath.Walk(advisoryDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if filepath.Ext(path) == ".yml" {
			data, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}
			var advisory Advisory
			if err := yaml.Unmarshal(data, &advisory); err != nil {
				return err
			}
			advisories = append(advisories, advisory)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return advisories, nil
}

// SearchAdvisories searches for advisories affecting the given gem and version
func SearchAdvisories(gemName, version string) (string, error) {
	advisories, err := LoadAdvisories()
	if err != nil {
		return "", fmt.Errorf("failed to load advisories: %v", err)
	}

	gemVersion, err := semver.NewVersion(version)
	if err != nil {
		return "", fmt.Errorf("invalid version: %v", err)
	}

	var results []Advisory
	for _, advisory := range advisories {
		if advisory.Gem == gemName {
			for _, patched := range advisory.PatchedVersions {
				constraint, err := semver.NewConstraint(patched)
				if err != nil {
					log.Printf("invalid constraint: %v", err)
					continue
				}
				if constraint.Check(gemVersion) {
					results = append(results, advisory)
					break
				}
			}
		}
	}

	resultJSON, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal results: %v", err)
	}

	return string(resultJSON), nil
}
