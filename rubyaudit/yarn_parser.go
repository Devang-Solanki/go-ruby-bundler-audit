// rubyaudit/yarn_parser.go
package rubyaudit

import (
	"bufio"
	"bytes"
	"log"
	"os"
	"strings"
)

type Dependency struct {
	Name    string
	Version string
}

// extractGemfileLockMainDependencies parses the Gemfile.lock content to extract main dependencies.
func ExtractGemfileLockDependenciesRaw(content *[]byte) []Dependency {
	var deps []Dependency

	scanner := bufio.NewScanner(bytes.NewReader(*content))

	// Indicate when we are inside the GEM specs section.
	inGemSpecsSection := false

	// Read through each line in the Gemfile.lock file.
	for scanner.Scan() {
		line := scanner.Text()

		// Detect the start of the GEM specs section.
		if strings.HasPrefix(line, "GEM") {
			inGemSpecsSection = true
			continue
		}

		// Detect the start of the specs subsection.
		if inGemSpecsSection && strings.TrimSpace(line) == "specs:" {
			inGemSpecsSection = true
			continue
		}

		// End of the GEM specs section.
		if inGemSpecsSection && strings.TrimSpace(line) == "" {
			break
		}

		// Process lines within the specs subsection for main dependencies.
		if inGemSpecsSection && strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "      ") {
			// Extract the gem name and version.
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				name := strings.TrimSuffix(parts[0], " ")
				version := strings.Trim(parts[1], "()")
				deps = append(deps, Dependency{Name: name, Version: version})
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error scanning Gemfile.lock file: %v", err)
	}

	return deps
}

// extractYarnLockDependencies extracts dependencies from a yarn.lock file given its file path.
func ExtractGemfileLockDependencies(filePath string) ([]Dependency, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return ExtractGemfileLockDependenciesRaw(&content), nil
}
