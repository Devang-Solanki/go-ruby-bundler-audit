// rubyaudit/yarn_parser.go
package rubyaudit

import (
	"bufio"
	"bytes"
	"log"
	"os"
	"regexp"
	"strings"
)

type Dependency struct {
	Name    string
	Version string
}

// extractYarnLockDependenciesRaw extracts dependencies from the raw content of a yarn.lock file.
func extractYarnLockDependenciesRaw(content *[]byte) []Dependency {
	var deps []Dependency

	// Define regex patterns for package names and versions.
	packageNameRegex := regexp.MustCompile(`^"([^"]+)"|^([^"\s][^"]*$)`)
	packageVersionRegex := regexp.MustCompile(`^\s{2}version "([^"]+)"`)

	scanner := bufio.NewScanner(bytes.NewReader(*content))
	var packageName string

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "#") {
			continue
		}

		// Match package name lines.
		if match := packageNameRegex.FindStringSubmatch(line); match != nil {
			packageName = ""              // Reset current package name
			for _, m := range match[1:] { // Check both capturing groups.
				if m != "" {
					// Handle multiple package names separated by commas.
					names := strings.Split(m, ", ")[0]
					packageName = extractPackageName(names)
				}
			}
		}

		// Match version lines.
		if match := packageVersionRegex.FindStringSubmatch(line); match != nil {
			version := match[1]
			if packageName != "" {
				deps = append(deps, Dependency{Name: packageName, Version: version})
			}
			packageName = "" // Reset for the next set of packages.
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error scanning yarn.lock content: %v", err)
	}

	return deps
}

// extractYarnLockDependencies extracts dependencies from a yarn.lock file given its file path.
func extractYarnLockDependencies(filePath string) ([]Dependency, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return extractYarnLockDependenciesRaw(&content), nil
}

// extractPackageName handles extracting the package name from a list of names
func extractPackageName(name string) string {
	// Split by '@' and remove the version range if present.
	parts := strings.Split(name, "@")
	if len(parts) > 1 && strings.HasPrefix(parts[len(parts)-1], "npm") {
		return strings.Join(parts[:len(parts)-1], "@")
	}
	return parts[0]
}
