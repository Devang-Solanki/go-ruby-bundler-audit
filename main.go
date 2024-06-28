// main.go
package main

import (
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"time"

	rubyaudit "github.com/Devang-Solanki/go-ruby-bundler-audit/rubyaudit"
)

func printResult(results []rubyaudit.Advisory, gemName *string, version *string) {
	fmt.Printf("Advisories for %s %s:\n", *gemName, *version)
	for _, res := range results {
		fmt.Println("	Gem:", res.Gem)
		fmt.Println("	Title:", res.Title)
		fmt.Println("	URL:", res.URL)
		fmt.Println("	Date:", res.Date)
		fmt.Println("	Description:", res.Description)
		fmt.Println("	CVE:", res.CVE)
		fmt.Println("	GHSA:", res.GHSA)
		fmt.Println("	Patched Versions:", res.PatchedVersions)
		fmt.Println("	Unaffected Versions:", res.UnaffectedVersions)
		fmt.Println() // Adding an empty line for better readability between entries
	}
}

func main() {
	// Command-line flags
	file := flag.String("file", "", "Path to the Gemfile.lock or yarn.lock file")
	gemName := flag.String("name", "", "Gem name to search for advisories")
	version := flag.String("version", "", "Version of the gem to search for advisories")

	flag.Parse()

	// Wait for a short duration to let the update process start
	time.Sleep(2 * time.Second)

	if *file != "" {
		// If a file is provided, handle the extraction based on the file type
		if filepath.Base(*file) == "yarn.lock" {
			deps, err := rubyaudit.ExtractGemfileLockDependencies(*file)
			if err != nil {
				log.Fatalf("Error extracting dependencies from yarn.lock: %v", err)
			}
			fmt.Printf("Dependencies in %s:\n", *file)
			for _, dep := range deps {
				fmt.Printf("- %s: %s\n", dep.Name, dep.Version)
				result, err := rubyaudit.SearchAdvisories(dep.Name, dep.Version)
				if err != nil {
					log.Fatalf("Error searching advisories: %v", err)
				}
				printResult(result, gemName, version)
			}
		} else if filepath.Base(*file) == "Gemfile.lock" {
			// You could add parsing for Gemfile.lock similarly here
			fmt.Println("Gemfile.lock parsing not implemented yet.")
		} else {
			log.Fatalf("Unsupported lock file type: %s", *file)
		}
	} else if *gemName != "" && *version != "" {
		// If gem name and version are provided, search for advisories
		result, err := rubyaudit.SearchAdvisories(*gemName, *version)
		if err != nil {
			log.Fatalf("Error searching advisories: %v", err)
		}
		printResult(result, gemName, version)
	} else {
		log.Println("Usage:")
		log.Println("  --file <file> : Specify the Gemfile.lock or yarn.lock file to process.")
		log.Println("  --name <gem_name> --version <version> : Specify the gem name and version to search advisories for.")
	}
}
