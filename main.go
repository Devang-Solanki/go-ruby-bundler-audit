// main.go
package rubyaudit

import (
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"time"

	"github.com/Devang-Solanki/go-bundler-audit/rubyaudit"
)

func main() {
	// Command-line flags
	file := flag.String("file", "", "Path to the Gemfile.lock or yarn.lock file")
	gemName := flag.String("name", "", "Gem name to search for advisories")
	version := flag.String("version", "", "Version of the gem to search for advisories")

	flag.Parse()

	// Update the advisory database in the background
	rubyaudit.UpdateDB()

	// Wait for a short duration to let the update process start
	time.Sleep(2 * time.Second)

	if *file != "" {
		// If a file is provided, handle the extraction based on the file type
		if filepath.Base(*file) == "yarn.lock" {
			deps, err := rubyaudit.ExtractYarnLockDependencies(*file)
			if err != nil {
				log.Fatalf("Error extracting dependencies from yarn.lock: %v", err)
			}
			fmt.Printf("Dependencies in %s:\n", *file)
			for _, dep := range deps {
				fmt.Printf("- %s: %s\n", dep.Name, dep.Version)
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
		fmt.Printf("Advisories for %s %s:\n%s\n", *gemName, *version, result)
	} else {
		log.Println("Usage:")
		log.Println("  --file <file> : Specify the Gemfile.lock or yarn.lock file to process.")
		log.Println("  --name <gem_name> --version <version> : Specify the gem name and version to search advisories for.")
	}
}
