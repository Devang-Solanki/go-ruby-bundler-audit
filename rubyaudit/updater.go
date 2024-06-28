// rubyaudit/updater.go
package rubyaudit

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	GitRepoURL  = "https://github.com/rubysec/ruby-advisory-db.git"
	AdvisoryDir = ".config/vulndb"
)

// UpdateDB updates the advisory database from the remote Git repository
func UpdateDB() {
	log.Print("Updating the advisory database...")

	// Create the directory if it doesn't exist
	advisoryPath := filepath.Join(os.Getenv("HOME"), AdvisoryDir)
	if _, err := os.Stat(advisoryPath); os.IsNotExist(err) {
		os.MkdirAll(advisoryPath, 0755)
	}

	// Check if the database is already cloned
	if _, err := os.Stat(filepath.Join(advisoryPath, ".git")); os.IsNotExist(err) {
		log.Print("Cloning the advisory database...")
		// Clone the repository
		cmd := exec.Command("git", "clone", GitRepoURL, advisoryPath)
		if err := cmd.Run(); err != nil {
			log.Printf("Failed to clone the repository: %v", err)
			return
		}
	} else {
		log.Print("Pulling the latest changes...")
		// Pull the latest changes
		cmd := exec.Command("git", "-C", advisoryPath, "pull", "origin", "main")
		if err := cmd.Run(); err != nil {
			log.Printf("Failed to pull the latest changes: %v", err)
			return
		}
	}

	log.Print("Database update completed.")
}
