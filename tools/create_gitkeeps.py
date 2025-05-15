import os

def create_gitkeep_files(root="."):
    for dirpath, dirnames, filenames in os.walk(root):
        # Skip .git and virtual environments
        if ".git" in dirpath or "venv" in dirpath or ".venv" in dirpath:
            continue
        if not dirnames and not filenames:
            gitkeep_path = os.path.join(dirpath, ".gitkeep")
            if not os.path.exists(gitkeep_path):
                with open(gitkeep_path, "w") as f:
                    pass
                print(f"Created: {gitkeep_path}")

if __name__ == "__main__":
    create_gitkeep_files()
    print("All .gitkeep files created.")
# This script creates .gitkeep files in empty directories to ensure they are tracked by Git.