# Get the latest tag
$latestTag = git describe --tags --abbrev=0

# If there's no tag yet, start with v0.1.0
if (-not $latestTag) {
    $latestTag = "v0.1.0"
}

# Extract the version numbers
$version = $latestTag -replace '^v'
$major, $minor, $patch = $version -split '\.'

# Increment the patch version
$patch = [int]$patch + 1

# Create the new version string
$newVersion = "v$major.$minor.$patch"

# Create a new tag
git tag -a $newVersion -m "Release $newVersion"

# Push the new tag to origin
git push origin $newVersion

Write-Host "Created and pushed new tag: $newVersion"
