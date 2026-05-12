#!/usr/bin/env bash
# Usage: ./scan_sbom.sh /path/to/sbom_directory affected.txt

set -euo pipefail

# collect input arguments
SBOM_DIR="${1:-./}"
AFFECTED_FILE="${2:-affected.txt}"

# validate dir and affected.txt file
if [ ! -d "$SBOM_DIR" ]; then
  echo "Directory not found: $SBOM_DIR"
  exit 1
fi

if [ ! -f "$AFFECTED_FILE" ]; then
  echo "Affected packages file not found: $AFFECTED_FILE"
  exit 1
fi

# find all CycloneDX JSON files
mapfile -t SBOM_FILES < <(find "$SBOM_DIR" -type f -name "*.json")

if [ ${#SBOM_FILES[@]} -eq 0 ]; then
  echo "No SBOM JSON files found in directory: $SBOM_DIR"
  exit 1
fi

# Prepare report file
REPORT_FILE="report.csv"
echo "host,sbom_file,package,version,cve" > "$REPORT_FILE"

set +u
# parse affected.txt into an associative array
declare -A affected_pkgs
while IFS= read -r line; do   
  pkg="$(echo "$line" | cut -d':' -f1)"
  versions="$(echo "$line" | cut -d':' -f2)"
  IFS=',' read -ra ver_array <<< "$versions"

  # SAFE assignment for keys containing @ or /
  printf -v "affected_pkgs[$pkg]" '%s' "${ver_array[*]}"   

done < "$AFFECTED_FILE"
set -u

# start scanning SBOM files and store output in temporary file
for SBOM_FILE in "${SBOM_FILES[@]}"; do
  echo "Scanning SBOM: $SBOM_FILE > ..."
  TMP_JSON=$(mktemp)

  # convert SBOM to normalized JSON for trivy
  trivy sbom --format json -o "$TMP_JSON" "$SBOM_FILE" >/dev/null 2>&1 || true

  # check each package and version inside SBOM
  for pkg in "${!affected_pkgs[@]}"; do
    IFS=' ' read -ra vers <<< "${affected_pkgs[$pkg]}"
    for v in "${vers[@]}"; do

      result=$(jq -r --arg pkg "$pkg" --arg ver "$v" '
        (.Results // [])[]?.Packages[]? |
        select(.Name == $pkg and .Version == $ver) |
        "\(.Name) \(.Version)"
      ' "$TMP_JSON")

      if [[ -n "$result" ]]; then
        echo "FOUND VULNERABLE: $pkg version $v"

        # Extract host name from SBOM filename
        host="$(basename "$SBOM_FILE" | sed 's/^sbom_//; s/\..*$//')"

        # Append to report
        echo "$host,$SBOM_FILE,$pkg,$v" >> "$REPORT_FILE"
      fi

    done
  done

  rm -f "$TMP_JSON"
  echo
done

echo "Scan complete"
echo "Report saved to: $REPORT_FILE"