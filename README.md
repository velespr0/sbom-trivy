# SBOM Trivy Scanner

This is a script to scan SBOM (Software Bill of Materials) files for specific vulnerable packages listed in a text file. It uses **Trivy** to normalize SBOMs and **jq** to query them for matches.

## How it Works
The `scan_sbom.sh` script:
1.  Loads a list of "affected" packages and versions from `affected.txt`.
2.  Finds all CycloneDX JSON files in a specified directory.
3.  Normalizes each SBOM using Trivy.
4.  Matches the normalized data against your list of affected packages.
5.  Outputs a `report.csv` file with the findings.

## Prerequisites
- [Trivy](https://github.com/aquasecurity/trivy)
- [jq](https://stedolan.github.io/jq/)
- Bash 4.0+

## Usage
1.  Update `affected.txt` with the packages you are looking for in `package:version1,version2` format.
2.  Run the script:
    ```bash
    ./scan_sbom.sh /path/to/sbom_directory affected.txt
    ```
3.  Check `report.csv` for results.

## Files
- `scan_sbom.sh`: The main scanning logic.
- `affected.txt`: Input file containing target packages (e.g., `rimarf:1.0.0`).
- `.gitignore`: Configured to exclude reports and host-specific data.
