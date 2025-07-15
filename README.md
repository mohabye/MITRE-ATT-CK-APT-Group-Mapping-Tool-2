# Threat Mapping Pro - MITRE ATT&CK Analyzer

## Overview

Threat Mapping Pro is a Python-based tool designed for advanced threat intelligence analysis using the MITRE ATT&CK framework. It enables security analysts to map and analyze Advanced Persistent Threat (APT) groups, their techniques, tactics, and procedures (TTPs), and generate actionable insights. The tool supports integration with MITRE ATT&CK Navigator for visualization and exports detailed reports in JSON and Excel formats.

## Features

- **APT Group Mapping**: Analyze APT groups by their MITRE ID, name, or aliases, mapping their associated techniques, tactics, platforms, and data sources.
- **Technique Prevalence Analysis**: Identify the most commonly used techniques within a specific tactic across APT groups.
- **Technique Usage Assessment**: Assess the usage of specific techniques by APT groups and export detailed reports to Excel.
- **Country-Targeted APT Analysis**: Identify and rank the top 20 APT groups targeting a specified country based on activity and relevance.
- **MITRE ATT&CK Navigator Integration**: Generate JSON layers for visualization in the MITRE ATT&CK Navigator.
- **Comprehensive Reporting**: Outputs detailed analysis results in JSON and Excel formats for further analysis and sharing.

## Prerequisites

- Python 3.6+
- Required Python packages:
  - `requests`
  - `openpyxl`
- Internet connection to fetch MITRE ATT&CK Enterprise data

Install dependencies using:
```bash
pip install requests openpyxl
```

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/mohabye/threat-mapping-pro.git
   cd threat-mapping-pro
   ```


## Usage

Run the tool using:
```bash
python threat_mapping_pro.py
```

Upon execution, the tool displays a banner and presents a menu with the following options:
1. **Map APT Group**: Enter an APT group name, MITRE ID (e.g., G0006), or alias (e.g., APT1, Lazarus Group) to map its techniques and tactics.
2. **Analyze Tactic Prevalence**: Analyze the prevalence of techniques within a specified tactic (e.g., Persistence, Defense Evasion).
3. **Assess Technique Usage & Export to Excel**: Assess a specific technique (by name or ID, e.g., T1547.001) and export the results to an Excel file.
4. **List Top 20 APT Groups by Country Target**: Identify the top 20 APT groups targeting a specified country (e.g., United States, China).

### Example Workflow
1. Run the script:
   ```bash
   python threat_mapping_pro.py
   ```
2. Select option `1` to map an APT group.
3. Enter `Lazarus Group` or `G0010`.
4. Review the detailed analysis, including techniques, tactics, and platforms.
5. A JSON file (e.g., `lazarus_group_navigator_layer.json`) is generated for MITRE ATT&CK Navigator visualization.

## Output Files

- **Navigator Layer**: JSON files (e.g., `<group_name>_navigator_layer.json`) for visualizing techniques in the MITRE ATT&CK Navigator.
- **Excel Reports**: Excel files (e.g., `technique_usage_T1547_001.xlsx`) containing detailed technique usage by APT groups.
- **Country Analysis**: JSON files (e.g., `<country_name>_apt_analysis.json`) listing top APT groups targeting a specific country.
- **Country Targets Log**: A JSON file (`country_targets.json`) logging queried country targets.

## Notes

- The tool fetches the latest MITRE ATT&CK Enterprise data from the official GitHub repository.
- Ensure a stable internet connection to avoid data retrieval errors.
- For Excel exports, ensure the `openpyxl` package is installed.
- Import generated JSON layers into the MITRE ATT&CK Navigator for interactive visualization.

## Contributing

Contributions are welcome! Please fork the repository, create a new branch, and submit a pull request with your changes. Ensure code follows PEP 8 standards and includes appropriate documentation.


## Author

Created by Muhap Yahia
