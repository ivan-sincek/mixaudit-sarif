# MixAudit SARIF

Convert MixAudit's JSON formatted results to SARIF format.

Tested on Kali Linux v2023.1 (64-bit) and with GitHub Actions.

Made for educational purposes. I hope it will help!

## How to Run

Open your preferred console from [/src/](https://github.com/ivan-sincek/mixaudit-sarif/tree/master/src) and run the commands show below.

Install required packages:

```fundamental
pip3 install -r requirements.txt
```

Run the script:

```fundamental
python mixaudit_sarif.py
```

Check the workflow [here](https://github.com/ivan-sincek/mixaudit-sarif/blob/main/workflows/mixaudit-analysis.yml).

## Other Elixir Workflows

Check the workflow for Elixir projects built on Phoenix framework [here](https://github.com/ivan-sincek/mixaudit-sarif/blob/main/workflows/sobelow-analysis.yml).

## Usage

```fundamental
MixAudit SARIF v1.7 ( github.com/ivan-sincek/mixaudit-sarif )

Usage:   python mixaudit_sarif.py -f file          -o out           -d directory
Example: python mixaudit_sarif.py -f mixaudit.json -o results.sarif -d $GITHUB_WORKSPACE

DESCRIPTION
    Convert MixAudit's JSON formatted results to SARIF format
FILE
    MixAudit's JSON results file
    -f <file> - mixaudit.json | etc.
OUT
    SARIF output file
    -o <out> - results.sarif | etc.
DIRECTORY
    Project's root directory within the workflow container
    -d <directory> - $GITHUB_WORKSPACE | /home/runner/work/repo/repo | etc.
```
