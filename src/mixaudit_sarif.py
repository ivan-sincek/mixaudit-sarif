#!/usr/bin/env python

import sys
import os
import json
import requests

# -------------------------- INFO --------------------------

def basic():
	global proceed
	proceed = False
	print("MixAudit SARIF v1.7 ( github.com/ivan-sincek/mixaudit-sarif )")
	print("")
	print("Usage:   python mixaudit_sarif.py -f file          -o out           -d directory")
	print("Example: python mixaudit_sarif.py -f mixaudit.json -o results.sarif -d $GITHUB_WORKSPACE")

def advanced():
	basic()
	print("")
	print("DESCRIPTION")
	print("    Convert MixAudit's JSON formatted results to SARIF format")
	print("FILE")
	print("    MixAudit's JSON results file")
	print("    -f <file> - mixaudit.json | etc.")
	print("OUT")
	print("    SARIF output file")
	print("    -o <out> - results.sarif | etc.")
	print("DIRECTORY")
	print("    Project's root directory within the workflow container")
	print("    -d <directory> - $GITHUB_WORKSPACE | /home/runner/work/repo/repo | etc.")

# ------------------- MISCELENIOUS BEGIN -------------------

def read_json(file):
	tmp = []
	try:
		tmp = json.loads(open(file, "r").read())
	except json.decoder.JSONDecodeError:
		pass
	return tmp

def jdump(data):
	return json.dumps(data, indent = 4, ensure_ascii = False)

def write_file(data, out):
	open(out, "w").write(data)
	print(("Results have been saved to '{0}'").format(out))

# -------------------- MISCELENIOUS END --------------------

# -------------------- VALIDATION BEGIN --------------------

# my own validation algorithm

proceed = True

def print_error(msg):
	print(("ERROR: {0}").format(msg))

def error(msg, help = False):
	global proceed
	proceed = False
	print_error(msg)
	if help:
		print("Use -h for basic and --help for advanced info")

args = {"file": None, "out": None, "directory": None}

def validate(key, value):
	global args
	value = value.strip()
	if len(value) > 0:
		if key == "-f" and args["file"] is None:
			args["file"] = os.path.abspath(value)
			if not os.path.isfile(args["file"]):
				error("File does not exists")
			elif not os.access(args["file"], os.R_OK):
				error("File does not have read permission")
			elif not os.stat(args["file"]).st_size > 0:
				error("File is empty")
			else:
				args["file"] = read_json(args["file"])
				if not args["file"]:
					error("Invalid JSON format")
		elif key == "-o" and args["out"] is None:
			args["out"] = value
		elif key == "-d" and args["directory"] is None:
			args["directory"] = os.path.abspath(value) + os.path.sep

def check(argc, args):
	count = 0
	for key in args:
		if args[key] is not None:
			count += 1
	return argc - count == argc / 2

argc = len(sys.argv) - 1

if argc == 0:
	advanced()
elif argc == 1:
	if sys.argv[1] == "-h":
		basic()
	elif sys.argv[1] == "--help":
		advanced()
	else:
		error("Incorrect usage", True)
elif argc % 2 == 0 and argc <= len(args) * 2:
	for i in range(1, argc, 2):
		validate(sys.argv[i], sys.argv[i + 1])
	if args["file"] is None or args["out"] is None or args["directory"] is None or not check(argc, args):
		error("Missing a mandatory option (-f, -o, -d)", True)
else:
	error("Incorrect usage", True)

# --------------------- VALIDATION END ---------------------

# ----------------------- TASK BEGIN -----------------------

def cve_details(identifier, cve):
	tmp = {
		"security-severity": "",
		"precision": "",
		"tags": []
	}
	cve = ("CVE-{0}").format(cve)
	try:
		response = requests.get(("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={0}").format(cve)).json()
		tmp["security-severity"] = response["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
		tmp["precision"] = response["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"].lower()
		tmp["tags"].extend([cve, tmp["precision"]])
	except (requests.packages.urllib3.exceptions.LocationParseError, requests.exceptions.RequestException):
		tmp = {}
		print_error(("{0}: Cannot fetch {1} details").format(identifier, cve))
	return tmp

def find_line(identifier, file, package):
	position = count = 0
	package = ("\"{0}\"").format(package) # NOTE: String to match in the file.
	with open(file, "r") as stream:
		for line in stream:
			count += 1
			if package in line:
				position = count
				break
	stream.close()
	if not position:
		print_error(("{0}: Cannot find string '{2}' in '{1}'").format(identifier, file, package.strip("\"")))
	return position

def sarif_schema():
	tmp = {
		# NOTE: Update the SARIF schema here.
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": [{
			"tool": {
				"driver": {
					"informationUri": "https://github.com/mirego/mix_audit",
					"name": "MixAudit",
					"rules": []
				}
			},
			"results": []
		}]
	}
	return tmp

def sarif_rule():
	tmp = {
		"id": "",
		"shortDescription": {
			"text": ""
		},
		"fullDescription": {
			"text": ""
		},
		"help": {
			"text": ""
		}
	}
	return tmp

def sarif_result():
	tmp = {
		"ruleId": "",
		"level": "",
		"locations": [{
			"physicalLocation": {
				"artifactLocation": {
					"uri": ""
				}
			}
		}],
		"message": {
			"text": ""
		}
	}
	return tmp

def format(results, directory):
	sarif = {}
	try:
		if not results["vulnerabilities"]:
			print("No vulnerabilities were found")
		else:
			sarif = sarif_schema()
			for vuln in results["vulnerabilities"]:
				rule = sarif_rule()
				result = sarif_result()

				# ----- identifier
				identifier = ("MA-{0}").format(vuln["advisory"]["cve"])
				rule["id"] = identifier
				result["ruleId"] = identifier

				# ----- level
				result["level"] = "warning"
				# TO DO: Change the SARIF semantics version to include CVE details.
				# details = cve_details(identifier, vuln["advisory"]["cve"])
				# if details:
				# 	rule["properties"] = details

				# ----- title
				title = ("{0} (Dependency: {1})").format(vuln["advisory"]["title"].strip(), vuln["advisory"]["package"])
				rule["shortDescription"]["text"] = title
				rule["fullDescription"]["text"] = title

				# ----- message
				date = ("Disclosure date: {0}").format(vuln["advisory"]["disclosure_date"])
				version = ("Current version: {0}").format(vuln["dependency"]["version"])
				patched = ("Patched versions: [ {0} ]").format((" | ").join(vuln["advisory"]["patched_versions"]))
				unaffected = ("Unaffected versions: [ {0} ]").format((" | ").join(vuln["advisory"]["unaffected_versions"]))
				message = ("{0}\n{1}\n{2}\n{3}\n{4}").format(title, date, version, patched, unaffected)
				result["message"]["text"] = message

				# ----- description
				rule["help"]["text"] = vuln["advisory"]["description"].strip()

				# ----- location
				result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = vuln["dependency"]["lockfile"].replace(directory, "")
				line = find_line(identifier, vuln["dependency"]["lockfile"], vuln["advisory"]["package"])
				if line:
					result["locations"][0]["physicalLocation"]["region"] = {
						"startLine": line,
						"endLine": line
					}
				sarif["runs"][0]["tool"]["driver"]["rules"].append(rule)
				sarif["runs"][0]["results"].append(result)
	except KeyError as ex:
		sarif = {}
		print_error(("Invalid JSON key '{0}'").format(ex))
	return sarif

if proceed:
	print("#######################################################################")
	print("#                                                                     #")
	print("#                         MixAudit SARIF v1.7                         #")
	print("#                                   by Ivan Sincek                    #")
	print("#                                                                     #")
	print("# Convert MixAudit's JSON formatted results to SARIF format.          #")
	print("# GitHub repository at github.com/ivan-sincek/mixaudit-sarif.         #")
	print("#                                                                     #")
	print("#######################################################################")
	sarif = format(args["file"], args["directory"])
	if sarif:
		write_file(jdump(sarif), args["out"])

# ------------------------ TASK END ------------------------
