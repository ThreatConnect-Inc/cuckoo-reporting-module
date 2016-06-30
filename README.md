# ThreatConnect Cuckoo Reporting Module

Cuckoo reporting module for version 1.2 stable

Cuckoo Sandbox is an open source automated malware analysis system. It provides a modular system
for reporting analysis results of a submitted sample. This module is installed directly into
the reporting modules directory of a Cuckoo instance. It parses the analysis results and creates
an incident in ThreatConnect that represents the analysis session. It also parses out network indicators
from the analysis results and creates indicators in ThreatConnect and associates them with the incident.
This module is designed and tested on Cuckoo version 1.2 Stable. To run the module, simply submit samples
for analysis to the Cuckoo instance as normal and this module will run in line with any other configured
reporting modules.

Requirements
------

This module is for Cuckoo Sandbox which can be obtained here: https://cuckoosandbox.org/

The only python requirements are the threatconnect and ipaddress python modules. This is installable from pypi:
```
pip install threatconnect ipaddress
```

The Basic product edition or higher with an API key is required to use this module.
For information on signing up for an account, please visit https://www.threatconnect.com/platform/editions/

Installation
------

1. Copy `threatconnect-report.py` into the `cuckoo/modules/reporting/` directory where you have installed Cuckoo.
2. Add a section to `reporting.conf` in the `cuckoo/conf` directory. An example is below.
3. Add the Access ID and Secret Key obtained in ThreatConnect during API Key creation.
4. If you are using a private cloud or on-prem instance of ThreatConnect, please change the api_base_url as appropriate.
5. Change the hostname for the Cuckoo instance in the report link template to your instance's host or address.
6. Add the Source, Org, or Community that you want the reports to be created in. It is suggested to create a Source for this purpose.
7. Add a custom attribute called "Analysis ID" to the target source in ThreatConnect. Instructions for creating this attribute can be found here: http://kb.threatconnect.com/customer/en/portal/articles/2215092-creating-custom-attributes

```
[threatconnect-report]
enabled = yes
api_access_id =
api_secret_key =
api_base_url = https://api.threatconnect.com
target_source =
report_link_template = http://cuckoo.example.com/analysis/{}/
```

Usage
------

Once the reporting module is installed, run samples through the instance as normal. The reporting module will
run in line with any other modules that are enabled. Once Cuckoo shows the analysis as reported, login to ThreatConnect
and browse to the incident and indicators that were created.

**Note:** Some Cuckoo instance VMs create benign network traffic. Much of this traffic is caught by ThreatConnect exclusion
lists to prevent import of false positives. If your instance produces traffic that is benign and is not caught by
the system exclusion lists, create a custom exclusion list in the target source. For more information on creating
exclusion lists, please visit http://kb.threatconnect.com/customer/en/portal/articles/2324728-creating-indicator-exclusion-lists
If your Cuckoo instance reports an indicator that turns out to be a false positive, please report it as a false positive
in the UI, via API, or via SDK. For more information on false positives, please visit http://kb.threatconnect.com/customer/portal/articles/2324809

Contact
------

For feedback and assistance with this module, please login to ThreatConnect. The TC Apps Lab email address is listed under the TC Apps Lab tab of the TC Exchange.
