# Asset examples
Print out percent of host assets with the External Facing Tag

```python
from VulcanSDK import readOnlyClient

client = readOnlyClient([your Vulcan base URL here],[your API token here])

externalFacingAssets = client.hosts(tags=["External Facing"])["count"]
allAssets = client.hosts()["count"]

print(f"Percent External Facing Hosts: {100 * externalFacingAssets/allAssets}%")   
```

# Vulnerability examples

Print out percent coverage for each threat intel tag
```python
from VulcanSDK import readOnlyClient

client = readOnlyClient([your Vulcan base URL here],[your API token here])

allVulns = client.vulns()["vulnerable"]

THREATS = ["Malware","Weaponized","Exploitable"]
for threat in THREATS:
    vulnsWithThreat = client.vulns(threats=[threat])["vulnerable"]
    print(f"Percent {threat}: {100*len(vulnsWithThreat)/len(allVulns)}%")
```

# Risk score examples 

Graph histogram of risk score value.
```python
from VulcanSDK import readOnlyClient
from matplotlib import pyplot as plt

client = readOnlyClient([your Vulcan base URL here],[your API token here])

risks = [v["max_risk"] for v in client.risks()["vulnerable"]]

plt.hist(risks,bins=[i for i in range(50,101)])
plt.title("Vulcan Risk Score Histogram")
plt.ylabel("Vulnerability Count")
plt.xlabel("Risk Score")
plt.show() 
```

Print a risk score vs CVSS heatmap in csv 

```python
from VulcanSDK import readOnlyClient

client = readOnlyClient([your Vulcan base URL here],[your API token here])

RANGES = [(0,0.9),(1.0,1.9),(2.0,2.9),(3.0,3.9),(4.0,4.9),(5.0,5.9),(6.0,6.9),(7.0,7.9),(8.0,8.9),(9.0,10.0)]
for l,h in RANGES:
    vulns = client.risks(cvss_score_min=l,cvss_score_max=h)["vulnerable"]
    risk_scores = [vuln["max_risk"] for vuln in vulns]
    for rl,rh in RANGES:
        print(sum([rl*10 <= risk_score <= rh*10 for risk_score in risk_scores]),end=",")
    print()
```