# PowerIntel
A tool to quickly search the MITRE Enterprise database for all threat groups that use specific TTPs.

## Instructions
1. Begin by creating a CSV file named ```techniques.csv``` and populate it with the MITRE technique IDs (e.g., T1023) under a header labeled ```TechniqueID```. (An example file will be provided.) 
2. Then, download the **MITRE ATT&CK STIX JSON** file from the official GitHub repository and save it in the same directory as the CSV file.
3. Next, open PowerShell and navigate to the directory containing the ```techniques.csv```, the ```enterprise-attack.json```, and the PowerIntel tool. Execute the PowerIntel script. Upon execution, the script will prompt you to select both the ```techniques.csv``` and the ```enterprise-attack.json``` files as input.

PowerIntel will analyze the techniques listed in the CSV and identify which adversary groups, according to the MITRE Enterprise ATT&CK framework, utilize those techniques. You will be prompted to specify the number of groups to include in the output. Based on your input, the script selects the top groups that employ the specified techniques and generates Attack Navigator Layer JSON files named after each identified group.

Once the layers are generated, proceed to the MITRE ATT&CK Navigator website. Use the **Open Existing Layer** option to upload all the layer files created by the script. Then, create a new composite layer by clicking the **plus (+)** sign next to the existing layers and selecting **Create Layer from Other Layers.** Configure the options as follows:
* Domain: Enterprise ATT&CK MITRE ATT&CK v17
* Score Expression: a+b+c (This expression assigns a score of 1 to each layer; combining them sums the scores for shared techniques.)
* Gradient: Select from any existing layer
* Legend: Select from any existing layer
Click “Create Layers.”

The resulting composite layer will aggregate all techniques used by the selected APT groups. Techniques shared across multiple groups will have proportionally higher scores.

The scoring and corresponding color gradient are as follows:
* Techniques used by all groups are displayed in red.
* Techniques used by more than one group are displayed in orange.
* Techniques used by only one group are assigned a score of 1 and shown in green.
* Techniques marked in red, indicating common use across all identified groups, should be prioritized during risk assessments and threat identification efforts.
