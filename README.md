# SegmentN3t
Tool to test internal segmentation networks.

Execute it as ROOT.

```
sudo pipenv shell
pip3 install -r requirements.txt 	
```

Example of usage:

```
python3 segmentn3t.py -i config.json
```

Example of `config.json`:

```
[
	{
		"network": "DMZ",
		"subnets": 
		[
			{
				"vlan" : "VLAN7",
				"ip" : "127.0.0.1/28"

			}

		]
	},
	{
		"network": "FW",
		"subnets": 
		[
			{
				"vlan" : "VLAN73",
				"ip" : "127.0.0.1/30"

			},
			{
				"vlan" : "VLAN72",
				"ip" : "127.0.0.2"

			}
		]
	}
]

```

# Report3r.py

Report3r is used for making reports from SegmentN3t tool.

Example of usage:

```
python3 report3r.py -r /tmp/report/2050-09-21_08:48:46/
```

It will make a report from results in word file format.
