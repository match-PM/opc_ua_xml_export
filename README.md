OPC UA XML Export client
=========================

This client exports all nodes from a running OPC UA server into a node XML file

Dependencies
------------
* Python3
* opcua-asyncio v0.9.98 (https://github.com/FreeOpcUa/opcua-asyncio)
* progressbar2 (https://pypi.org/project/progressbar2/)

Install
-------
```bash
pip install asyncua
pip install progressbar2
```


Run
---
Export nodes from server `opc.tcp://localhost:16664` into XML file `export.xml`

The script is modified to our needs. It deletes all nodes without a namespace, instead of the ones need.

Generate xml:
```
python3 NodeXmlExporter.py --namespace 0 --namespace 2 opc.tcp://PC1M0484-1:4840 export_ns02.xml
```

Then you can use the nodeset_compiler. Use the open62541 repro.
There you can run:

```
python3 nodeset_compiler.py -e ../../deps/ua-nodeset/Schema/Opc.Ua.NodeSet2.xml --xml ~/Downloads/opc_ua_xml_export_client/export_ns21.xml  /home/pmlab/Downloads/new_server
```

Finally, you can copy the the generated the "new_server.c" file to match_pm_robot/opcua_server pgk.
Replace the current pm_opcua_server.c. 

Then run the "modify_server_export.py" script to apply some changes which are nessesary to run the server properly.

Build the workspace. Then you can run the opcua_server.
