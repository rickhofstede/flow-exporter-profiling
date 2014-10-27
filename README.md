flow-exporter-profiling
=======================

Tool for estimating flow exporter parameters based on the exported flow data. Currently, the following parameters and setups/events can be determined:

* Active timeout
* Idle timeout
* Hardware-based vs. software-based flow exporter
* Flow cache overload
* Several Cisco supervisor modules

For more information on flow monitoring, we refer the reader to [this tutorial](http://ieeexplore.ieee.org/xpl/login.jsp?arnumber=6814316). More information on common flow data artifacts (some of which can be identified using this tool) we refer to [this paper](http://eprints.eemcs.utwente.nl/23200/).

Configuration
-------------

Before being able to run the tool, it should be configured using the predefined constants at the top of the source file.

Execution
---

The tool can be run, after making it executable, as follows:

```
chmod +x flow-exporter-profiling.py
./flow-exporter-profiling.py
```
