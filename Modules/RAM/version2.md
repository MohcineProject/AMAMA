# The practical multi-agent design 

## 1- Collector 
- Runs the volatility commands and prepares a list of process records in a txt file.
- A single process record contains all the informations detected by volatility using these plugins

| Filename | Plugin | Required? |
|----------|--------|-----------|
| `pstree.txt` | `windows.pstree.PsTree` | **Required** |
| `psscan.txt` | `windows.psscan.PsScan` | **Required** |
| `cmdline.txt` | `windows.cmdline.CmdLine` | Recommended |
| `dlllist.txt` | `windows.dlllist.DllList` | Recommended |
| `privileges.txt` | `windows.privileges.Privs` | Recommended |
| `netscan.txt` | `windows.netscan.NetScan` | Optional (often empty on ELF dumps) |
| `netstat.txt` | `windows.netstat.NetStat` | Recommended (merged with netscan) |
| `handles.txt` | `windows.handles.Handles` | Optional (large; use `--no-handles` to skip) |
| `getsids.txt` | `windows.getsids.GetSIDs` | Optional |

- The script is designed to emit processes in structured way :
	- We emit by chunks that do not exceeds a predefined number of tokens
	- Each chunk contains a list of full subtrees, so we don’t lose the information about parent 	   and child relationships

## 2- Agent 1: triage analyst :
Reads only the high-level file and returns, their PIDS and a summary of why it was flagged suspicious.

## 3- Agent 2: pivot analyst
Receives only the output from the agent and use it to investigate deeper using the SIFT workstation, and to collect evidence on each process and confirm it is mallicious.


## 4- Agent 3: report writer 
Correlates all pivots into a short incident narrative: 
• initial access guess 
• execution chain 
• persistence 
• credential access 
• staging 
• likely files of interest 

That split keeps the token load low and makes the workflow repeatable. 