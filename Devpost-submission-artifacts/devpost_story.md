# AMAMA: Multi-Agent DFIR Triage

## What it does

AMAMA takes a raw memory image and a raw disk image of a (Windows) machine and produces an evidence-traceable incident report, the kind of triage write-up a DFIR analyst would normally spend hours or even days assembling by hand. Rather than being one monolithic tool, it is built as a set of independent forensic modules coordinated by a central orchestrator. Today there are three of them: a RAM module that runs Volatility 3 over a memory image, a Disk module that mounts a disk image and collects the usual Windows artifacts (MFT, registry, event logs, browser history, persistence mechanisms, ...), and a Threat Intelligence module that enriches the potential IOCs the other two surface.

The orchestrator runs these modules in parallel and then drives an investigation loop. Every finding flows back through it, and from there it can decide to route an entity, whether an IP, a hash, a file or a process, to another module to gather more context. This is essentially the pivoting a human analyst does when chasing a lead. Importantly, the final report is not a raw execution log: it groups related findings into a coherent narrative based on the MITRE ATT&CK phases, and ties scattered indicators together into threads.

## How we built it

We built AMAMA almost entirely with Claude Code, on a Python stack. The orchestrator and the agents lean on anthropic, while the modules wrap Volatility 3 and a set of Windows artifact parsers.

The team is a hybrid. Two of us are AI engineers who architected the overall system and the agentic pipelines, two are security analysts who brought the industry knowledge so that our methodology, the artifacts we collect and the way we reason about them all follow the standards that real DFIR investigations use, and, thank god, we also had a developer (Mohcine) who kept the codebase from descending into chaos.

The core architectural idea is a modular design organised around that central orchestrator. Modules talk to the orchestrator through a shared contracts, a set of versioned JSON schemas (ModuleScanResult, EntityQuery and EntityFindings) currently pinned at v1.0. Because every module speaks the same contract, modules can be added or removed at will, and any module declared in the orchestrator config is integrated automatically. A second decision sits at the very heart of the system: the agents never touch the forensic tools directly. Deterministic scripts collect the artifacts, and the agents only read what those tools produced. This is what keeps forensic integrity intact, since every claim in the report traces back to a verbatim line in a real artifact file, with its source file and line number.

## Challenges and limitations

We hit several walls. The first and biggest was simply time, since we had a short deadline for a quite complex topic that sits at the crossroads of memory forensics, disk forensics, threat intelligence and LLM orchestration. The second is that our threat intelligence is currently single-source, the module only queries VirusTotal, whereas we wanted it to consult several sources so it could cross-check and surface more precise, higher-quality information. We simply ran out of time.

The third limitation comes from a design choice. Our architecture deliberately keeps the agents away from the tools to guarantee evidence integrity, so they only read artifacts that were collected deterministically. At the same time, we wanted to give the agents some MCP capability so they could choose which plugin or collector to invoke and look for data in exactly the right place. We believe this would make the pipeline more efficient, but we have not implemented it yet. This might be implemented in later versions of the tool.

Finally, one of the biggest limitations was related to the datasets. It was very difficult to benchmark our tool properly because of the lack of established dataset in the DFIR community and the lack of a standard methodology to evaluate investigative performance. Moreover, the sheer size of the data manipulated made it quite slow and unpractical to test at scale, that's why we didn't have time to perform as much tests as we wanted in the alloted time, this is something to work on if we want the tool to gain credibility and have a good reputation.

## Design decisions, tradeoffs and autonomous execution

Because every finding goes through the orchestrator, the orchestrator can redirect an entity to the Threat Intel module, or to any other module, to gather more information. That gives detailed, end-to-end visibility into a finding, and it is what DFIR people do when they pivot.

We also see real autonomous self-correction. Each module runs a layered agent design in which Agent 1 flags potentially suspicious findings and Agent 2 then confirms or infirms them by analysing further, requiring corroboration across at least two independent artifact types before it will confirm anything. We have many real examples where Agent 2 rejects what Agent 1 raised, which is genuine self-correction, with a written justification, all captured in the audit tree.

The hardest tradeoff is speed against depth. The deeper we go into the artifacts, and the more kinds of artifact we ingest, the more visibility we gain, but the slower and more token-costly the run becomes. To manage this we implemented a fast mode and a full mode. As a concrete illustration, in fast mode the RAM module runs 23 Volatility plugins, whereas in full mode it runs 67. The goal is to minimise blind spots while still staying fast enough to matter, because if the pipeline takes four hours there is no real added value over a human-led investigation.

We are also happy that the report behaves like an analyst rather than spitting out a list of verdicts. For instance, the "Threat Intel Enrichment" finding groups IOCs that share a common thread, in our ROCBA case report it clustered several confirmed brute-force source IPs by their shared ASN and flagged a separate IP as attacker-controlled cloud staging infrastructure. Tying scattered indicators into one story is exactly the value an analyst typically adds, and seeing the system do it on its own is very promising.

Cost is another tradeoff worth spelling out. A DFIR expert bills on the order of a few hundred dollars per hour, and triaging a single host can take many hours, whereas an end-to-end AMAMA run costs on the order of a few dollars in API tokens (~3-8$). We have already done some work to push that even lower by cutting noise before it ever reaches the LLM, for example through the whitelist in the RAM module, which rejects known-good system paths so that most queries terminate before an LLM is ever called. There is clearly still more we can do here to waste fewer tokens.

Finally, a word on guardrails, because agents are powerful but dangerous and do sometimes step off the rails. Occasionally an output does not respect the schema we expect, or it miscategorises something, for example mistaking an executable for a domain. To handle this we added input validation, including logic to make sure that IPs are not interpreted as hashes, together with JSON-schema validation on every agent output. We will not pretend we have caught every edge case, it is constant improvement and very much a work in progress.

## What we learned

We are all still junior engineers and analysts, and this was the first time any of us built something this complex, something that really required coordination across different industries. The biggest lesson was about how to structure the project at every step and discuss every important decision along the way, rather than charging ahead (which we did quite a few times and had to move backwards afterwards!).

It was also a real lesson in working with Claude Code on a large project. That is nothing like asking Claude to write a basic function, it demands advanced prompt engineering and constant monitoring of what the agent is actually doing (otherwise claude can sometimes be a bit verbose and mess-up the codebase quite fast). For the record, we did not pick the "allow dangerously" option!

## What's next

This is a first functioning version, and our ambitions for the project are much bigger. The modular architecture is the real novelty (we haven't seen such a thing in any other proposals shown during the hackathon), since a central orchestrator querying pluggable modules means we can add or remove modules as we please. So if this project gets attention, it will be a pleasure to add more of them in next iterations we want , with a network module the likely next in line, until we can study all the main forensic artifacts through this one architecture.

We also want to broaden the systems we support. Everything today, from the workflow to the prompts to the tuning, is built for Windows, and that was on purpose, because it is the system most used in corporate settings and we wanted to do one thing well rather than produce AI slop. Once the Windows pipeline is solid, we will extend it to Linux and macOS so that AMAMA can analyse any system.

Beyond that, there are a few specific directions we already have in mind. We want to evolve the contract, which is currently pinned at v1.0, now that the pattern has proven itself, to find a shape that makes the data flow between modules even better. We want to move the Threat Intel module beyond VirusTotal towards multiple sources for more precise, corroborated intelligence. And we want to give the agents the ability to choose which plugin or collector to query through MCP, without giving up the evidence-integrity guarantees the whole architecture is built around.

All in all, we are quite happy with what we built, and at the same time we know about how much further it can still go.