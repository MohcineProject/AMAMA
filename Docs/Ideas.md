- Mitre attack framework
- Labeling of degree instead of mesurement
- psscan, pslist, netscan, cmdline, dlllist

- context d'execution et le privilege, 

- do hybrid approach LLM and deterministic as default
- do a background running approach, deterministic to be fast and LLM running to check in background 
- check Claude proposal https://claude.ai/chat/7a5cb5d1-f521-403c-ab6d-0b4272d5a08d

- in the full chunked approch keep the trees in the same chunk
- use flags to flag 
- look up other SANS tools for example to find mapping between networks and pids 
- chercher une lib ou une dep 
- chercher s'il y a une façon pour filtrer 
- what if we didn't detect anything
- Don't give evrything, but let the agent use volatility tools freely, and maybe multiple agents
- use "flag" from an open source repo like a github
- check [signed|signed=no] with other custom volatility 
- make the agent 1 produces flags for agent 2 
- specify in the submission the limitations 
- use a deterministic phase to reduce the charge on agent 1, it will flag processe as well for agent 2 *
- rules for DLLs as well 
- Think about Linux and Mac
- **Profile detection**: use vol3 automagic or require explicit `--profile` on failure.

3. Precompute for each node `u` the preorder interval `[start(u), end(u)]` — descendants occupy a contiguous range in `L` (standard tree DFS property).
4. **Atomic units** for packing: intervals of whole subtrees. **Never split inside `(start(u)..end(u))` across chunks**.
5. **Greedy packing** over the *sequence of root subtrees* in the forest:
  - Concatenate root subtree intervals in forest order.
  - If root `r`’s interval length in tokens `T_r` exceeds `max_tokens`, **recursively split** `r` by partitioning its **child subtrees** into consecutive groups:
    - First group starts with `line(r)` plus as many **full child subtrees that fit** in the remaining budget.
    - Next chunk continues with the next group of **completed child subtrees**; prefix each continuation chunk with a deterministic `**# CONTEXT` 1-line breadcrumb** listing ancestors `(name,pid)` so the model doesn’t lose lineage when a huge parent’s children span multiple chunks. This satisfies “don’t chunk between B and C” while still allowing huge `System` trees to stream.

- Use filtering layers before the agents access the data of the images.
- Use a recall mechanism, where the agents output some notes and go back to them regularly.