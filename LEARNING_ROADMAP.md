# 📚 Aegis-SRE: Learning Roadmap

> **Philosophy:** Don't learn everything at once. Learn each concept *just before* you need to use it. This roadmap is structured in the same order as the project phases.

---

## How to Use This Guide

Each section has:
- **What it is** — Plain English explanation
- **The "why it matters for Aegis"** — Why you're learning this
- **Concepts to master** — Specific things to understand
- **Resources** — Where to learn it (free, high-quality sources)
- **Self-test** — How to know you've actually learned it

Work through these **in order**. Don't jump ahead.

---

## 🔵 Stage 0: Foundation (Before Anything Else)

> Learn these first. Everything else builds on them.

---

### 0.1 — Linux Fundamentals

**What it is:** The operating system running inside every container and on your Oracle server.

**Why it matters for Aegis:** Falco watches Linux kernel syscalls. You cannot understand what Falco is detecting if you don't know what the kernel is doing.

**Concepts to master:**
- Processes, PIDs, parent/child process relationships
- File descriptors and how processes read/write files
- Users, permissions, root vs non-root
- What a "system call" (syscall) is — the bridge between user code and the kernel
- `ps`, `top`, `lsof`, `strace` commands
- `/proc` filesystem — how Linux exposes process info

**Resources:**
- [Linux Journey](https://linuxjourney.com/) — free, interactive, beginner-friendly
- [The Linux Command Line (book, free PDF)](https://linuxcommand.org/tlcl.php)
- YouTube: "Linux System Calls Explained" by Jacob Sorber

**Self-test:**
> Can you explain what happens step-by-step when you run `cat /etc/passwd`? (from shell → syscall → kernel → disk → return)

---

### 0.2 — Networking Basics

**What it is:** How computers talk to each other.

**Why it matters for Aegis:** Cilium controls network traffic at the kernel level. The Dashboard communicates over WebSockets. Tailscale creates a VPN mesh.

**Concepts to master:**
- IP addresses, subnets, CIDR notation (e.g., `10.0.0.0/24`)
- TCP vs UDP — what's the difference and when is each used
- Ports — what they are and why they matter for isolation
- DNS — how names resolve to IPs 
- HTTP vs HTTPS — basic request/response model
- What a firewall does (allow/drop rules on packets)
- What a VPN does conceptually

**Resources:**
- [Computer Networking: A Top-Down Approach (free slides)](https://gaia.cs.umass.edu/kurose_ross/online_lectures.html)
- YouTube: "Networking Fundamentals" by Professor Messer
- [Cloudflare Learning Center](https://www.cloudflare.com/learning/) — excellent short articles

**Self-test:**
> If pod A (IP: 10.0.0.5) tries to talk to pod B (IP: 10.0.0.8) on port 5432, and a firewall rule says "DROP all traffic to 10.0.0.8:5432" — what happens?


---

## 🟢 Stage 1: Kubernetes (Phase 1 Foundation)

> The platform everything runs on. Learn just enough to be dangerous.

---

### 1.1 — Container Basics (Docker)

**What it is:** Packaging an app + its dependencies into a portable box.

**Why it matters for Aegis:** Every microservice, every tool (Prometheus, Falco, Ollama) runs in a container.

**Concepts to master:**
- What a container is vs a VM (lightweight namespaced process, not full OS)
- Dockerfile — how to build an image
- `docker run`, `docker ps`, `docker exec`, `docker logs`
- Container networking — how containers talk to each other
- Volumes — how containers persist data
- Container namespaces and cgroups (the Linux primitives underneath Docker)

**Resources:**
- [Play with Docker](https://labs.play-with-docker.com/) — free browser-based lab
- [Docker Official Get Started Guide](https://docs.docker.com/get-started/)
- YouTube: "Docker Tutorial for Beginners" by TechWorld with Nana

**Self-test:**
> Run a container, exec into it, run `ps aux`, and explain what you see. Why is PID 1 special inside a container?



---

### 1.2 — Kubernetes Core Concepts

**What it is:** A system that manages containers across many machines.

**Why it matters for Aegis:** The Go Controller manipulates K8s resources directly. You need to know what you're manipulating.

**Concepts to master:**
- **Pod** — the smallest deployable unit (one or more containers)
- **Deployment** — manages replica sets, handles rolling restarts
- **Service** — stable network endpoint pointing to pods
- **Namespace** — logical isolation within a cluster
- **ConfigMap / Secret** — configuration injection
- **Node** — a physical/virtual machine in the cluster
- The **control plane** — API Server, Scheduler, Controller Manager, etcd
- `kubectl get`, `kubectl describe`, `kubectl apply`, `kubectl delete`, `kubectl logs`

**Resources:**
- [Kubernetes Official Interactive Tutorial](https://kubernetes.io/docs/tutorials/kubernetes-basics/)
- [Katacoda Kubernetes Scenarios](https://killercoda.com/playgrounds/scenario/kubernetes) (free browser lab)
- YouTube: "Kubernetes Explained" by TechWorld with Nana (full course, free)

**Self-test:**
> Deploy a simple nginx pod. Scale it to 3 replicas. Delete one pod manually. Watch Kubernetes recreate it. Explain why it did that.

NOTE: DONE TILL HERE !!!
---

### 1.3 — K3s and ARM Specifics

**What it is:** Lightweight Kubernetes that runs on low-power ARM hardware.

**Why it matters for Aegis:** Your Oracle cluster is K3s on ARM. Some tools need ARM-compatible images.

**Concepts to master:**
- How K3s differs from full K8s (embedded SQLite, single binary)
- ARM64 vs AMD64 architecture — why Docker images are architecture-specific
- Checking image compatibility: `--platform linux/arm64`
- K3s installation and basic `kubeconfig` setup

**Resources:**
- [K3s Documentation](https://docs.k3s.io/)
- [K3s vs K8s comparison article](https://www.rancher.com/blog/2019/why-k3s-is-the-future-of-k8s-at-the-edge)

**Self-test:**
> What does K3s use instead of etcd by default? What's the tradeoff?

note: done till here 

---


## 🟡 Stage 2: Observability (Phase 2 Foundation)

---

### 2.1 — Prometheus & Metrics

**What it is:** A time-series database that scrapes metrics from your services.

**Why it matters for Aegis:** Prometheus is the "thermometer" — it detects CPU spikes, OOM kills, error rates that trigger the triage pipeline.

**Concepts to master:**
- **Metrics types:** Counter, Gauge, Histogram, Summary
- **PromQL** — the query language. Learn: `rate()`, `sum()`, `by()`, `avg_over_time()`
- **Scrape configs** — how Prometheus finds targets
- **AlertManager** — rules that fire when thresholds are crossed
- **Recording rules** — precompute expensive queries
- The Prometheus data model: `metric_name{label="value"} value timestamp`

**Resources:**
- [Prometheus Official Docs](https://prometheus.io/docs/introduction/overview/)
- [Prometheus Getting Started Tutorial](https://prometheus.io/docs/prometheus/latest/getting_started/)
- YouTube: "Prometheus Tutorial" by TechWorld with Nana

**Self-test:**
> Write a PromQL query that: "Alert me if any pod's CPU usage averages above 80% for 5 minutes."


---

### 2.2 — Loki & Log Aggregation

**What it is:** A log aggregation system (like Elasticsearch, but cheaper).

**Why it matters for Aegis:** The LLM needs the "story" — the log lines that explain what happened. Loki provides this.

**Concepts to master:**
- **Labels** in Loki — how logs are indexed (pod name, namespace, etc.)
- **LogQL** — Loki's query language: `{app="checkout"} |= "error"`
- **Promtail** — the agent that ships logs to Loki
- Structured vs unstructured logs — why JSON logs are easier to query
- Log streaming via Grafana

**Resources:**
- [Loki Official Docs](https://grafana.com/docs/loki/latest/)
- [LogQL Cheat Sheet](https://grafana.com/docs/loki/latest/query/)

**Self-test:**
> What's the difference between how Loki indexes logs vs how Elasticsearch does it? Why does this make Loki cheaper?

Done till here!
---

### 2.3 — Falco & eBPF (The Star of Phase 2)

**What it is:** A runtime security tool that watches Linux kernel syscalls in real time.

**Why it matters for Aegis:** Falco is what "sees" hackers. It's the most technically deep component of the project.

**Learn in this order:**

#### Step 1: Understand syscalls first
- What is a syscall? (process asking the kernel to do something)
- Key syscalls to know: `execve` (run a program), `open`/`read`/`write` (file ops), `connect` (network), `clone` (create process)
- How to trace syscalls: `strace -p <PID>`

#### Step 2: Understand eBPF
- **eBPF** = "extended Berkeley Packet Filter" — lets you run safe programs inside the Linux kernel
- Think of it as: "tiny, sandboxed programs that run in the kernel and can observe everything without crashing it"
- Why eBPF vs kernel modules? (safer, no recompilation, verifier prevents crashes)
- eBPF programs attach to "hook points" — syscall entry/exit, network events, etc.

#### Step 3: Learn Falco
- Falco uses eBPF (or kernel module) to tap into syscalls
- **Falco rule syntax** — condition + output + priority
- Built-in rule categories: file access, network, process spawning, privilege escalation
- Falco output: JSON events with process context, container info, syscall details

**Concepts to master:**
- `execve` syscall — why every shell spawn triggers this
- Falco's `spawned_process`, `shell_procs`, `sensitive_files` macros
- Writing a custom Falco rule from scratch
- MITRE ATT&CK framework — what TTPs are, how they map to syscall patterns

**Resources:**
- [Falco Official Docs](https://falco.org/docs/)
- [eBPF.io](https://ebpf.io/) — the best eBPF learning resource
- [Falco Rules Reference](https://falco.org/docs/rules/)
- Book: "Learning eBPF" by Liz Rice (O'Reilly) — free sample chapters available
- YouTube: "eBPF Explained" by Liz Rice (CNCF)
- [MITRE ATT&CK Matrix for Containers](https://attack.mitre.org/matrices/enterprise/containers/)

**Self-test:**
> Write a Falco rule that fires when any process reads `/etc/shadow` inside a container. Map this to a MITRE TTP.

---

## 🟠 Stage 3: AI/LLM Pipeline (Phase 3 Foundation)

---

### 3.1 — How LLMs Work (Conceptual)

**What it is:** Understanding what Llama 3.1 is actually doing under the hood.

**Why it matters for Aegis:** You need to know why LLMs sometimes hallucinate, what "temperature" does, and why prompt structure matters — so you can write better prompts and better guardrails.

**Concepts to master:**
- Transformer architecture at a high level (attention = "which words matter most")
- Tokenization — text → numbers → text
- Inference vs training — you are only doing inference
- **Quantization** — Q4 means 4-bit weights. Smaller model, faster, slightly less accurate
- **Context window** — how much text the LLM can "see" at once
- Temperature — 0 = deterministic, 1+ = creative/random
- Why LLMs hallucinate — they predict likely tokens, not "truth"

**Resources:**
- [3Blue1Brown: "But what is a GPT?"](https://www.youtube.com/watch?v=wjZofJX0v4M) — visual, intuitive
- [Andrej Karpathy: "Intro to Large Language Models"](https://www.youtube.com/watch?v=zjkBMFhNj_g)
- [Ollama Docs](https://ollama.com/docs)

**Self-test:**
> Why does setting temperature=0 help for structured JSON output from an LLM?

---

### 3.2 — RAG (Retrieval-Augmented Generation)

**What it is:** Giving the LLM a searchable "book" to look things up in, rather than relying only on its training data.

**Why it matters for Aegis:** The LLM doesn't know your specific runbooks or the latest MITRE TTPs. RAG injects relevant context at query time.

**Concepts to master:**
- **Embeddings** — converting text to vectors (numbers that capture meaning)
- **Vector similarity search** — finding the most semantically similar documents
- **Chunking** — splitting documents into digestible pieces before embedding
- **Top-K retrieval** — fetching the K most relevant chunks
- The RAG pipeline: Query → Embed query → Search vector DB → Inject results into prompt → LLM answers
- **ChromaDB / Qdrant** — lightweight vector databases

**Resources:**
- [LangChain RAG Tutorial](https://python.langchain.com/docs/tutorials/rag/)
- [Pinecone: "What is a Vector Database?"](https://www.pinecone.io/learn/vector-database/)
- YouTube: "RAG from Scratch" by LangChain

**Self-test:**
> Explain the difference between a keyword search and a vector similarity search. When would vector search give a better result?

---

### 3.3 — Prompt Engineering & Function Calling

**What it is:** Structuring your inputs to the LLM to get reliable, structured outputs.

**Why it matters for Aegis:** The LLM must output valid JSON every single time. Bad prompt = unparseable output = guardrail can't do its job.

**Concepts to master:**
- System prompt vs user prompt vs assistant message
- Few-shot prompting — showing the LLM examples of what you want
- Chain-of-thought prompting — "Think step by step before answering"
- **Function calling / JSON mode** — constraining LLM output to a schema
- JSON Schema — defining what valid output looks like
- How to handle LLM output parsing failures gracefully

**Resources:**
- [OpenAI Prompt Engineering Guide](https://platform.openai.com/docs/guides/prompt-engineering)
- [Ollama JSON mode docs](https://ollama.com/blog/structured-outputs)

**Self-test:**
> Write a system prompt that forces the LLM to output a JSON object with exactly these fields: `category`, `action`, `confidence`, `reason`. Include a few-shot example.

---

## 🔴 Stage 4: Security & Guardrails (Phase 4 Foundation)

---

### 4.1 — MITRE ATT&CK Framework

**What it is:** A globally recognized knowledge base of attacker tactics, techniques, and procedures (TTPs).

**Why it matters for Aegis:** Your guardrails use MITRE TTPs as labels. Krishna's core contribution is mapping Falco events → MITRE TTPs → action categories.

**Concepts to master:**
- **Tactics** = the "why" (e.g., Execution, Persistence, Credential Access, Exfiltration)
- **Techniques** = the "how" (e.g., T1059 = Command and Scripting Interpreter)
- **Sub-techniques** = more specific (e.g., T1059.004 = Unix Shell)
- Container-specific TTPs — what attackers do inside compromised containers
- How to use the ATT&CK Navigator

**Key TTPs to know for Aegis:**
| TTP | Name | What it looks like |
|---|---|---|
| T1059 | Command Execution | Shell spawned inside container |
| T1552 | Unsecured Credentials | Reading /etc/shadow, env vars |
| T1046 | Network Discovery | nmap or curl inside container |
| T1610 | Deploy Container | Unexpected new container |
| T1048 | Exfiltration | Large outbound data transfer |

**Resources:**
- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)
- [Falco + MITRE ATT&CK Mapping](https://falco.org/blog/falco-mitre-attack/)
- [ATT&CK Navigator (interactive)](https://mitre-attack.github.io/attack-navigator/)

**Self-test:**
> A Falco alert fires: "Process `nc` (netcat) launched in container." Which MITRE TTP does this most likely map to? What should Aegis do?

---

### 4.2 — Guardrail Design Principles

**What it is:** Designing safety constraints around AI system outputs.

**Why it matters for Aegis:** This is Krishna's core technical contribution. The guardrail is the "Grumpy Manager" — it prevents catastrophic AI mistakes.

**Concepts to master:**
- **Allowlisting vs denylisting** — allowlist is safer (deny everything not explicitly permitted)
- **Confidence thresholds** — when to trust the LLM vs escalate to human
- **Idempotency** — actions should be safe to apply twice
- **Rate limiting** — prevent restart loops
- **Schema validation** — ensure LLM output matches expected structure before parsing
- **Principle of least privilege** — the controller should only be able to do what it needs to

**Resources:**
- [OWASP AI Security](https://owasp.org/www-project-ai-security-and-privacy-guide/)
- [Google: "Responsible AI Practices"](https://ai.google/responsibilities/responsible-ai-practices/)

**Self-test:**
> List 5 actions an LLM might suggest that should always be blocked. List 5 that are always safe to approve. What makes something "safe"?

---

## 🟣 Stage 5: Go & Kubernetes Controllers (Phase 5 Foundation)

---

### 5.1 — Go Language Basics

**What it is:** The programming language used for the K8s controller (and most of K8s itself).

**Why it matters for Aegis:** The controller and guardrail engine are written in Go.

**Concepts to master:**
- Goroutines and channels — Go's concurrency model
- Error handling — `if err != nil` pattern everywhere
- Structs and interfaces
- `context.Context` — cancellation and deadlines (critical for K8s controllers)
- HTTP client/server basics

**Resources:**
- [A Tour of Go](https://go.dev/tour/) — official, interactive, free
- [Go by Example](https://gobyexample.com/) — short, practical examples
- YouTube: "Go Programming Language Tutorial" by Traversy Media

**Self-test:**
> Write a Go function that makes an HTTP GET request, reads the response body, and handles errors at each step.

---

### 5.2 — Kubernetes Controller Pattern

**What it is:** The reconcile loop — the core pattern of how everything in K8s works.

**Why it matters for Aegis:** The Go Controller is the "muscle" — it watches for action objects and executes them.

**Concepts to master:**
- **Reconcile loop:** Observe desired state → compare with actual state → take action
- **Custom Resource Definitions (CRDs)** — extending K8s with your own object types
- **client-go** library — the Go SDK for talking to K8s API
- **controller-runtime** — higher-level framework built on client-go
- **Informers and work queues** — how controllers watch for changes efficiently
- Leader election — for HA controllers

**Resources:**
- [Kubernetes Controller Tutorial](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/)
- [controller-runtime book](https://book.kubebuilder.io/) — the Kubebuilder book, excellent
- [client-go examples](https://github.com/kubernetes/client-go/tree/master/examples)

**Self-test:**
> What is the difference between a "watch" and a "list" in the K8s API? Why do controllers use informers instead of polling?

---

### 5.3 — Cilium & eBPF Networking

**What it is:** eBPF-based Kubernetes networking and security enforcement.

**Why it matters for Aegis:** Cilium is the "cage" — it cuts network access to quarantined pods without killing them.

**Concepts to master:**
- How Cilium replaces kube-proxy using eBPF
- **CiliumNetworkPolicy** — more expressive than standard K8s NetworkPolicy
- Label-based endpoint selection — how Cilium targets specific pods
- Ingress/Egress rules — what "deny all" means and how to express it
- How eBPF enforces these rules at the kernel level (XDP, TC hooks)
- The difference between quarantine (isolate) vs termination (kill)

**Resources:**
- [Cilium Official Docs](https://docs.cilium.io/)
- [Cilium Network Policy Editor (visual)](https://editor.networkpolicy.io/)
- [eBPF.io — Cilium section](https://ebpf.io/applications/#cilium)

**Self-test:**
> Write a CiliumNetworkPolicy that allows pod A to talk to pod B on port 5432, but blocks all other traffic to pod B.

---

## 🌐 Stage 6: Backend & Dashboard (Phase 7 Foundation)

---

### 6.1 — FastAPI & WebSockets

**What it is:** A modern Python web framework with built-in async support.

**Why it matters for Aegis:** The backend streams real-time data from the cluster to the dashboard.

**Concepts to master:**
- FastAPI route definitions (`@app.get`, `@app.post`)
- Pydantic models for request/response validation
- **WebSockets** — persistent bidirectional connection (vs HTTP request/response)
- `async`/`await` in Python — why async matters for real-time streaming
- Background tasks in FastAPI

**Resources:**
- [FastAPI Official Tutorial](https://fastapi.tiangolo.com/tutorial/)
- [FastAPI WebSockets Guide](https://fastapi.tiangolo.com/advanced/websockets/)

**Self-test:**
> Build a FastAPI endpoint that accepts a WebSocket connection and sends a timestamp message every second. Connect to it with a browser.

---

### 6.2 — React Fundamentals

**What it is:** The JavaScript library for building the dashboard UI.

**Why it matters for Aegis:** The dashboard is a React app showing live cluster state.

**Concepts to master:**
- Components and props
- `useState` and `useEffect` hooks
- Fetching data from an API
- WebSocket client in JavaScript (`new WebSocket(url)`)
- Conditional rendering — show/hide elements based on state
- Basic CSS-in-JS or CSS modules

**Resources:**
- [React Official Tutorial](https://react.dev/learn)
- [The Net Ninja: React Tutorial](https://www.youtube.com/playlist?list=PL4cUxeGkcC9gZD-Tvwfod2gaISzfRiP9d)

**Self-test:**
> Build a React component that connects to a WebSocket server and displays incoming messages in a list, updating in real time.

---

## 📐 Learning Order Summary

```
Week 1:  0.1 Linux + 0.2 Networking           ← Foundation
Week 2:  1.1 Docker + 1.2 Kubernetes Core     ← Containers
Week 3:  1.3 K3s + 2.1 Prometheus             ← Cluster + Metrics
Week 4:  2.2 Loki + 2.3 Falco + eBPF          ← Observability (DEEP)
Week 5:  3.1 LLMs + 3.2 RAG                   ← AI Pipeline
Week 6:  3.3 Prompts + 4.1 MITRE ATT&CK       ← AI Safety
Week 7:  4.2 Guardrails + 5.1 Go basics       ← Security + Code
Week 8:  5.2 K8s Controllers + 5.3 Cilium     ← The Muscle
Week 9:  6.1 FastAPI + 6.2 React              ← Dashboard
```

> **Rule:** Don't move to the next stage until you can pass the self-test for the current one. If you can't explain it simply, you don't know it yet.

---

## 🎯 Quick Reference: What to Google When Stuck

| Stuck On | Search Term |
|---|---|
| eBPF concepts | "eBPF explained Liz Rice" |
| Falco rule syntax | "Falco rule writing guide" |
| K8s controller pattern | "kubebuilder tutorial" |
| MITRE TTPs for containers | "MITRE ATT&CK containers matrix" |
| Cilium network policy | "Cilium network policy editor" |
| LLM JSON output | "Ollama structured output JSON mode" |
| RAG pipeline | "LangChain RAG tutorial" |
| Go K8s SDK | "client-go examples GitHub" |

---

*Learning Roadmap v1.0 — Aegis-SRE*
