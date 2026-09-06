# 🛠️ Aegis-SRE: Cloud Infrastructure Setup & Status

> 🟢 **Cost Guarantee:** Every service is **100% Free Forever**, with **no credit card required**.

---

## 🚦 Live Cloud Integrations Status

| Service | Status | Description |
| :--- | :--- | :--- |
| **⚡ Groq Cloud LPU (AI Brain)** | ✅ **CONNECTED & VERIFIED** | Running `openai/gpt-oss-20b` (sub-second diagnosis). |
| **🗄️ Neon Cloud PostgreSQL** | ✅ **CONNECTED & VERIFIED** | Serverless Postgres v18 live on AWS us-east-2; tables initialized! |
| **🌐 Cloudflare Zero-Trust** | 🟡 **READY TO RUN** | Choose Quick Tunnel (no account) or Cloudflare Dashboard Named Tunnel. |
| **☁️ Oracle Cloud ARM K3s** | ⏳ **ACTION NEEDED FROM YOU** | Provision Always Free 24 GB RAM Ampere instance on OCI. |

---

## 1. 🌐 Cloudflare Zero-Trust (How It Works — No Site Registration Needed!)

You asked: *"no cloudflare like on site registration and shit ? if thats possible"*

**YES! It is 100% possible to skip on-site registration entirely!** Cloudflare provides two modes:

### Mode A: ⚡ The "No-Registration, No-Account" Way (Recommended for Quick Demos)
You **do not need an account, do not need to register on any website, and do not need a domain**.
1. Install `cloudflared` on your PC:
   ```powershell
   winget install Cloudflare.cloudflared
   ```
2. Run our launcher script:
   ```powershell
   .\scripts\start_public_tunnel.ps1
   ```
3. Cloudflare automatically generates an instant, secure public HTTPS URL (e.g. `https://xxxx.trycloudflare.com`) that connects to your local Aegis Mission Control!

### Mode B: 🏷️ The "Cloudflare Dashboard Named Tunnel" Way (If You Want a Custom Domain)
If you *do* want a custom permanent domain (e.g. `aegis.yourdomain.com`):
1. Create a free account at [dash.cloudflare.com](https://dash.cloudflare.com/).
2. Go to **Zero Trust ➔ Networks ➔ Tunnels ➔ Create a Tunnel**.
3. Copy the tunnel token and run:
   ```powershell
   cloudflared tunnel run --token <YOUR_CLOUDFLARE_TOKEN>
   ```

---

## 2. ☁️ Oracle Cloud Always Free 24 GB ARM K3s Cluster (Step-by-Step)

Since we are using **Oracle Cloud ARM** instead of local Minikube:

### Step 1: Create Your Always-Free OCI Account
1. Go to **[oracle.com/cloud/free](https://www.oracle.com/cloud/free/)** and register for an **Always Free** account.

### Step 2: Provision the 24 GB RAM Ampere ARM Instance
1. In the Oracle Console, navigate to: **Compute ➔ Instances ➔ Create Instance**.
2. Set the configuration:
   - **Name:** `aegis-k3s-node-1`
   - **Image:** `Ubuntu 22.04 LTS (ARM64)`
   - **Shape:** `Ampere` ➔ `VM.Standard.A1.Flex`
   - **OCPUs:** `4 OCPU`
   - **Memory:** `24 GB RAM` (100% Free Tier limit)
   - **Boot Volume:** `100 GB`
   - **SSH Keys:** Download and save the private key file (`oracle_key.key`) to your computer.
3. Click **Create** and wait for the status to turn **Running** 🟢. Note your **Public IP**.

### Step 3: Open Firewall Ports in Oracle VCN
In Oracle Console, go to **Networking ➔ Virtual Cloud Networks ➔ Default Security List for your VCN ➔ Add Ingress Rules**:
- Port `22` (SSH)
- Port `6443` (Kubernetes API Server)
- Port `80`, `443` (HTTP/HTTPS)
- Port `3000` (Grafana)
- Port `8000` (Aegis Dashboard)

### Step 4: Install K3s (1-Command Installer)
SSH into your Oracle instance:
```powershell
ssh -i oracle_key.key ubuntu@<YOUR_ORACLE_PUBLIC_IP>
```
Run this single command inside the Oracle shell:
```bash
# 1. Flush Oracle iptables restrictions
sudo iptables -F && sudo netfilter-persistent save

# 2. Install K3s Lightweight Kubernetes
curl -sfL https://get.k3s.io | sh -

# 3. Allow non-root kubectl access
sudo chmod 644 /etc/rancher/k3s/k3s.yaml

# 4. Verify node is healthy
kubectl get nodes
```

### Step 5: Connect Local `kubectl` to Cloud K3s
1. Copy `/etc/rancher/k3s/k3s.yaml` from your Oracle VM to your local PC.
2. Replace `127.0.0.1` inside `k3s.yaml` with `<YOUR_ORACLE_PUBLIC_IP>`.
3. In PowerShell, set:
   ```powershell
   $env:KUBECONFIG="C:\path\to\k3s.yaml"
   kubectl get nodes
   ```
*Your local machine is now controlling a live 24 GB cloud Kubernetes cluster!*
