---
name: github-actions-optimization
description: Optimize GitHub Actions pipelines and run them on Kubernetes. Use when a workflow is slow or expensive, when designing a caching strategy (dependencies, Docker layers, build artifacts), when deciding GitHub-hosted vs self-hosted runners, or when setting up self-hosted runners on Kubernetes with actions-runner-controller (ARC) — including the GitHub connection (PAT or GitHub App), autoscaling, and runner isolation. Pairs with the mcp-github-enterprise read tools (list_workflows, get_actions_cache_usage, list_self_hosted_runners, list_runner_groups, get_actions_permissions).
---

# GitHub Actions: pipeline optimization & runners on Kubernetes

Two jobs: make pipelines **fast and cheap**, and run them on **your own Kubernetes** when GitHub-hosted runners aren't enough. Measure with the server's read tools before changing anything — `list_workflows`, `get_actions_cache_usage`, `list_self_hosted_runners`, `list_runner_groups`.

## 1. Pipeline optimization strategy

Optimize in this order — earliest wins are biggest.

1. **Don't run work you don't need.**
   - `paths:` / `paths-ignore:` and `branches:` filters so unrelated changes don't trigger a build.
   - `concurrency:` with `cancel-in-progress: true` to kill superseded runs on a branch/PR.
   - Path-filter or change-detection (e.g. `dorny/paths-filter`) to run only the affected jobs in a monorepo.
2. **Parallelize and fail fast.**
   - Split independent work into separate jobs (they run concurrently); use `needs:` only for real dependencies.
   - `strategy.matrix` for multi-version/OS; set `fail-fast: true` to stop the matrix on the first failure.
   - Shard long test suites across matrix legs.
3. **Cache the expensive, reproducible stuff** (section 2).
4. **Shrink the critical path.**
   - `actions/checkout` with `fetch-depth: 1` (and `sparse-checkout` for monorepos).
   - Pin `timeout-minutes:` on every job so a hung step fails fast instead of burning the 6h default.
   - Prefer prebuilt container images over installing toolchains each run.
5. **Right-size the runner.** Bigger GitHub-hosted runners (or self-hosted) cut wall-clock when a job is CPU/IO-bound; don't pay for them on trivial jobs.
6. **Harden while you're in there.** `permissions:` least-privilege at the workflow level (default read), `persist-credentials: false` on checkout, pin third-party actions to a full commit SHA. (`get_actions_permissions` / `set_actions_permissions` enforce the org policy.)

**Supply-chain note:** restricting `allowed_actions` to `selected`/`local_only` (see the admin skill) is both a security and a stability win — fewer untrusted actions to break or compromise your pipeline.

## 2. Caching strategy

Caching turns minutes into seconds, but a wrong key silently serves stale or never-hit caches.

- **Dependencies** — easiest win. Use the ecosystem cache built into the setup actions: `actions/setup-node` (`cache: npm|yarn|pnpm`), `setup-python` (`cache: pip`), `setup-java` (`cache: maven|gradle`), `setup-go`. They key on the lockfile automatically.
- **Manual `actions/cache`** when you need control:
  ```yaml
  - uses: actions/cache@v4
    with:
      path: ~/.cache/my-tool
      key: ${{ runner.os }}-mytool-${{ hashFiles('**/lockfile') }}
      restore-keys: ${{ runner.os }}-mytool-
  ```
  - **`key`** must include a hash of the inputs that invalidate the cache (lockfiles, tool versions). Same inputs ⇒ exact hit.
  - **`restore-keys`** give a partial (prefix) fallback so a near-miss still warm-starts instead of building from zero.
- **Docker layer cache** — use Buildx with GitHub Actions cache backend: `cache-from: type=gha` / `cache-to: type=gha,mode=max`, or a registry cache for cross-runner reuse.
- **Build systems** that cache natively (Gradle, Bazel, Turborepo, Nx, ccache/sccache) — cache *their* cache dir and let them do incremental work.

**Watch the limits (this is why `get_actions_cache_usage` exists):**
- **10 GB per repository.** Over it, GitHub evicts least-recently-used entries — your big cache pushes out everyone else's and nothing hits.
- Caches **unused for 7 days are evicted**; branch caches are scoped and don't cross to unrelated branches (base-branch caches are readable by its PRs).
- Keep caches **small and specific** — cache the package store, not `node_modules`; cache build outputs, not the whole workspace. Monitor with `get_actions_cache_usage { org }` (org-wide) or `{ org, repo }` and prune the repos sitting near the cap.

## 3. Self-hosted runners on Kubernetes (actions-runner-controller / ARC)

Use self-hosted when you need private-network access, custom hardware (GPU/ARM), larger or longer jobs, or cheaper sustained throughput. **actions-runner-controller (ARC)** runs ephemeral runners as Kubernetes pods and autoscales them.

### 3.1 Connecting ARC to GitHub

ARC authenticates as either a **GitHub App** (recommended) or a **PAT**.

- **GitHub App (recommended — scoped, higher rate limits, no personal account):**
  1. Create an App on the org (or enterprise). Permissions: repo `Administration: read&write`, `Metadata: read`, `Actions: read`; org `Self-hosted runners: read&write`. Subscribe to the `workflow_job` webhook event.
  2. Install it on the org (or selected repos) and note the **App ID**, **Installation ID**, and a generated **private key**.
  3. Store them as a Kubernetes Secret for the controller — never in the manifest.
- **PAT (simplest):** a token with `repo` (+ `admin:org` for org-level runners). Easy to start, but it's tied to a user and hits lower rate limits — prefer the App for anything beyond a trial.

Register runners at the **org** (or enterprise) level, not per-repo, and place them in a **runner group** whose repository access you restrict (`list_runner_groups` audits this). Verify from the other side with `list_self_hosted_runners { org }`.

### 3.2 Install (GitHub's official ARC — "gha-runner-scale-set")

```bash
# 1) Controller
helm install arc \
  --namespace arc-systems --create-namespace \
  oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set-controller

# 2) Auth secret (GitHub App) — do NOT commit the private key
kubectl create namespace arc-runners
kubectl create secret generic arc-gh-app -n arc-runners \
  --from-literal=github_app_id=<APP_ID> \
  --from-literal=github_app_installation_id=<INSTALLATION_ID> \
  --from-file=github_app_private_key=<path/to/private-key.pem>

# 3) A runner scale set bound to your org
helm install my-runners \
  --namespace arc-runners \
  --set githubConfigUrl="https://github.com/<your-org>" \
  --set githubConfigSecret=arc-gh-app \
  --set minRunners=0 --set maxRunners=20 \
  oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set
```

Use the scale set's name as the label in the workflow: `runs-on: my-runners`. GHES: add `--set githubConfigUrl="https://HOST/<org>"`.

### 3.3 Autoscaling, caching & isolation on K8s

- **Scale to zero.** `minRunners: 0` so idle costs nothing; ARC spins a pod per queued `workflow_job` up to `maxRunners`. Size `maxRunners` to your cluster's headroom and GitHub concurrency limits.
- **Ephemeral by default.** Each job gets a fresh pod — no state leaks between jobs. Keep it that way; don't mount shared writable volumes across runners.
- **Caching across ephemeral pods.** The GitHub Actions cache still works from self-hosted runners. For Docker builds, point Buildx at a **registry cache** (or a persistent cache volume) so layers survive pod churn. Consider a pull-through registry mirror and an in-cluster artifact/dependency proxy to cut egress.
- **`dind` vs rootless.** If jobs build images, either run a Docker-in-Docker sidecar or use Buildx/Kaniko/BuildKit. Prefer rootless builders; if you must use `dind`, isolate those runners in their own group and namespace.
- **Resource governance.** Set pod `resources.requests/limits`, a namespace `ResourceQuota`, `PriorityClass`, and node selectors/taints so CI can't starve other workloads. Put runners that touch secrets or production networks in a **dedicated runner group + namespace + NetworkPolicy**.
- **Right-size to the job.** Separate scale sets for light vs heavy (GPU/large) jobs; target each with its own `runs-on` label.

### 3.4 Verify & audit from the server

- `list_self_hosted_runners { org }` — are the expected runners **online/idle**, with the right labels?
- `list_runner_groups { org }` — which **repositories** can use each group? Tighten public-repo access.
- `get_actions_permissions { org }` — is Actions scoped to **selected** repos, and are **allowed actions** restricted?
- `get_actions_cache_usage { org }` — which repos are near the cache cap and need pruning?

**Golden rule:** public repositories must **not** use self-hosted runners in a shared group — a fork PR can run attacker-controlled code on your cluster. Keep public-repo CI on GitHub-hosted runners, or in a strongly isolated, disposable group with no access to internal networks or secrets.
