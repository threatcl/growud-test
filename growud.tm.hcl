spec_version = "0.2.4"

backend "threatcl-cloud" {
  organization = "weyland"
  threatmodel = "growud"
}

threatmodel "Growud" {
  description = "Growud is a local-first Go application that monitors Growatt hybrid solar inverters via the Growatt OpenAPI. It ships as a CLI, an embedded web dashboard, and a macOS menu-bar (tray) app. It stores an API token (env var or macOS Keychain), persists historical inverter readings to SQLite, archives raw JSON to disk, caches API responses on the local filesystem, and optionally calculates grid import cost / export credit from a user-supplied tariff.json."
  author      = "@xntrik"

  attributes {
    new_initiative  = "false"
    internet_facing = "false"
    initiative_size = "Small"
  }

  information_asset "growatt-api-token" {
    description                = "Growatt OpenAPI bearer token. Grants read access to the user's Growatt cloud account (plants, devices, historical energy readings). Sourced from the GROWATT_TOKEN env var (including a working-directory .env file) or from the macOS Keychain. Sent in the 'token' HTTP header on every Growatt API call."
    information_classification = "Restricted"
  }

  information_asset "energy-readings-db" {
    description                = "SQLite database (growud.db) containing time-series solar generation, battery SOC, load, and grid import/export readings for the user's inverters. Reveals household occupancy patterns and energy consumption habits."
    information_classification = "Confidential"
  }

  information_asset "raw-readings-archive" {
    description                = "Per-day raw JSON archive of Growatt API history responses, written to .cache/readings (CLI) or ~/Library/Caches/Growud/readings (bundle). Same sensitivity as the SQLite store."
    information_classification = "Confidential"
  }

  information_asset "api-response-cache" {
    description                = "File-based cache of recent Growatt API responses (5 minute TTL by default). Files keyed by sha256 of the request, stored in .cache (CLI) or ~/Library/Caches/Growud (bundle) with 0600/0700 permissions."
    information_classification = "Confidential"
  }

  information_asset "tariff-config" {
    description                = "User-authored tariff.json describing time-of-use electricity prices and feed-in tariffs. Not secret in itself, but its integrity drives any cost/credit numbers shown to the user."
    information_classification = "Public"
  }

  usecase {
    description = "User runs `growud` from a terminal to view a real-time summary of their solar plant and devices."
  }

  usecase {
    description = "User runs `growud serve` to expose a local web dashboard (default bind 127.0.0.1:8080) showing live metrics and historical charts."
  }

  usecase {
    description = "User runs `growud tray` (or launches the .app bundle) to get a macOS menu-bar status indicator with an embedded web server and periodic background data collection."
  }

  usecase {
    description = "User runs `growud collect` to backfill historical readings into the local SQLite database."
  }

  usecase {
    description = "User runs `growud cost` (or hits /api/cost) to compute grid import cost / export credit for a date range using their tariff.json."
  }

  exclusion {
    description = "Compromise of the upstream Growatt cloud account, ShinePhone credentials, or Growatt's own API infrastructure is out of scope."
  }

  exclusion {
    description = "Physical or full-OS compromise of the user's machine is out of scope (an attacker with arbitrary code execution as the user can already read the keychain, the database, and the .env file)."
  }

  exclusion {
    description = "Supply-chain compromise of Go module dependencies (charmbracelet/bubbletea, caseymrm/menuet, modernc/sqlite, 99designs/keyring, etc.) is out of scope for this model."
  }

  third_party_dependency "Growatt OpenAPI" {
    description       = "Upstream SaaS providing inverter and plant data. All meaningful functionality depends on it."
    saas              = "true"
    paying_customer   = "false"
    open_source       = "false"
    infrastructure    = "false"
    uptime_dependency = "hard"
    uptime_notes      = "If the Growatt API is unavailable, live refresh fails and historical collection stalls. Cached values continue to serve for the cache TTL (5 min default)."
  }

  third_party_dependency "macOS Keychain" {
    description       = "Used via 99designs/keyring to persist the Growatt API token for the tray/.app workflow."
    saas              = "false"
    paying_customer   = "false"
    open_source       = "false"
    infrastructure    = "true"
    uptime_dependency = "degraded"
    uptime_notes      = "If Keychain access fails, the user can still run with GROWATT_TOKEN set in the environment or .env."
  }

  threat "Growatt API token disclosed via .env file" {
    description            = "The CLI workflow loads the token from a .env file in the working directory via godotenv. The file is plaintext, has no enforced permissions, and is easy to accidentally commit, back up, or share. .gitignore mitigates the commit case but not the others."
    impacts                = ["Confidentiality"]
    stride                 = ["Info Disclosure"]
    information_asset_refs = ["growatt-api-token"]

    control "Token preferred to be stored in macOS Keychain for tray/.app users" {
      description    = "The tray app prompts for the token and writes it to the OS keychain via 99designs/keyring; CLI users are encouraged to use the keychain path or at least keep .env out of version control (already in .gitignore)."
      implemented    = true
      risk_reduction = 40
    }

    control "Document the risk and recommend restrictive file permissions on .env" {
      description    = "Add README guidance to chmod 600 the .env file when used, and call out that the env-var path leaks the token to any child process started from the same shell."
      implemented    = false
      risk_reduction = 20
    }
  }

  threat "Growatt API token exposed via process environment" {
    description            = "When GROWATT_TOKEN is exported, every child process spawned from the same shell (including ad-hoc scripts, editors, MCP tools, language servers) inherits it. `ps e` and /proc/<pid>/environ also expose it to other processes running as the same user."
    impacts                = ["Confidentiality"]
    stride                 = ["Info Disclosure"]
    information_asset_refs = ["growatt-api-token"]

    control "Keychain-backed retrieval avoids process-env leakage" {
      description    = "When the keychain code path is used (tray/.app), the token never has to be present in the process environment of unrelated programs."
      implemented    = true
      risk_reduction = 50
    }
  }

  threat "Web dashboard bound to all interfaces exposes data and triggers Growatt API calls without authentication" {
    description            = "GROWUD_BIND / -bind allows binding the dashboard to 0.0.0.0. The dashboard has no authentication, no CSRF protection, and no rate limiting. Anyone reachable on the network can read live energy data via /api/summary, query historical readings via /api/readings, retrieve computed grid import cost / export credit via /api/cost (which also reveals the tariff configuration), and force the local process to make Growatt API calls (consuming the user's Growatt API quota). /api/cost itself does not call upstream Growatt — it queries the local SQLite store — but it widens the unauthenticated read surface."
    impacts                = ["Confidentiality", "Integrity", "Availability"]
    stride                 = ["Info Disclosure", "Spoofing", "Denial of Service"]
    information_asset_refs = ["energy-readings-db", "growatt-api-token", "tariff-config"]

    control "Default bind is 127.0.0.1" {
      description    = "Both the serve subcommand and the tray app default to 127.0.0.1, so listening on the network is opt-in via -bind / GROWUD_BIND."
      implemented    = true
      risk_reduction = 60
    }

    control "Add an authentication layer (or refuse to bind non-loopback without it)" {
      description    = "Require a token / basic auth credential when -bind is non-loopback, or print a loud warning and demand an explicit flag like -insecure-bind. Add per-IP rate limiting on /api/* to bound upstream Growatt calls."
      implemented    = false
      risk_reduction = 40
    }
  }

  threat "Local API cache files tampered with by another local user" {
    description            = "Cache dir is created with mode 0700 and files with 0600, which protects against other unprivileged local users on a multi-user system. However, on macOS the user's own ~/Library/Caches is generally writable only by the user, so the practical residual risk is from another process running as the same user (covered by the host-compromise exclusion)."
    impacts                = ["Integrity"]
    stride                 = ["Tampering"]
    information_asset_refs = ["api-response-cache"]

    control "Restrictive permissions on cache dir and entries" {
      description    = "newCache() calls os.MkdirAll(dir, 0700) and os.WriteFile(path, raw, 0600). Cache TTL is bounded (5 min default) so any tampering self-heals on the next miss."
      implemented    = true
      risk_reduction = 70
    }
  }

  threat "Insecure GROWATT_BASE_URL leaks token over the wire" {
    description            = "GROWATT_BASE_URL is taken verbatim from the environment. If a user (or a tampered .env file) sets it to an http:// URL or a hostile host, the token is sent in a plaintext header to whoever controls that endpoint."
    impacts                = ["Confidentiality", "Integrity"]
    stride                 = ["Info Disclosure", "Spoofing"]
    information_asset_refs = ["growatt-api-token"]

    control "Default base URL is HTTPS" {
      description    = "defaultBaseURL is https://openapi-au.growatt.com/v1/, so the insecure case only happens if the user (or a process running as them) explicitly overrides it."
      implemented    = true
      risk_reduction = 50
    }

    control "Reject non-HTTPS GROWATT_BASE_URL unless an explicit opt-in flag is set" {
      description    = "Validate the scheme of GROWATT_BASE_URL at startup and refuse http:// (or require an explicit -insecure-base-url style flag for testing)."
      implemented    = false
      risk_reduction = 30
    }
  }

  threat "Malicious or malformed Growatt API response crashes or misleads the client" {
    description            = "The client trusts the upstream JSON envelope, and parts of the dashboard render values that ultimately come from upstream. A compromised or hostile upstream (DNS hijack, MITM with a forged cert, malicious mock) could try to OOM the client, inject misleading numbers, or smuggle data into the SQLite store."
    impacts                = ["Availability", "Integrity"]
    stride                 = ["Tampering", "Denial of Service"]
    information_asset_refs = ["energy-readings-db", "raw-readings-archive"]

    control "Response body is bounded to 10 MB" {
      description    = "client.go uses io.LimitReader with a 10 MB cap before json.Unmarshal, preventing trivial OOM from a runaway upstream payload."
      implemented    = true
      risk_reduction = 50
    }

    control "HTML escaping in dashboard rendering" {
      description    = "The dashboard template is parsed with html/template, which contextually escapes interpolated values, blocking the obvious XSS path if upstream returned a hostile string."
      implemented    = true
      risk_reduction = 30
    }
  }

  threat "Tariff config tampering yields incorrect cost/credit figures" {
    description            = "tariff.json is plain JSON read from disk with no integrity checks. An attacker (or a buggy edit) that alters cents_per_kwh or time windows produces silently wrong cost figures, which the user may rely on for billing decisions."
    impacts                = ["Integrity"]
    stride                 = ["Tampering"]
    information_asset_refs = ["tariff-config"]

    control "Tariff file lives in user-owned config dir" {
      description    = "In bundle mode the file lives under ~/Library/Application Support/Growud/, which is user-writable only; in CLI mode it's wherever the user puts it."
      implemented    = true
      risk_reduction = 30
    }
  }

  threat "Token disclosed in logs" {
    description            = "Bundle mode tees stdout/stderr to ~/Library/Logs/Growud/growud.log. The token itself is never logged today, but log lines such as 'Token present: %v' could regress to logging the raw token via a careless future edit. Logs are otherwise readable by the user only."
    impacts                = ["Confidentiality"]
    stride                 = ["Info Disclosure"]
    information_asset_refs = ["growatt-api-token"]

    control "Current logs only emit a boolean for token presence" {
      description    = "main.go logs `Token present: %v` (a bool), not the token value. Other log statements log paths and command names but not secrets."
      implemented    = true
      risk_reduction = 70
    }
  }

  threat "Untrusted query parameters drive database / cost queries" {
    description            = "/api/readings and /api/cost accept date and device query parameters from any caller able to reach the dashboard. Without input validation these would feed straight into SQL queries and tariff calculations."
    impacts                = ["Integrity", "Availability"]
    stride                 = ["Tampering", "Denial of Service"]
    information_asset_refs = ["energy-readings-db"]

    control "Strict regex validation on date and device-SN inputs" {
      description    = "server.go validates date with ^\\d{4}-\\d{2}-\\d{2}$ and device with ^[A-Za-z0-9_-]{1,64}$, then time.Parse-checks the date. Applied uniformly to /api/readings and /api/cost (from/to/device). Store queries use parameterised SQL via database/sql, including QueryRangeReadings used by the cost calculator."
      implemented    = true
      risk_reduction = 80
    }
  }

  threat "Growatt API outage stalls the application" {
    description            = "All meaningful functionality (live summary, collect, tray refresh) requires Growatt's cloud API. Sustained outage or rate-limiting renders the app effectively useless until upstream returns."
    impacts                = ["Availability"]
    stride                 = ["Denial of Service"]
    information_asset_refs = ["energy-readings-db"]

    control "Local store remains queryable for historical data" {
      description    = "Even when the upstream API is down, /api/readings and `growud cost` continue to work against the SQLite store using already-collected data."
      implemented    = true
      risk_reduction = 30
    }

    control "Per-request HTTP timeout" {
      description    = "growatt.Client uses a 30s http.Client timeout, so a hanging upstream cannot hang the process indefinitely."
      implemented    = true
      risk_reduction = 20
    }
  }

  data_flow_diagram_v2 "Growud" {

    trust_zone "User Workstation" {
      external_element "User" {}

      process "growud CLI" {}

      process "Tray / .app" {}

      process "Web Dashboard (HTTP)" {}

      data_store "SQLite DB (growud.db)" {
        information_asset = "energy-readings-db"
      }

      data_store "Raw Readings Archive" {
        information_asset = "raw-readings-archive"
      }

      data_store "API Response Cache" {
        information_asset = "api-response-cache"
      }

      data_store ".env / config.env" {
        information_asset = "growatt-api-token"
      }

      data_store "tariff.json" {
        information_asset = "tariff-config"
      }
    }

    trust_zone "macOS Keychain" {
      data_store "macOS Keychain" {
        information_asset = "growatt-api-token"
      }
    }

    trust_zone "Growatt Cloud" {
      external_element "Growatt OpenAPI" {}
    }

    flow "launch" {
      from = "User"
      to   = "growud CLI"
    }

    flow "launch" {
      from = "User"
      to   = "Tray / .app"
    }

    flow "browser HTTP" {
      from = "User"
      to   = "Web Dashboard (HTTP)"
    }

    flow "load token" {
      from = ".env / config.env"
      to   = "growud CLI"
    }

    flow "load token" {
      from = "macOS Keychain"
      to   = "Tray / .app"
    }

    flow "save token" {
      from = "Tray / .app"
      to   = "macOS Keychain"
    }

    flow "embeds" {
      from = "Tray / .app"
      to   = "Web Dashboard (HTTP)"
    }

    flow "read tariff" {
      from = "tariff.json"
      to   = "Web Dashboard (HTTP)"
    }

    flow "read tariff" {
      from = "tariff.json"
      to   = "growud CLI"
    }

    flow "read tariff" {
      from = "tariff.json"
      to   = "Tray / .app"
    }

    flow "HTTPS + token header" {
      from = "growud CLI"
      to   = "Growatt OpenAPI"
    }

    flow "HTTPS + token header" {
      from = "Tray / .app"
      to   = "Growatt OpenAPI"
    }

    flow "JSON response" {
      from = "Growatt OpenAPI"
      to   = "growud CLI"
    }

    flow "JSON response" {
      from = "Growatt OpenAPI"
      to   = "Tray / .app"
    }

    flow "cache write/read" {
      from = "growud CLI"
      to   = "API Response Cache"
    }

    flow "cache write/read" {
      from = "Tray / .app"
      to   = "API Response Cache"
    }

    flow "upsert readings" {
      from = "growud CLI"
      to   = "SQLite DB (growud.db)"
    }

    flow "upsert readings" {
      from = "Tray / .app"
      to   = "SQLite DB (growud.db)"
    }

    flow "archive raw JSON" {
      from = "Tray / .app"
      to   = "Raw Readings Archive"
    }

    flow "query readings" {
      from = "Web Dashboard (HTTP)"
      to   = "SQLite DB (growud.db)"
    }
  }
}
