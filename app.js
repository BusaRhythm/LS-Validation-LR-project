(function () {
  "use strict";

  const PAGE_SIZE = 1000;
  const DETAIL_CONCURRENCY = 5;
  const PORT = 8501;
  const PROXY_ENDPOINT = "/proxy";
  const MAX_IDENTIFIERS = 8;
  const SEARCH_DEBOUNCE_MS = 250;
  const DEFAULT_INVENTORY_PAGE_SIZE = 100;
  const INVENTORY_PAGE_SIZES = [50, 100, 250, 500, 1000, "all"];
  const COLLECTION_METHODS = ["Push Syslog", "Pull API", "Pull the MS Event Log", "Pull Flat File", "Pull UDLA", "Open Collector", "Unknown"];
  const API_LOG_SOURCE_TYPES = [
    "API - AWS CloudTrail", "API - AWS CloudWatch Alarm", "API - AWS Config Event",
    "API - AWS S3 CloudTrail (via Flat File)", "API - AWS S3 Server Access Event", "API - Tenable.io Scanner"
  ];
  const SYSLOG_LOG_SOURCE_TYPES = ["Syslog - Palo Alto Firewall", "Syslog - Cisco ISE", "Syslog - Fortinet FortiGate"];
  const FLAT_FILE_LOG_SOURCE_TYPES = [
    "Flat File - Microsoft IIS W3C File", "Flat File - Microsoft Exchange Message Tracking Log", "Flat File - Mimecast Email"
  ];
  const MS_EVENT_LOG_SOURCE_TYPES = ["Microsoft Windows Event Log", "Windows Event Log"];
  const UDLA_LOG_SOURCE_TYPES = ["UDLA - Symmetry Access Control", "UDLA - VMware vCenter Server - Events"];
  const OPEN_COLLECTOR_LOG_SOURCE_TYPES = ["Open Collector", "Open Collector Beat", "OC Beat"];
  const COLLECTION_TYPE_PREFIX_RULES = [
    { method: "Pull the MS Event Log", prefixes: ["MS Windows Event Logging XML -", "MS Windows Event Logging -", "MS Windows Event Logging", "Microsoft Windows Event Log", "Windows Event Log"], mappings: MS_EVENT_LOG_SOURCE_TYPES },
    { method: "Pull UDLA", prefixes: ["System: UDLA -", "UDLA -"], mappings: UDLA_LOG_SOURCE_TYPES },
    { method: "Pull API", prefixes: ["System: API -", "API -"], mappings: API_LOG_SOURCE_TYPES },
    { method: "Pull Flat File", prefixes: ["System: Flat File -", "Flat File -"], mappings: FLAT_FILE_LOG_SOURCE_TYPES },
    { method: "Push Syslog", prefixes: ["System: Syslog -", "Syslog -"], mappings: SYSLOG_LOG_SOURCE_TYPES }
  ];
  const LAST_LOG_DATE_FIELDS = new Set([
    "lastlogdate", "lastlogtime", "lasteventdate", "lasteventtime", "lastmessagedate",
    "lastlogmessagedate", "lastlogreceived", "lastreceiveddate", "lastdatareceived", "mostrecentlogdate"
  ]);
  const EXCLUDED_LOG_SOURCE_TYPES = [
    "LogRhythm AI Engine",
    "LogRhythm Diagnostic Messages",
    "Flat File - LogRhythm System Monitor Log File",
    "LogRhythm Data Loss Defender",
    "LogRhythm File Monitor",
    "LogRhythm Network Connection Monitor",
    "LogRhythm Process Monitor",
    "LogRhythm Registry Integrity Monitor",
    "LogRhythm User Activity Monitor"
  ];

  const elements = typeof document === "undefined" ? null : {
    form: document.getElementById("connectionForm"),
    host: document.getElementById("hostInput"),
    token: document.getElementById("tokenInput"),
    connect: document.getElementById("connectButton"),
    cancel: document.getElementById("cancelButton"),
    connectionBadge: document.getElementById("connectionBadge"),
    connectionText: document.getElementById("connectionText"),
    progressRegion: document.getElementById("progressRegion"),
    progressMessage: document.getElementById("progressMessage"),
    progressCount: document.getElementById("progressCount"),
    progressTrack: document.querySelector(".progress-track"),
    progressBar: document.getElementById("progressBar"),
    messageBox: document.getElementById("messageBox"),
    totalBadge: document.getElementById("totalBadge"),
    excludedBadge: document.getElementById("excludedBadge"),
    discoveredBadge: document.getElementById("discoveredBadge"),
    failedBadge: document.getElementById("failedBadge"),
    unknownBadge: document.getElementById("unknownBadge"),
    allCount: document.getElementById("allCount"),
    activeCount: document.getElementById("activeCount"),
    retiredCount: document.getElementById("retiredCount"),
    search: document.getElementById("searchInput"),
    advancedToggle: document.getElementById("advancedFiltersToggle"),
    advancedPanel: document.getElementById("advancedFiltersPanel"),
    clearFilters: document.getElementById("clearFiltersButton"),
    filterName: document.getElementById("filterName"),
    filterId: document.getElementById("filterId"),
    filterEntity: document.getElementById("filterEntity"),
    filterType: document.getElementById("filterType"),
    filterHost: document.getElementById("filterHost"),
    filterSystemMonitor: document.getElementById("filterSystemMonitor"),
    filterCollectionMethod: document.getElementById("filterCollectionMethod"),
    filterIdentifierType: document.getElementById("filterIdentifierType"),
    filterIdentifierValue: document.getElementById("filterIdentifierValue"),
    filterStatus: document.getElementById("filterStatus"),
    filterHasError: document.getElementById("filterHasError"),
    detailImportSummary: document.getElementById("detailImportSummary"),
    detailSuccessCount: document.getElementById("detailSuccessCount"),
    detailFailureCount: document.getElementById("detailFailureCount"),
    failureGroups: document.getElementById("failureGroups"),
    retryFailed: document.getElementById("retryFailedButton"),
    activeFilterCount: document.getElementById("activeFilterCount"),
    inventoryExport: document.getElementById("inventoryExportButton"),
    emptyState: document.getElementById("emptyState"),
    tableRegion: document.getElementById("tableRegion"),
    tableBody: document.getElementById("logSourceBody"),
    resultSummary: document.getElementById("resultSummary"),
    operationalPagination: document.getElementById("operationalPagination"),
    operationalPageSize: document.getElementById("operationalPageSize"),
    operationalRange: document.getElementById("operationalRange"),
    operationalFirst: document.getElementById("operationalFirst"),
    operationalPrevious: document.getElementById("operationalPrevious"),
    operationalPageIndicator: document.getElementById("operationalPageIndicator"),
    operationalNext: document.getElementById("operationalNext"),
    operationalLast: document.getElementById("operationalLast"),
    excludedSectionCount: document.getElementById("excludedSectionCount"),
    excludedToggle: document.getElementById("excludedToggle"),
    excludedContent: document.getElementById("excludedContent"),
    excludedExport: document.getElementById("excludedExportButton"),
    excludedEmptyState: document.getElementById("excludedEmptyState"),
    excludedTableRegion: document.getElementById("excludedTableRegion"),
    excludedTableBody: document.getElementById("excludedLogSourceBody"),
    excludedResultSummary: document.getElementById("excludedResultSummary"),
    excludedPagination: document.getElementById("excludedPagination"),
    excludedPageSize: document.getElementById("excludedPageSize"),
    excludedRange: document.getElementById("excludedRange"),
    excludedFirst: document.getElementById("excludedFirst"),
    excludedPrevious: document.getElementById("excludedPrevious"),
    excludedPageIndicator: document.getElementById("excludedPageIndicator"),
    excludedNext: document.getElementById("excludedNext"),
    excludedLast: document.getElementById("excludedLast"),
    comparisonView: document.getElementById("comparisonView"),
    comparisonNotice: document.getElementById("comparisonInventoryNotice"),
    comparisonWorkspace: document.getElementById("comparisonWorkspace"),
    includeExcludedComparison: document.getElementById("includeExcludedComparison"),
    comparisonFile: document.getElementById("comparisonFileInput"),
    fileValidationMessage: document.getElementById("fileValidationMessage"),
    fileSummary: document.getElementById("fileSummary"),
    submittedRowCount: document.getElementById("submittedRowCount"),
    validRowCount: document.getElementById("validRowCount"),
    invalidRowCount: document.getElementById("invalidRowCount"),
    invalidRowsPanel: document.getElementById("invalidRowsPanel"),
    invalidRowsBody: document.getElementById("invalidRowsBody"),
    comparisonSearch: document.getElementById("comparisonSearch"),
    comparisonMatchFilter: document.getElementById("comparisonMatchFilter"),
    clearComparison: document.getElementById("clearComparisonButton"),
    comparisonCsv: document.getElementById("comparisonCsvButton"),
    comparisonXlsx: document.getElementById("comparisonXlsxButton"),
    comparisonSummary: document.getElementById("comparisonSummary"),
    comparisonSubmittedCount: document.getElementById("comparisonSubmittedCount"),
    comparisonValidCount: document.getElementById("comparisonValidCount"),
    comparisonMatchedCount: document.getElementById("comparisonMatchedCount"),
    comparisonUnmatchedCount: document.getElementById("comparisonUnmatchedCount"),
    comparisonInvalidCount: document.getElementById("comparisonInvalidCount"),
    comparisonMatchRecordCount: document.getElementById("comparisonMatchRecordCount"),
    comparisonEmptyState: document.getElementById("comparisonEmptyState"),
    comparisonTableRegion: document.getElementById("comparisonTableRegion"),
    comparisonBody: document.getElementById("comparisonBody"),
    comparisonVisibleSummary: document.getElementById("comparisonVisibleSummary"),
    drawer: document.getElementById("detailsDrawer"),
    drawerBackdrop: document.getElementById("drawerBackdrop"),
    drawerTitle: document.getElementById("drawerTitle"),
    drawerSubtitle: document.getElementById("drawerSubtitle"),
    drawerContent: document.getElementById("drawerContent"),
    closeDrawer: document.getElementById("closeDrawerButton")
  };

  const state = {
    sources: [],
    filter: "all",
    search: "",
    sortKey: "name",
    sortDirection: "asc",
    controller: null,
    isLoading: false,
    lastHost: "",
    searchTimer: null,
    advanced: createEmptyAdvancedFilters(),
    visibleOperational: [],
    visibleExcluded: [],
    operationalPage: 1,
    operationalPageSize: DEFAULT_INVENTORY_PAGE_SIZE,
    excludedPage: 1,
    excludedPageSize: DEFAULT_INVENTORY_PAGE_SIZE,
    comparisonInput: null,
    comparisonRows: [],
    comparisonVisible: [],
    comparisonSearch: "",
    comparisonMatchFilter: "all",
    comparisonSortKey: "inputOrder",
    comparisonSortDirection: "asc"
  };

  let bearerToken = "";
  const summaryCache = new WeakMap();
  const searchTextCache = new WeakMap();

  function createEmptyAdvancedFilters() {
    return {
      name: "",
      id: "",
      entity: "",
      type: "",
      host: "",
      systemMonitor: "",
      collectionMethod: "all",
      identifierType: "",
      identifierValue: "",
      status: "all",
      hasError: "all"
    };
  }

  function validateHost(value) {
    const host = value.trim();
    if (!host) throw new AppError("invalid-host", "Enter a Platform Manager FQDN or IP address.");
    if (/^[a-z][a-z\d+.-]*:\/\//i.test(host) || /[/?#@\s]/.test(host)) {
      throw new AppError("invalid-host", "Enter only the FQDN or IP address—without https://, a port, path, spaces, or credentials.");
    }

    if (host.includes(":")) throw new AppError("invalid-host", "Do not include a port. The Platform Manager port is fixed to 8501.");
    if (host.toLowerCase() === "localhost") return "localhost";

    const ipv4Candidate = /^\d+(?:\.\d+){3}$/.test(host);
    if (ipv4Candidate) {
      if (!host.split(".").every((part) => Number(part) >= 0 && Number(part) <= 255)) {
        throw new AppError("invalid-host", "The IPv4 address contains a number outside the valid 0–255 range.");
      }
      return host;
    }

    if (host.length > 253 || !host.includes(".") || !host.split(".").every((label) =>
      label.length > 0 && label.length <= 63 && /^[a-z\d](?:[a-z\d-]*[a-z\d])?$/i.test(label))) {
      throw new AppError("invalid-host", "Enter a valid FQDN (for example, pm.example.com), IPv4 address, or localhost.");
    }
    return host.toLowerCase();
  }

  class AppError extends Error {
    constructor(code, message, status, details) {
      super(message);
      this.name = "AppError";
      this.code = code;
      this.status = status;
      this.details = details && typeof details === "object" ? details : { code, message, status };
    }
  }

  function requestHeaders() {
    return { "Content-Type": "application/json", Accept: "application/json" };
  }

  async function fetchJson(path, signal, context, host) {
    let response;
    try {
      response = await fetch(PROXY_ENDPOINT, {
        method: "POST",
        headers: requestHeaders(),
        body: JSON.stringify({ host, token: bearerToken, path }),
        signal,
        cache: "no-store"
      });
    } catch (error) {
      if (error && error.name === "AbortError") throw error;
      throw new AppError("local-server", "The local PowerShell server is unavailable. Close this tab, start the application with Start.cmd, and try again.");
    }

    let payload;
    try {
      payload = await response.json();
    } catch (error) {
      throw new AppError("invalid-json", "The local proxy returned an invalid JSON response.", response.status);
    }

    if (!response.ok) {
      const proxyError = payload && payload.error && typeof payload.error === "object" ? payload.error : {};
      const code = typeof proxyError.code === "string" ? proxyError.code : "proxy-error";
      const fallback = response.status === 404 && context === "detail"
        ? "This log source was not found (HTTP 404). It may have been removed after discovery."
        : `The local proxy returned HTTP ${response.status}.`;
      throw new AppError(code, typeof proxyError.message === "string" ? proxyError.message : fallback, response.status, proxyError);
    }
    return payload;
  }

  function extractRecords(payload) {
    if (Array.isArray(payload)) return payload;
    if (!payload || typeof payload !== "object") {
      throw new AppError("invalid-json", "The list response was valid JSON, but it did not contain a log source collection.");
    }
    const directKeys = ["items", "records", "results", "logSources", "logsources", "data"];
    for (const key of directKeys) {
      if (Array.isArray(payload[key])) return payload[key];
    }
    if (payload.data && typeof payload.data === "object") {
      for (const key of directKeys) {
        if (Array.isArray(payload.data[key])) return payload.data[key];
      }
    }
    throw new AppError("invalid-json", "The list response was valid JSON, but no recognized log source array was found.");
  }

  function firstValue(object, paths) {
    for (const path of paths) {
      let value = object;
      for (const part of path.split(".")) {
        if (value == null || typeof value !== "object" || !(part in value)) {
          value = undefined;
          break;
        }
        value = value[part];
      }
      if (value !== undefined && value !== null && value !== "") return value;
    }
    return "";
  }

  function displayValue(value) {
    if (value === undefined || value === null || value === "") return "—";
    if (typeof value === "object") {
      return firstValue(value, ["name", "displayName", "description", "id"]) || "—";
    }
    return String(value);
  }

  function normalizedKey(value) {
    return String(value).toLowerCase().replace(/[^a-z0-9]/g, "");
  }

  function readableIdentifierPart(value) {
    if (value === undefined || value === null) return "";
    if (typeof value !== "object") return String(value).trim();
    const preferredKeys = ["name", "value", "displayName", "description", "id"];
    for (const preferred of preferredKeys) {
      const match = Object.entries(value).find(([key]) => normalizedKey(key) === normalizedKey(preferred));
      if (match) {
        const readable = readableIdentifierPart(match[1]);
        if (readable) return readable;
      }
    }
    return "";
  }

  function readIdentifierProperty(object, acceptedNames) {
    if (!object || typeof object !== "object" || Array.isArray(object)) return "";
    const accepted = new Set(acceptedNames.map(normalizedKey));
    for (const [key, value] of Object.entries(object)) {
      if (accepted.has(normalizedKey(key))) return readableIdentifierPart(value);
    }
    return "";
  }

  function extractAllIdentifiers(detail, listRecord) {
    const collected = [];
    const seenObjects = new WeakSet();

    function addPair(object) {
      const type = readIdentifierProperty(object, ["type", "identifierType", "logSourceIdentifierType"]);
      const value = readIdentifierProperty(object, ["value", "identifierValue", "logSourceIdentifierValue"]);
      if (type && value) collected.push({ type, value, order: collected.length });
    }

    function visit(value, identifierContext, depth) {
      if (!value || typeof value !== "object" || depth > 12 || seenObjects.has(value)) return;
      seenObjects.add(value);
      if (Array.isArray(value)) {
        value.forEach((item) => {
          if (identifierContext) addPair(item);
          visit(item, identifierContext, depth + 1);
        });
        return;
      }
      if (identifierContext) addPair(value);
      Object.entries(value).forEach(([key, nested]) => {
        const nestedContext = identifierContext || normalizedKey(key).includes("identifier");
        visit(nested, nestedContext, depth + 1);
      });
    }

    visit(detail, false, 0);
    visit(listRecord, false, 0);

    const uniqueIdentifiers = [];
    const seenPairs = new Set();
    collected.forEach((identifier) => {
      const key = `${normalizedKey(identifier.type)}\u0000${identifier.value.toLowerCase()}`;
      if (!seenPairs.has(key)) {
        seenPairs.add(key);
        uniqueIdentifiers.push(identifier);
      }
    });

    function priority(identifier) {
      const type = normalizedKey(identifier.type);
      if (type === "ipaddress" || type === "ip") return 0;
      if (type === "hostname" || type === "fqdn") return 1;
      return 2;
    }

    return uniqueIdentifiers
      .sort((left, right) => priority(left) - priority(right) || left.order - right.order)
      .map(({ type, value }) => ({ type, value }));
  }

  function extractIdentifiers(detail, listRecord) {
    return extractAllIdentifiers(detail, listRecord).slice(0, MAX_IDENTIFIERS);
  }

  function getId(record) {
    return firstValue(record, ["id", "logSourceId", "logsourceId", "lsId", "logSource.id", "logsource.id"]);
  }

  function normalizedStatus(record, fallback) {
    const statusValue = firstValue(record, ["recordStatus", "status", "record.status"]) ||
      firstValue(fallback || {}, ["recordStatus", "status", "record.status"]);
    const raw = displayValue(statusValue).toLowerCase();
    if (["active", "enabled", "accepted", "1", "true"].includes(raw)) return "active";
    if (["retired", "inactive", "disabled", "0", "false"].includes(raw)) return "retired";
    return "unknown";
  }

  function collectScalarFields(object, source, maxDepth) {
    const fields = [];
    const seen = new WeakSet();
    function visit(value, path, depth) {
      if (value === null || value === undefined || depth > maxDepth) return;
      if (typeof value !== "object") {
        fields.push({ path, key: path[path.length - 1] || "Value", value: String(value), source });
        return;
      }
      if (seen.has(value)) return;
      seen.add(value);
      if (Array.isArray(value)) value.forEach((item, index) => visit(item, path.concat(`Item ${index + 1}`), depth + 1));
      else Object.entries(value).forEach(([key, nested]) => visit(nested, path.concat(key), depth + 1));
    }
    visit(object, [], 0);
    return fields;
  }

  function resolvedLogSourceTypeName(detail, listRecord) {
    const paths = ["logSourceType.name", "logSourceTypeName", "type.name", "type"];
    const value = firstValue(detail || {}, paths) || firstValue(listRecord || {}, paths);
    return value === undefined || value === null || typeof value === "object" ? "" : String(value).trim().replace(/\s+/g, " ");
  }

  function classifyCollectionMethod(detail, listRecord) {
    const originalType = resolvedLogSourceTypeName(detail, listRecord);
    if (!originalType) return { method: "Unknown", confidence: "unknown", evidence: "No Log Source Type mapping matched" };
    const normalizedType = originalType.toLocaleLowerCase();

    for (const rule of COLLECTION_TYPE_PREFIX_RULES) {
      const exact = rule.mappings.find((name) => name.trim().replace(/\s+/g, " ").toLocaleLowerCase() === normalizedType);
      if (exact) return { method: rule.method, confidence: "confirmed", evidence: `Exact ${rule.method.replace(/^Pull (?:the )?/, "")} mapping: "${originalType}"` };
      const prefix = rule.prefixes.find((value) => normalizedType.startsWith(value.toLocaleLowerCase()));
      if (prefix) return { method: rule.method, confidence: "confirmed", evidence: `Log Source Type prefix "${prefix}"` };
      if (rule.method === "Pull UDLA" && /(?:^|[\s:-])udla(?:\s*-|$)/i.test(originalType)) {
        return { method: rule.method, confidence: "confirmed", evidence: `Explicit UDLA designation in Log Source Type: "${originalType}"` };
      }
    }

    const openCollectorExact = OPEN_COLLECTOR_LOG_SOURCE_TYPES.find((name) => name.toLocaleLowerCase() === normalizedType);
    if (openCollectorExact) return { method: "Open Collector", confidence: "confirmed", evidence: `Exact Open Collector mapping: "${originalType}"` };
    const openCollectorDesignation = originalType.match(/\b(?:open collector(?: beat)?|oc beat)\b/i);
    if (openCollectorDesignation) return { method: "Open Collector", confidence: "confirmed", evidence: `Explicit Log Source Type designation "${openCollectorDesignation[0]}"` };

    return { method: "Unknown", confidence: "unknown", evidence: "No Log Source Type mapping matched" };
  }

  function parseLastLogTimestamp(raw) {
    if (raw === null || raw === undefined || raw === "") return null;
    let timestamp;
    if (typeof raw === "number" && Number.isFinite(raw)) {
      timestamp = Math.abs(raw) < 100000000000 ? raw * 1000 : raw;
    } else {
      const text = String(raw).trim();
      const microsoft = /^\/Date\((-?\d+)(?:[+-]\d{4})?\)\/$/.exec(text);
      if (microsoft) timestamp = Number(microsoft[1]);
      else if (/^-?\d+(?:\.\d+)?$/.test(text)) {
        const numeric = Number(text);
        timestamp = Math.abs(numeric) < 100000000000 ? numeric * 1000 : numeric;
      } else timestamp = Date.parse(text);
    }
    if (!Number.isFinite(timestamp)) return null;
    const year = new Date(timestamp).getUTCFullYear();
    if (year < 1970 || year > 2200) return null;
    return timestamp;
  }

  function lastLogCandidates(object, source) {
    return collectScalarFields(object, source, 10)
      .filter((field) => LAST_LOG_DATE_FIELDS.has(normalizedKey(field.key)))
      .map((field) => ({ ...field, timestamp: parseLastLogTimestamp(field.value) }))
      .filter((field) => field.timestamp !== null);
  }

  function extractLastLogDate(detail, listRecord) {
    const detailCandidates = lastLogCandidates(detail, "Detail response");
    const listCandidates = lastLogCandidates(listRecord, "List response");
    const candidates = detailCandidates.length ? detailCandidates : listCandidates;
    if (!candidates.length) return { display: "—", raw: "", field: "", source: "", timestamp: null };
    const selected = candidates.sort((left, right) => right.timestamp - left.timestamp)[0];
    return {
      display: new Date(selected.timestamp).toLocaleString(),
      raw: selected.value,
      field: selected.path.join(" > "),
      source: selected.source,
      timestamp: selected.timestamp
    };
  }

  function lastLogTooltip(info) {
    return info && info.timestamp !== null ? `${info.source} • ${info.field}: ${info.raw}` : "No valid last-log timestamp returned";
  }

  function summaryFor(item) {
    if (summaryCache.has(item)) return summaryCache.get(item);
    const record = item.detail || item.listRecord || {};
    const fallback = item.listRecord || {};
    const pick = (paths) => firstValue(record, paths) || firstValue(fallback, paths);
    const allIdentifiers = extractAllIdentifiers(item.detail, item.listRecord);
    const identifiers = allIdentifiers.slice(0, MAX_IDENTIFIERS);
    const collection = classifyCollectionMethod(item.detail, item.listRecord);
    const lastLog = extractLastLogDate(item.detail, item.listRecord);
    const summary = {
      id: displayValue(item.id),
      name: displayValue(pick(["name", "displayName", "logSourceName", "logsourceName"])),
      status: normalizedStatus(record, fallback),
      entity: displayValue(pick(["entity.name", "entityName", "entity", "parentEntity.name"])),
      type: displayValue(pick(["logSourceType.name", "logSourceTypeName", "type.name", "type"])),
      collectionMethod: collection.method,
      collectionConfidence: collection.confidence,
      collectionEvidence: collection.evidence,
      host: displayValue(pick(["host", "hostname", "hostName", "ipAddress", "address"])),
      systemMonitor: displayValue(pick(["systemMonitor.name", "systemMonitorName", "systemMonitor", "agent.name", "agentName"])),
      lastLogDate: lastLog.display,
      lastLogDateInfo: lastLog,
      error: item.error ? item.error.message : "",
      identifiers,
      allIdentifiers
    };
    for (let index = 0; index < MAX_IDENTIFIERS; index += 1) {
      summary[`identifier${index + 1}`] = identifiers[index] ? identifiers[index].value : "—";
    }
    summaryCache.set(item, summary);
    return summary;
  }

  function exclusionReason(source) {
    const type = summaryFor(source).type;
    const matched = EXCLUDED_LOG_SOURCE_TYPES.find((excludedType) => excludedType.toLowerCase() === type.toLowerCase());
    return matched ? `Matched excluded Log Source Type: ${matched}` : "";
  }

  function partitionSources(sources) {
    const operational = [];
    const excluded = [];
    sources.forEach((source) => (exclusionReason(source) ? excluded : operational).push(source));
    return { operational, excluded };
  }

  async function discoverLogSources(host, signal) {
    const discovered = [];
    let offset = 0;
    while (true) {
      updateProgress(`Discovering log sources (offset ${offset.toLocaleString()})…`, discovered.length, null);
      const path = `/lr-admin-api/logsources/?offset=${offset}&count=${PAGE_SIZE}&recordStatus=all`;
      const page = extractRecords(await fetchJson(path, signal, "list", host));
      discovered.push(...page);
      updateProgress("Discovering log sources…", discovered.length, null);
      if (page.length < PAGE_SIZE) break;
      offset += PAGE_SIZE;
    }
    return discovered;
  }

  async function loadDetails(host, records, signal) {
    let nextIndex = 0;
    let completed = 0;
    const results = new Array(records.length);

    async function worker() {
      while (true) {
        if (signal.aborted) throw new DOMException("Cancelled", "AbortError");
        const index = nextIndex++;
        if (index >= records.length) return;
        const record = records[index];
        const id = getId(record);
        if (id === "") {
          results[index] = { id: "—", listRecord: record, detail: null, error: new AppError("missing-id", "The discovery record did not contain a recognizable log source ID.") };
        } else if (!/^\d+$/.test(String(id))) {
          results[index] = { id, listRecord: record, detail: null, error: new AppError("invalid-id", "The discovery record contained a non-numeric log source ID, so the restricted proxy did not request it.") };
        } else {
          try {
            const encodedId = encodeURIComponent(String(id));
            const detail = await fetchJson(`/lr-admin-api/logsources/${encodedId}`, signal, "detail", host);
            results[index] = { id, listRecord: record, detail, error: null };
          } catch (error) {
            if (error && error.name === "AbortError") throw error;
            results[index] = { id, listRecord: record, detail: null, error: normalizeError(error) };
          }
        }
        completed += 1;
        updateProgress("Loading full log source details…", records.length, { completed, total: records.length });
      }
    }

    const workerCount = Math.min(DETAIL_CONCURRENCY, records.length);
    await Promise.all(Array.from({ length: workerCount }, worker));
    return results;
  }

  function normalizeError(error) {
    if (error instanceof AppError) return error;
    return new AppError("unknown", error && error.message ? error.message : "An unexpected error occurred.");
  }

  async function startImport(event) {
    event.preventDefault();
    if (state.isLoading) return;
    hideMessage();

    let host;
    try {
      host = validateHost(elements.host.value);
      if (!elements.token.value) throw new AppError("unauthorized", "Enter a Bearer Token.");
    } catch (error) {
      showMessage(normalizeError(error).message);
      setConnectionStatus("error", "Connection error");
      return;
    }

    bearerToken = elements.token.value;
    state.lastHost = host;
    state.controller = new AbortController();
    state.isLoading = true;
    setLoadingUi(true);
    setConnectionStatus("loading", "Loading…");
    elements.progressRegion.hidden = false;
    elements.progressRegion.dataset.indeterminate = "true";
    updateProgress("Connecting to Platform Manager…", 0, null);

    try {
      const records = await discoverLogSources(host, state.controller.signal);
      if (records.length === 0) {
        state.sources = [];
        resetInventoryPages();
        renderResults();
        setConnectionStatus("success", "Connected");
        updateProgress("Import complete. No log sources were returned.", 0, { completed: 0, total: 0 });
        return;
      }

      state.sources = await loadDetails(host, records, state.controller.signal);
      resetInventoryPages();
      renderResults();
      const failures = state.sources.filter((source) => source.error).length;
      setConnectionStatus("success", "Connected");
      updateProgress("Import complete.", records.length, { completed: records.length, total: records.length });
      if (failures) {
        showMessage(`${failures.toLocaleString()} detail request${failures === 1 ? "" : "s"} failed. Review the grouped failure summary or open an affected row for its exact error, then retry only the failed details when ready.`, "info");
      }
    } catch (error) {
      if (error && error.name === "AbortError") {
        setConnectionStatus("idle", "Cancelled");
        showMessage("Loading was cancelled. Any partial import was discarded.", "info");
        updateProgress("Cancelled.", 0, { completed: 0, total: 0 });
      } else {
        const appError = normalizeError(error);
        setConnectionStatus("error", "Connection error");
        showMessage(appError.message);
      }
    } finally {
      bearerToken = "";
      state.controller = null;
      state.isLoading = false;
      setLoadingUi(false);
    }
  }

  function cancelImport() {
    if (state.controller) state.controller.abort();
  }

  async function retryFailedDetails() {
    if (state.isLoading) return;
    const failedEntries = state.sources
      .map((source, index) => ({ source, index }))
      .filter((entry) => entry.source.error && !exclusionReason(entry.source));
    if (failedEntries.length === 0) return;

    hideMessage();
    if (!state.lastHost) {
      showMessage("Reload the inventory before retrying failed details.");
      return;
    }
    if (!elements.token.value) {
      showMessage("Enter the Bearer Token again before retrying failed details.");
      return;
    }

    bearerToken = elements.token.value;
    state.controller = new AbortController();
    state.isLoading = true;
    setLoadingUi(true);
    setConnectionStatus("loading", "Retrying…");
    elements.progressRegion.hidden = false;
    updateProgress("Retrying failed detail requests…", failedEntries.length, { completed: 0, total: failedEntries.length });

    try {
      const retried = await loadDetails(
        state.lastHost,
        failedEntries.map((entry) => entry.source.listRecord),
        state.controller.signal
      );
      retried.forEach((result, index) => {
        state.sources[failedEntries[index].index] = result;
      });
      renderResults();
      const remainingFailures = partitionSources(state.sources).operational.filter((source) => source.error).length;
      setConnectionStatus("success", "Connected");
      updateProgress("Failed detail retry complete.", failedEntries.length, { completed: failedEntries.length, total: failedEntries.length });
      if (remainingFailures) {
        showMessage(`${remainingFailures.toLocaleString()} detail request${remainingFailures === 1 ? " still has" : "s still have"} an error. Exact retry errors are preserved in the failure summary and affected rows.`, "info");
      } else {
        showMessage("All failed detail requests were loaded successfully.", "info");
      }
    } catch (error) {
      if (error && error.name === "AbortError") {
        setConnectionStatus("idle", "Cancelled");
        showMessage("The failed-detail retry was cancelled. Existing results and errors were preserved.", "info");
      } else {
        const appError = normalizeError(error);
        setConnectionStatus("error", "Retry error");
        showMessage(appError.message);
      }
    } finally {
      bearerToken = "";
      state.controller = null;
      state.isLoading = false;
      setLoadingUi(false);
    }
  }

  function setLoadingUi(isLoading) {
    elements.connect.disabled = isLoading;
    elements.cancel.hidden = !isLoading;
    elements.host.disabled = isLoading;
    elements.token.disabled = isLoading;
    elements.retryFailed.disabled = isLoading;
  }

  function setConnectionStatus(status, text) {
    elements.connectionBadge.dataset.state = status;
    elements.connectionText.textContent = text;
  }

  function updateProgress(message, discovered, detailProgress) {
    if (!elements) return;
    elements.progressMessage.textContent = message;
    elements.progressCount.textContent = `${discovered.toLocaleString()} discovered`;
    const hasKnownTotal = detailProgress && detailProgress.total > 0;
    elements.progressRegion.dataset.indeterminate = String(!hasKnownTotal);
    const percent = hasKnownTotal ? Math.round((detailProgress.completed / detailProgress.total) * 100) : 0;
    elements.progressBar.style.width = hasKnownTotal ? `${percent}%` : "";
    elements.progressTrack.setAttribute("aria-valuenow", String(percent));
    if (hasKnownTotal) elements.progressCount.textContent = `${detailProgress.completed.toLocaleString()} / ${detailProgress.total.toLocaleString()} details • ${discovered.toLocaleString()} discovered`;
  }

  function showMessage(message, kind) {
    elements.messageBox.textContent = message;
    elements.messageBox.dataset.kind = kind || "error";
    elements.messageBox.hidden = false;
  }

  function hideMessage() {
    elements.messageBox.hidden = true;
    elements.messageBox.textContent = "";
  }

  function searchableText(source) {
    if (searchTextCache.has(source)) return searchTextCache.get(source);
    const parts = [];
    const seen = new WeakSet();
    function visit(value) {
      if (value === null || value === undefined) return;
      if (typeof value === "object") {
        if (seen.has(value)) return;
        seen.add(value);
        Object.entries(value).forEach(([key, nested]) => { parts.push(key); visit(nested); });
      } else {
        parts.push(String(value));
      }
    }
    visit(source.listRecord);
    visit(source.detail);
    const summary = summaryFor(source);
    [summary.id, summary.name, summary.status, summary.entity, summary.type, summary.collectionMethod,
      summary.collectionConfidence, summary.collectionEvidence, summary.host, summary.systemMonitor, summary.lastLogDate]
      .forEach((value) => parts.push(value));
    summary.allIdentifiers.forEach((identifier) => parts.push(identifier.type, identifier.value));
    if (source.error) parts.push(source.error.code, source.error.status, source.error.message);
    const text = parts.join(" ").toLowerCase();
    searchTextCache.set(source, text);
    return text;
  }

  function includesFilter(value, filter) {
    return !filter || String(value).toLowerCase().includes(filter.toLowerCase());
  }

  function sourceMatchesAdvancedFilters(source, filters) {
    const summary = summaryFor(source);
    if (!includesFilter(summary.name, filters.name)) return false;
    if (!includesFilter(summary.id, filters.id)) return false;
    if (!includesFilter(summary.entity, filters.entity)) return false;
    if (!includesFilter(summary.type, filters.type)) return false;
    if (!includesFilter(summary.host, filters.host)) return false;
    if (!includesFilter(summary.systemMonitor, filters.systemMonitor)) return false;
    if (filters.collectionMethod !== "all" && summary.collectionMethod !== filters.collectionMethod) return false;
    if (filters.status !== "all" && summary.status !== filters.status) return false;
    if (filters.hasError === "yes" && !source.error) return false;
    if (filters.hasError === "no" && source.error) return false;

    const identifierType = normalizedKey(filters.identifierType);
    const identifierValue = filters.identifierValue.toLowerCase();
    if ((identifierType || identifierValue) && !summary.allIdentifiers.some((identifier) =>
      (!identifierType || normalizedKey(identifier.type).includes(identifierType)) &&
      (!identifierValue || identifier.value.toLowerCase().includes(identifierValue)))) {
      return false;
    }
    return true;
  }

  function inventoryCounts(sources) {
    const counts = { all: sources.length, active: 0, retired: 0, unknown: 0 };
    sources.forEach((source) => { counts[summaryFor(source).status] += 1; });
    return counts;
  }

  function paginateRecords(records, requestedPage, pageSize) {
    const allRows = pageSize === "all";
    const numericPageSize = allRows ? Math.max(records.length, 1) : Number(pageSize);
    const totalPages = allRows ? 1 : Math.max(1, Math.ceil(records.length / numericPageSize));
    const page = Math.min(Math.max(Number(requestedPage) || 1, 1), totalPages);
    const startIndex = records.length === 0 ? 0 : (page - 1) * numericPageSize;
    const endIndex = allRows ? records.length : Math.min(startIndex + numericPageSize, records.length);
    return {
      rows: records.slice(startIndex, endIndex),
      page,
      totalPages,
      start: records.length === 0 ? 0 : startIndex + 1,
      end: endIndex,
      total: records.length
    };
  }

  function filteredAndSortedSources(sources) {
    const query = state.search.trim().toLowerCase();
    const filtered = sources.filter((source) => {
      const summary = summaryFor(source);
      return (state.filter === "all" || summary.status === state.filter) &&
        (!query || searchableText(source).includes(query)) &&
        sourceMatchesAdvancedFilters(source, state.advanced);
    });
    const direction = state.sortDirection === "asc" ? 1 : -1;
    return filtered.sort((a, b) => {
      const left = summaryFor(a)[state.sortKey];
      const right = summaryFor(b)[state.sortKey];
      return String(left).localeCompare(String(right), undefined, { numeric: true, sensitivity: "base" }) * direction;
    });
  }

  function groupDetailFailures(sources) {
    const groups = new Map();
    sources.filter((source) => source.error).forEach((source) => {
      const code = source.error.code || "unknown";
      const status = source.error.status === undefined || source.error.status === null ? "No HTTP status" : `HTTP ${source.error.status}`;
      const key = `${code}\u0000${status}`;
      if (!groups.has(key)) groups.set(key, { code, status, count: 0 });
      groups.get(key).count += 1;
    });
    return Array.from(groups.values()).sort((left, right) => right.count - left.count || left.code.localeCompare(right.code));
  }

  function protectSpreadsheetValue(value) {
    const text = value === null || value === undefined ? "" : String(value);
    return /^[=+\-@]/.test(text) ? `'${text}` : text;
  }

  function csvCell(value) {
    const text = protectSpreadsheetValue(value);
    return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  }

  function buildCsv(rows) {
    return `\uFEFF${rows.map((row) => row.map(csvCell).join(",")).join("\r\n")}`;
  }

  function filenameTimestamp(date) {
    const pad = (value) => String(value).padStart(2, "0");
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}_${pad(date.getHours())}${pad(date.getMinutes())}`;
  }

  function downloadBlob(content, type, filename) {
    const blob = content instanceof Blob ? content : new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    anchor.hidden = true;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function detailErrorStatus(source) {
    if (!source.error) return "None";
    return source.error.status === undefined || source.error.status === null
      ? source.error.code
      : `${source.error.code} (HTTP ${source.error.status})`;
  }

  function inventoryExportRows(sources, includeExclusionReason) {
    const headers = ["Log Source ID", "Log Source Name", "Record Status", "Entity", "Log Source Type", "Collection Method",
      "Host", "System Monitor", "Last Log Date", ...Array.from({ length: MAX_IDENTIFIERS }, (_, index) => `Identifier ${index + 1}`),
      "Detail Error Status", "Detail Error Message"];
    if (includeExclusionReason) headers.splice(6, 0, "Exclusion Reason");
    const rows = [headers];
    sources.forEach((source) => {
      const summary = summaryFor(source);
      const row = [summary.id, summary.name, summary.status, summary.entity, summary.type, summary.collectionMethod];
      if (includeExclusionReason) row.push(exclusionReason(source));
      row.push(summary.host, summary.systemMonitor, summary.lastLogDate);
      for (let index = 0; index < MAX_IDENTIFIERS; index += 1) row.push(summary.identifiers[index] ? summary.identifiers[index].value : "");
      row.push(detailErrorStatus(source), source.error ? source.error.message : "");
      rows.push(row);
    });
    return rows;
  }

  function exportInventoryCsv(sources, excluded) {
    if (!sources.length) return;
    const prefix = excluded ? "LogRhythm_Excluded_Log_Sources" : "LogRhythm_Log_Source_Inventory";
    downloadBlob(buildCsv(inventoryExportRows(sources, excluded)), "text/csv;charset=utf-8", `${prefix}_${filenameTimestamp(new Date())}.csv`);
  }

  function validateSubmittedAsset(value) {
    const original = value === null || value === undefined ? "" : String(value).trim();
    if (!original) return { valid: false, original, reason: "Empty value" };
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(original)) return { valid: false, original, reason: "URLs are not allowed" };
    if (/[\\/?#@:,;\s]/.test(original)) return { valid: false, original, reason: "Ports, paths, usernames, or multiple values are not allowed" };
    if (original.toLowerCase() === "localhost") return { valid: true, original, normalized: "localhost", kind: "fqdn" };

    if (/^\d+(?:\.\d+){3}$/.test(original)) {
      const parts = original.split(".");
      if (!parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255)) {
        return { valid: false, original, reason: "Invalid IPv4 address" };
      }
      return { valid: true, original, normalized: parts.map((part) => String(Number(part))).join("."), kind: "ipv4" };
    }
    if (/^[\d.]+$/.test(original)) return { valid: false, original, reason: "Invalid IPv4 address" };

    const withoutDot = original.endsWith(".") ? original.slice(0, -1) : original;
    const labels = withoutDot.split(".");
    if (withoutDot.length > 253 || labels.length < 2 || !labels.every((label) =>
      label.length >= 1 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label))) {
      return { valid: false, original, reason: "Invalid FQDN" };
    }
    return { valid: true, original, normalized: withoutDot.toLowerCase(), kind: "fqdn" };
  }

  function parseCsvText(text) {
    const rows = [];
    let row = [];
    let cell = "";
    let quoted = false;
    for (let index = 0; index < text.length; index += 1) {
      const character = text[index];
      if (quoted) {
        if (character === '"' && text[index + 1] === '"') { cell += '"'; index += 1; }
        else if (character === '"') quoted = false;
        else cell += character;
      } else if (character === '"') quoted = true;
      else if (character === ",") { row.push(cell); cell = ""; }
      else if (character === "\n") { row.push(cell.replace(/\r$/, "")); rows.push(row); row = []; cell = ""; }
      else cell += character;
    }
    if (quoted) throw new AppError("invalid-file", "The CSV contains an unterminated quoted value.");
    if (cell || row.length) { row.push(cell.replace(/\r$/, "")); rows.push(row); }
    return rows;
  }

  function isOptionalCsvHeader(row) {
    if (!row || row.length !== 1) return false;
    const key = normalizedKey(row[0]);
    return ["asset", "submittedasset", "ipaddress", "iporfqdn", "fqdn", "host", "hostname", "address"].includes(key);
  }

  function validateComparisonRows(rows, firstDataIndex) {
    const valid = [];
    const invalid = [];
    let total = 0;
    for (let index = firstDataIndex; index < rows.length; index += 1) {
      const row = Array.isArray(rows[index]) ? rows[index] : [rows[index]];
      if (row.every((cell) => String(cell === undefined || cell === null ? "" : cell).trim() === "")) continue;
      total += 1;
      const nonEmpty = row.filter((cell) => String(cell === undefined || cell === null ? "" : cell).trim() !== "");
      if (nonEmpty.length !== 1 || row.findIndex((cell) => String(cell === undefined || cell === null ? "" : cell).trim() !== "") !== 0) {
        invalid.push({ row: index + 1, original: row.map((cell) => String(cell || "")).join(" | "), reason: "Exactly one populated column is required" });
        continue;
      }
      const result = validateSubmittedAsset(nonEmpty[0]);
      if (!result.valid) invalid.push({ row: index + 1, original: result.original, reason: result.reason });
      else valid.push(result);
    }
    return { total, valid, invalid, validRows: valid.length };
  }

  async function parseComparisonFile(file) {
    const extension = file.name.split(".").pop().toLowerCase();
    if (extension === "txt") {
      const rows = (await file.text()).replace(/^\uFEFF/, "").split(/\r?\n/).map((line) => [line]);
      return validateComparisonRows(rows, 0);
    }
    if (extension === "csv") {
      const rows = parseCsvText((await file.text()).replace(/^\uFEFF/, ""));
      return validateComparisonRows(rows, isOptionalCsvHeader(rows[0]) ? 1 : 0);
    }
    if (extension === "xlsx") {
      if (!globalThis.XLSX) throw new AppError("xlsx-unavailable", "The locally bundled XLSX parser could not be loaded.");
      const workbook = globalThis.XLSX.read(await file.arrayBuffer(), { type: "array" });
      if (!workbook.SheetNames.length) throw new AppError("invalid-file", "The XLSX workbook does not contain a worksheet.");
      const rows = globalThis.XLSX.utils.sheet_to_json(workbook.Sheets[workbook.SheetNames[0]], { header: 1, raw: false, defval: "", blankrows: false });
      if (!rows.length || rows[0].filter((cell) => String(cell).trim()).length !== 1) {
        throw new AppError("invalid-file", "The first XLSX worksheet must have exactly one populated header cell in its first row.");
      }
      return validateComparisonRows(rows, 1);
    }
    throw new AppError("invalid-file", "Choose a TXT, CSV, or XLSX file.");
  }

  function sourceComparisonKeys(source) {
    const summary = summaryFor(source);
    const candidates = [summary.host, ...summary.allIdentifiers.map((identifier) => identifier.value)];
    const keys = new Set();
    candidates.forEach((candidate) => {
      const validation = validateSubmittedAsset(candidate);
      if (validation.valid) keys.add(validation.normalized);
    });
    return keys;
  }

  function compareSubmittedAssets(input, sources) {
    const lookup = new Map();
    sources.forEach((source) => sourceComparisonKeys(source).forEach((key) => {
      if (!lookup.has(key)) lookup.set(key, []);
      lookup.get(key).push(source);
    }));

    const rows = [];
    let matchedRows = 0;
    let unmatchedRows = 0;
    let inputOrder = 0;
    input.valid.forEach((asset) => {
      const matches = lookup.get(asset.normalized) || [];
      if (matches.length) {
        matchedRows += 1;
        matches.forEach((source) => {
          const summary = summaryFor(source);
          rows.push({ submitted: asset.original, type: summary.type, name: summary.name, matched: true, inputOrder: inputOrder++ });
        });
      } else {
        unmatchedRows += 1;
        rows.push({ submitted: asset.original, type: "", name: "", matched: false, inputOrder: inputOrder++ });
      }
    });
    return {
      rows,
      submittedRows: input.total,
      validRows: input.valid.length,
      matchedRows,
      unmatchedRows,
      invalidRows: input.invalid.length,
      matchingRecords: rows.filter((row) => row.matched).length
    };
  }

  function runComparison() {
    if (!state.comparisonInput) return;
    const partition = partitionSources(state.sources);
    const sources = elements.includeExcludedComparison.checked ? state.sources : partition.operational;
    const result = compareSubmittedAssets(state.comparisonInput, sources);
    state.comparisonRows = result.rows;
    elements.comparisonSummary.hidden = false;
    elements.comparisonSubmittedCount.textContent = result.submittedRows.toLocaleString();
    elements.comparisonValidCount.textContent = result.validRows.toLocaleString();
    elements.comparisonMatchedCount.textContent = result.matchedRows.toLocaleString();
    elements.comparisonUnmatchedCount.textContent = result.unmatchedRows.toLocaleString();
    elements.comparisonInvalidCount.textContent = result.invalidRows.toLocaleString();
    elements.comparisonMatchRecordCount.textContent = result.matchingRecords.toLocaleString();
    renderComparisonResults();
  }

  function filterAndSortComparisonRows(rows, search, matchFilter, sortKey, sortDirection) {
    const query = search.toLowerCase();
    const direction = sortDirection === "asc" ? 1 : -1;
    return rows.filter((row) =>
      (matchFilter === "all" || (matchFilter === "matched") === row.matched) &&
      (!query || [row.submitted, row.type, row.name].some((value) => value.toLowerCase().includes(query))))
      .sort((left, right) => sortKey === "inputOrder"
        ? (left.inputOrder - right.inputOrder) * direction
        : left[sortKey].localeCompare(right[sortKey], undefined, { numeric: true, sensitivity: "base" }) * direction);
  }

  function filteredComparisonRows() {
    return filterAndSortComparisonRows(state.comparisonRows, state.comparisonSearch, state.comparisonMatchFilter,
      state.comparisonSortKey, state.comparisonSortDirection);
  }

  function renderComparisonResults() {
    const visible = filteredComparisonRows();
    state.comparisonVisible = visible;
    elements.comparisonBody.replaceChildren();
    const fragment = document.createDocumentFragment();
    visible.forEach((result) => {
      const row = document.createElement("tr");
      if (!result.matched) row.className = "unmatched-row";
      appendCell(row, result.submitted);
      appendCell(row, result.type || "");
      appendCell(row, result.name || "");
      fragment.appendChild(row);
    });
    elements.comparisonBody.appendChild(fragment);
    elements.comparisonEmptyState.hidden = state.comparisonRows.length !== 0;
    elements.comparisonTableRegion.hidden = visible.length === 0;
    elements.comparisonVisibleSummary.hidden = state.comparisonRows.length === 0;
    elements.comparisonVisibleSummary.textContent = `Visible comparison rows: ${visible.length.toLocaleString()} of ${state.comparisonRows.length.toLocaleString()}`;
    [elements.comparisonSearch, elements.comparisonMatchFilter, elements.clearComparison].forEach((control) => { control.disabled = state.comparisonRows.length === 0; });
    elements.comparisonCsv.disabled = visible.length === 0;
    elements.comparisonXlsx.disabled = visible.length === 0;
    elements.comparisonCsv.textContent = `Export Visible CSV (${visible.length.toLocaleString()})`;
    elements.comparisonXlsx.textContent = `Export Visible Excel (${visible.length.toLocaleString()})`;
  }

  function comparisonExportRows(rows) {
    return [["Submitted Asset", "Log Source Type", "Log Source Name"], ...rows.map((row) => [row.submitted, row.type, row.name])];
  }

  function exportComparisonCsv() {
    if (!state.comparisonVisible.length) return;
    downloadBlob(buildCsv(comparisonExportRows(state.comparisonVisible)), "text/csv;charset=utf-8", `LogRhythm_Comparison_Results_${filenameTimestamp(new Date())}.csv`);
  }

  function exportComparisonXlsx() {
    if (!state.comparisonVisible.length || !globalThis.XLSX) return;
    const safeRows = comparisonExportRows(state.comparisonVisible).map((row) => row.map(protectSpreadsheetValue));
    const sheet = globalThis.XLSX.utils.aoa_to_sheet(safeRows);
    sheet["!cols"] = [{ wch: 35 }, { wch: 35 }, { wch: 45 }];
    const workbook = globalThis.XLSX.utils.book_new();
    globalThis.XLSX.utils.book_append_sheet(workbook, sheet, "Comparison Results");
    globalThis.XLSX.writeFile(workbook, `LogRhythm_Comparison_Results_${filenameTimestamp(new Date())}.xlsx`, { compression: true });
  }

  function renderFileSummary(input) {
    elements.fileSummary.hidden = false;
    elements.submittedRowCount.textContent = input.total.toLocaleString();
    elements.validRowCount.textContent = input.validRows.toLocaleString();
    elements.invalidRowCount.textContent = input.invalid.length.toLocaleString();
    elements.invalidRowsPanel.hidden = input.invalid.length === 0;
    elements.invalidRowsBody.replaceChildren();
    const fragment = document.createDocumentFragment();
    input.invalid.forEach((invalid) => {
      const row = document.createElement("tr");
      appendCell(row, String(invalid.row));
      appendCell(row, invalid.original);
      appendCell(row, invalid.reason);
      fragment.appendChild(row);
    });
    elements.invalidRowsBody.appendChild(fragment);
  }

  async function handleComparisonFile() {
    const file = elements.comparisonFile.files[0];
    if (!file) return;
    elements.fileValidationMessage.hidden = true;
    elements.fileSummary.hidden = true;
    elements.invalidRowsPanel.hidden = true;
    elements.comparisonSummary.hidden = true;
    try {
      const input = await parseComparisonFile(file);
      state.comparisonInput = input;
      state.comparisonSortKey = "inputOrder";
      state.comparisonSortDirection = "asc";
      document.querySelectorAll("[data-comparison-sort]").forEach((button) => {
        button.removeAttribute("data-direction");
        button.querySelector("span").textContent = "↕";
      });
      renderFileSummary(input);
      runComparison();
    } catch (error) {
      state.comparisonInput = null;
      state.comparisonRows = [];
      elements.invalidRowsBody.replaceChildren();
      elements.invalidRowsPanel.hidden = true;
      elements.fileValidationMessage.textContent = normalizeError(error).message;
      elements.fileValidationMessage.hidden = false;
      renderComparisonResults();
    }
  }

  function clearComparisonResults() {
    state.comparisonInput = null;
    state.comparisonRows = [];
    state.comparisonVisible = [];
    state.comparisonSearch = "";
    state.comparisonMatchFilter = "all";
    state.comparisonSortKey = "inputOrder";
    state.comparisonSortDirection = "asc";
    elements.comparisonFile.value = "";
    elements.comparisonSearch.value = "";
    elements.comparisonMatchFilter.value = "all";
    elements.fileSummary.hidden = true;
    elements.invalidRowsPanel.hidden = true;
    elements.comparisonSummary.hidden = true;
    elements.fileValidationMessage.hidden = true;
    renderComparisonResults();
  }

  function renderDetailImportSummary(operationalSources) {
    const failures = operationalSources.filter((source) => source.error).length;
    const successes = operationalSources.length - failures;
    elements.failedBadge.hidden = failures === 0;
    elements.failedBadge.textContent = `Failed Details ${failures.toLocaleString()}`;
    elements.detailImportSummary.hidden = operationalSources.length === 0;
    elements.detailSuccessCount.textContent = `Successful details: ${successes.toLocaleString()}`;
    elements.detailFailureCount.textContent = `Failed details: ${failures.toLocaleString()}`;
    elements.retryFailed.hidden = failures === 0;
    elements.failureGroups.replaceChildren();
    if (failures === 0) return;

    const fragment = document.createDocumentFragment();
    groupDetailFailures(operationalSources).forEach((group) => {
      const item = document.createElement("span");
      item.className = "failure-group";
      item.textContent = `${group.code} • ${group.status}: ${group.count.toLocaleString()}`;
      fragment.appendChild(item);
    });
    elements.failureGroups.appendChild(fragment);
  }

  function renderInventoryPagination(kind, pagination) {
    const isOperational = kind === "operational";
    const container = isOperational ? elements.operationalPagination : elements.excludedPagination;
    const range = isOperational ? elements.operationalRange : elements.excludedRange;
    const indicator = isOperational ? elements.operationalPageIndicator : elements.excludedPageIndicator;
    const first = isOperational ? elements.operationalFirst : elements.excludedFirst;
    const previous = isOperational ? elements.operationalPrevious : elements.excludedPrevious;
    const next = isOperational ? elements.operationalNext : elements.excludedNext;
    const last = isOperational ? elements.operationalLast : elements.excludedLast;
    container.hidden = pagination.total === 0;
    range.textContent = pagination.total === 0
      ? "Showing 0 records"
      : `Showing ${pagination.start.toLocaleString()}–${pagination.end.toLocaleString()} of ${pagination.total.toLocaleString()} records`;
    indicator.textContent = `Page ${pagination.page.toLocaleString()} of ${pagination.totalPages.toLocaleString()}`;
    first.disabled = previous.disabled = pagination.page <= 1;
    next.disabled = last.disabled = pagination.page >= pagination.totalPages;
  }

  function renderResults() {
    const partition = partitionSources(state.sources);
    const counts = inventoryCounts(partition.operational);
    elements.totalBadge.textContent = `Operational ${counts.all.toLocaleString()}`;
    elements.excludedBadge.textContent = `Excluded ${partition.excluded.length.toLocaleString()}`;
    elements.discoveredBadge.textContent = `Total Discovered ${state.sources.length.toLocaleString()}`;
    elements.allCount.textContent = counts.all.toLocaleString();
    elements.activeCount.textContent = counts.active.toLocaleString();
    elements.retiredCount.textContent = counts.retired.toLocaleString();
    elements.unknownBadge.hidden = counts.unknown === 0;
    elements.unknownBadge.textContent = `Unknown ${counts.unknown.toLocaleString()}`;
    renderDetailImportSummary(partition.operational);
    elements.search.disabled = state.sources.length === 0;
    const visible = filteredAndSortedSources(partition.operational);
    state.visibleOperational = visible;
    const operationalPage = paginateRecords(visible, state.operationalPage, state.operationalPageSize);
    state.operationalPage = operationalPage.page;
    elements.tableBody.replaceChildren();
    renderExcludedSources(partition.excluded);
    updateActiveFilterCount();
    updateComparisonAvailability();
    elements.inventoryExport.disabled = visible.length === 0;
    elements.inventoryExport.textContent = `Export Visible CSV (${visible.length.toLocaleString()})`;
    elements.inventoryExport.title = "Exports all currently filtered operational records across every page, not only the current page.";
    renderInventoryPagination("operational", operationalPage);

    if (state.sources.length === 0) {
      elements.tableRegion.hidden = true;
      elements.emptyState.hidden = false;
      elements.emptyState.querySelector("h3").textContent = "No log sources found";
      elements.emptyState.querySelector("p").textContent = "The Platform Manager returned an empty log source collection.";
      elements.resultSummary.hidden = true;
      return;
    }

    elements.emptyState.hidden = visible.length !== 0;
    elements.tableRegion.hidden = visible.length === 0;
    if (visible.length === 0) {
      elements.emptyState.querySelector("h3").textContent = "No matching log sources";
      elements.emptyState.querySelector("p").textContent = "Try changing the search text or record status filter.";
    }

    const fragment = document.createDocumentFragment();
    operationalPage.rows.forEach((source) => fragment.appendChild(createRow(source)));
    elements.tableBody.appendChild(fragment);
    elements.resultSummary.hidden = false;
    elements.resultSummary.textContent = `Filtered operational records: ${visible.length.toLocaleString()} of ${partition.operational.length.toLocaleString()}. CSV export includes all ${visible.length.toLocaleString()} filtered records.`;
  }

  function renderExcludedSources(excludedSources) {
    const visible = filteredAndSortedSources(excludedSources);
    state.visibleExcluded = visible;
    const excludedPage = paginateRecords(visible, state.excludedPage, state.excludedPageSize);
    state.excludedPage = excludedPage.page;
    elements.excludedSectionCount.textContent = excludedSources.length.toLocaleString();
    elements.excludedExport.disabled = visible.length === 0;
    elements.excludedExport.textContent = `Export Excluded CSV (${visible.length.toLocaleString()})`;
    elements.excludedExport.title = "Exports all currently filtered excluded records across every page, not only the current page.";
    elements.excludedTableBody.replaceChildren();
    elements.excludedEmptyState.hidden = visible.length !== 0;
    elements.excludedTableRegion.hidden = visible.length === 0;
    const fragment = document.createDocumentFragment();
    excludedPage.rows.forEach((source) => fragment.appendChild(createExcludedRow(source)));
    elements.excludedTableBody.appendChild(fragment);
    renderInventoryPagination("excluded", excludedPage);
    elements.excludedResultSummary.hidden = excludedSources.length === 0;
    elements.excludedResultSummary.textContent = `Filtered excluded records: ${visible.length.toLocaleString()} of ${excludedSources.length.toLocaleString()}. CSV export includes all ${visible.length.toLocaleString()} filtered records.`;
  }

  function createExcludedRow(source) {
    const summary = summaryFor(source);
    const row = document.createElement("tr");
    if (source.error) row.classList.add("row-error");
    row.appendChild(createActionCell(source));
    appendCell(row, summary.id, "sticky-col id-col");
    appendCell(row, summary.name, "name-cell sticky-col name-col");
    appendCell(row, summary.status, "sticky-col status-col");
    appendCell(row, summary.type);
    appendCell(row, exclusionReason(source), "exclusion-reason");
    appendCell(row, summary.collectionMethod, "", `${summary.collectionConfidence}: ${summary.collectionEvidence}`);
    appendCell(row, summary.host);
    appendCell(row, summary.lastLogDate, "", lastLogTooltip(summary.lastLogDateInfo));
    for (let index = 0; index < MAX_IDENTIFIERS; index += 1) {
      appendIdentifierCell(row, summary.identifiers[index]);
    }
    return row;
  }

  function createRow(source) {
    const summary = summaryFor(source);
    const row = document.createElement("tr");
    if (source.error) row.classList.add("row-error");
    row.tabIndex = 0;
    row.setAttribute("aria-label", `View details for ${summary.name}`);
    row.addEventListener("click", () => openDetails(source));
    row.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        openDetails(source);
      }
    });

    row.appendChild(createActionCell(source));
    appendCell(row, summary.id, "sticky-col id-col");
    appendCell(row, summary.name, "name-cell sticky-col name-col");
    const statusCell = document.createElement("td");
    statusCell.className = "sticky-col status-col";
    const statusPill = document.createElement("span");
    statusPill.className = `status-pill ${summary.status}`;
    statusPill.textContent = summary.status;
    statusCell.appendChild(statusPill);
    row.appendChild(statusCell);
    appendCell(row, summary.entity);
    appendCell(row, summary.type);
    appendCell(row, summary.collectionMethod, "collection-method-cell", `${summary.collectionConfidence}: ${summary.collectionEvidence}`);
    appendCell(row, summary.host);
    appendCell(row, summary.systemMonitor);
    appendCell(row, summary.lastLogDate, "", lastLogTooltip(summary.lastLogDateInfo));
    for (let index = 0; index < MAX_IDENTIFIERS; index += 1) {
      appendIdentifierCell(row, summary.identifiers[index]);
    }

    return row;
  }

  function createActionCell(source) {
    const actionCell = document.createElement("td");
    actionCell.className = "sticky-col action-col";
    const button = document.createElement("button");
    button.type = "button";
    button.className = "details-button";
    button.textContent = source.error ? "View Error" : "View Details";
    if (source.error) button.classList.add("inline-error");
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      openDetails(source);
    });
    actionCell.appendChild(button);
    return actionCell;
  }

  function appendCell(row, value, className, title) {
    const cell = document.createElement("td");
    if (className) cell.className = className;
    cell.textContent = value;
    cell.title = title || value;
    row.appendChild(cell);
  }

  function appendIdentifierCell(row, identifier) {
    const cell = document.createElement("td");
    cell.className = "identifier-cell";
    if (identifier) {
      cell.textContent = identifier.value;
      cell.title = `${identifier.type}: ${identifier.value}`;
    } else {
      cell.textContent = "—";
    }
    row.appendChild(cell);
  }

  function openDetails(source) {
    const summary = summaryFor(source);
    elements.drawerTitle.textContent = summary.name;
    elements.drawerSubtitle.textContent = `Log source ID: ${summary.id}`;
    elements.drawerContent.replaceChildren();

    const derivedHeading = document.createElement("h3");
    derivedHeading.textContent = "Derived inventory fields";
    elements.drawerContent.appendChild(derivedHeading);
    elements.drawerContent.appendChild(renderObject({
      collectionMethod: summary.collectionMethod,
      collectionConfidence: summary.collectionConfidence,
      collectionEvidence: summary.collectionEvidence,
      lastLogDate: summary.lastLogDate,
      lastLogDateSourceField: summary.lastLogDateInfo.field || "Not available",
      lastLogDateRawValue: summary.lastLogDateInfo.raw || "Not available",
      exclusionReason: exclusionReason(source) || "Not excluded"
    }));

    if (source.error) {
      const errorBox = document.createElement("div");
      errorBox.className = "drawer-error";
      errorBox.textContent = source.error.message;
      elements.drawerContent.appendChild(errorBox);
      if (source.error.details && typeof source.error.details === "object") {
        const errorHeading = document.createElement("h3");
        errorHeading.textContent = "Structured error";
        errorHeading.className = "drawer-section-heading";
        elements.drawerContent.appendChild(errorHeading);
        elements.drawerContent.appendChild(renderObject(source.error.details));
      }
      if (source.listRecord) {
        const heading = document.createElement("h3");
        heading.textContent = "Discovery record";
        heading.className = "drawer-section-heading";
        elements.drawerContent.appendChild(heading);
        elements.drawerContent.appendChild(renderObject(source.listRecord));
      }
    } else {
      const apiHeading = document.createElement("h3");
      apiHeading.textContent = "API detail response";
      apiHeading.className = "drawer-section-heading";
      elements.drawerContent.appendChild(apiHeading);
      elements.drawerContent.appendChild(renderObject(source.detail));
    }

    elements.drawerBackdrop.hidden = false;
    elements.drawer.setAttribute("aria-hidden", "false");
    requestAnimationFrame(() => elements.drawer.classList.add("open"));
    elements.closeDrawer.focus();
  }

  function renderObject(value) {
    const list = document.createElement("dl");
    list.className = "detail-list";
    if (value === null || typeof value !== "object") {
      const row = createDetailRow("Value", value);
      list.appendChild(row);
      return list;
    }
    const entries = Array.isArray(value) ? value.map((item, index) => [`Item ${index + 1}`, item]) : Object.entries(value);
    if (entries.length === 0) list.appendChild(createDetailRow("Value", "Empty"));
    entries.forEach(([key, item]) => list.appendChild(createDetailRow(humanizeKey(key), item)));
    return list;
  }

  function createDetailRow(key, value) {
    const wrapper = document.createElement("div");
    wrapper.className = "detail-row";
    const term = document.createElement("dt");
    term.textContent = key;
    const description = document.createElement("dd");
    if (value !== null && typeof value === "object") {
      description.appendChild(renderNested(value));
    } else {
      description.textContent = value === null ? "null" : value === "" ? "Empty" : String(value);
    }
    wrapper.append(term, description);
    return wrapper;
  }

  function renderNested(value) {
    const container = document.createElement("div");
    container.className = "nested-block";
    const entries = Array.isArray(value) ? value.map((item, index) => [`Item ${index + 1}`, item]) : Object.entries(value);
    if (entries.length === 0) {
      container.textContent = Array.isArray(value) ? "Empty array" : "Empty object";
      return container;
    }
    entries.forEach(([key, item]) => {
      const block = document.createElement("div");
      block.className = "nested-item";
      const label = document.createElement("span");
      label.className = "nested-key";
      label.textContent = humanizeKey(key);
      block.appendChild(label);
      if (item !== null && typeof item === "object") block.appendChild(renderNested(item));
      else block.appendChild(document.createTextNode(item === null ? "null" : item === "" ? "Empty" : String(item)));
      container.appendChild(block);
    });
    return container;
  }

  function humanizeKey(key) {
    return String(key).replace(/([a-z\d])([A-Z])/g, "$1 $2").replace(/[_-]+/g, " ").replace(/^./, (letter) => letter.toUpperCase());
  }

  function closeDetails() {
    elements.drawer.classList.remove("open");
    elements.drawer.setAttribute("aria-hidden", "true");
    window.setTimeout(() => { elements.drawerBackdrop.hidden = true; }, 220);
  }

  function toggleAdvancedFilters() {
    const willOpen = elements.advancedPanel.hidden;
    elements.advancedPanel.hidden = !willOpen;
    elements.advancedToggle.setAttribute("aria-expanded", String(willOpen));
  }

  function switchView(event) {
    const button = event.target.closest("[data-view]");
    if (!button) return;
    const view = button.dataset.view;
    document.querySelectorAll("[data-app-view]").forEach((section) => { section.hidden = section.dataset.appView !== view; });
    document.querySelectorAll(".nav-button").forEach((candidate) => {
      const active = candidate === button;
      candidate.classList.toggle("active", active);
      if (active) candidate.setAttribute("aria-current", "page");
      else candidate.removeAttribute("aria-current");
    });
    if (view === "comparison") updateComparisonAvailability();
  }

  function updateComparisonAvailability() {
    const loaded = state.sources.length > 0;
    elements.comparisonNotice.hidden = loaded;
    elements.comparisonWorkspace.hidden = !loaded;
  }

  function toggleExcludedSources() {
    const willOpen = elements.excludedContent.hidden;
    elements.excludedContent.hidden = !willOpen;
    elements.excludedToggle.setAttribute("aria-expanded", String(willOpen));
    elements.excludedToggle.textContent = willOpen ? "Hide Excluded" : "Show Excluded";
  }

  function readAdvancedFilters() {
    state.advanced = {
      name: elements.filterName.value.trim(),
      id: elements.filterId.value.trim(),
      entity: elements.filterEntity.value.trim(),
      type: elements.filterType.value.trim(),
      host: elements.filterHost.value.trim(),
      systemMonitor: elements.filterSystemMonitor.value.trim(),
      collectionMethod: elements.filterCollectionMethod.value,
      identifierType: elements.filterIdentifierType.value.trim(),
      identifierValue: elements.filterIdentifierValue.value.trim(),
      status: elements.filterStatus.value,
      hasError: elements.filterHasError.value
    };
  }

  function scheduleFilterRender() {
    window.clearTimeout(state.searchTimer);
    state.searchTimer = window.setTimeout(() => {
      state.search = elements.search.value;
      readAdvancedFilters();
      resetInventoryPages();
      renderResults();
    }, SEARCH_DEBOUNCE_MS);
  }

  function updateActiveFilterCount() {
    const active = Object.entries(state.advanced).filter(([key, value]) =>
      key === "status" || key === "hasError" || key === "collectionMethod" ? value !== "all" : Boolean(value)).length;
    elements.activeFilterCount.textContent = `${active.toLocaleString()} active`;
  }

  function clearAllFilters() {
    window.clearTimeout(state.searchTimer);
    elements.search.value = "";
    [elements.filterName, elements.filterId, elements.filterEntity, elements.filterType, elements.filterHost,
      elements.filterSystemMonitor, elements.filterIdentifierType, elements.filterIdentifierValue]
      .forEach((input) => { input.value = ""; });
    elements.filterStatus.value = "all";
    elements.filterHasError.value = "all";
    elements.filterCollectionMethod.value = "all";
    state.search = "";
    state.advanced = createEmptyAdvancedFilters();
    state.filter = "all";
    document.querySelectorAll("[data-filter]").forEach((button) => {
      const selected = button.dataset.filter === "all";
      button.classList.toggle("active", selected);
      button.setAttribute("aria-pressed", String(selected));
    });
    resetInventoryPages();
    renderResults();
  }

  function changeFilter(event) {
    const button = event.target.closest("[data-filter]");
    if (!button) return;
    state.filter = button.dataset.filter;
    document.querySelectorAll("[data-filter]").forEach((candidate) => {
      const selected = candidate === button;
      candidate.classList.toggle("active", selected);
      candidate.setAttribute("aria-pressed", String(selected));
    });
    resetInventoryPages();
    renderResults();
  }

  function changeSort(event) {
    const button = event.target.closest("[data-sort]");
    if (!button) return;
    const key = button.dataset.sort;
    if (state.sortKey === key) state.sortDirection = state.sortDirection === "asc" ? "desc" : "asc";
    else { state.sortKey = key; state.sortDirection = "asc"; }
    document.querySelectorAll("[data-sort]").forEach((candidate) => candidate.removeAttribute("data-direction"));
    button.dataset.direction = state.sortDirection;
    button.querySelector("span").textContent = state.sortDirection === "asc" ? "↑" : "↓";
    resetInventoryPages();
    renderResults();
  }

  function resetInventoryPages() {
    state.operationalPage = 1;
    state.excludedPage = 1;
  }

  function changeInventoryPage(kind, action) {
    const key = kind === "operational" ? "operationalPage" : "excludedPage";
    if (action === "first") state[key] = 1;
    else if (action === "previous") state[key] = Math.max(1, state[key] - 1);
    else if (action === "next") state[key] += 1;
    else if (action === "last") state[key] = Number.MAX_SAFE_INTEGER;
    renderResults();
  }

  function changeInventoryPageSize(kind, value) {
    const parsed = value === "all" ? "all" : Number(value);
    if (!INVENTORY_PAGE_SIZES.includes(parsed)) return;
    if (kind === "operational") {
      state.operationalPageSize = parsed;
      state.operationalPage = 1;
    } else {
      state.excludedPageSize = parsed;
      state.excludedPage = 1;
    }
    renderResults();
  }

  function changeComparisonSort(event) {
    const button = event.target.closest("[data-comparison-sort]");
    if (!button) return;
    const key = button.dataset.comparisonSort;
    if (state.comparisonSortKey === key) state.comparisonSortDirection = state.comparisonSortDirection === "asc" ? "desc" : "asc";
    else { state.comparisonSortKey = key; state.comparisonSortDirection = "asc"; }
    document.querySelectorAll("[data-comparison-sort]").forEach((candidate) => candidate.removeAttribute("data-direction"));
    button.dataset.direction = state.comparisonSortDirection;
    button.querySelector("span").textContent = state.comparisonSortDirection === "asc" ? "↑" : "↓";
    renderComparisonResults();
  }

  if (elements) {
    elements.form.addEventListener("submit", startImport);
    elements.cancel.addEventListener("click", cancelImport);
    elements.search.addEventListener("input", scheduleFilterRender);
    [elements.filterName, elements.filterId, elements.filterEntity, elements.filterType, elements.filterHost,
      elements.filterSystemMonitor, elements.filterIdentifierType, elements.filterIdentifierValue]
      .forEach((input) => input.addEventListener("input", scheduleFilterRender));
    elements.filterStatus.addEventListener("change", () => { readAdvancedFilters(); resetInventoryPages(); renderResults(); });
    elements.filterHasError.addEventListener("change", () => { readAdvancedFilters(); resetInventoryPages(); renderResults(); });
    elements.filterCollectionMethod.addEventListener("change", () => { readAdvancedFilters(); resetInventoryPages(); renderResults(); });
    elements.advancedToggle.addEventListener("click", toggleAdvancedFilters);
    elements.clearFilters.addEventListener("click", clearAllFilters);
    elements.retryFailed.addEventListener("click", retryFailedDetails);
    elements.inventoryExport.addEventListener("click", () => exportInventoryCsv(state.visibleOperational, false));
    elements.excludedExport.addEventListener("click", () => exportInventoryCsv(state.visibleExcluded, true));
    elements.excludedToggle.addEventListener("click", toggleExcludedSources);
    elements.operationalPageSize.addEventListener("change", () => changeInventoryPageSize("operational", elements.operationalPageSize.value));
    elements.excludedPageSize.addEventListener("change", () => changeInventoryPageSize("excluded", elements.excludedPageSize.value));
    elements.operationalFirst.addEventListener("click", () => changeInventoryPage("operational", "first"));
    elements.operationalPrevious.addEventListener("click", () => changeInventoryPage("operational", "previous"));
    elements.operationalNext.addEventListener("click", () => changeInventoryPage("operational", "next"));
    elements.operationalLast.addEventListener("click", () => changeInventoryPage("operational", "last"));
    elements.excludedFirst.addEventListener("click", () => changeInventoryPage("excluded", "first"));
    elements.excludedPrevious.addEventListener("click", () => changeInventoryPage("excluded", "previous"));
    elements.excludedNext.addEventListener("click", () => changeInventoryPage("excluded", "next"));
    elements.excludedLast.addEventListener("click", () => changeInventoryPage("excluded", "last"));
    document.querySelector(".app-nav").addEventListener("click", switchView);
    elements.comparisonFile.addEventListener("change", handleComparisonFile);
    elements.includeExcludedComparison.addEventListener("change", runComparison);
    elements.comparisonSearch.addEventListener("input", () => { state.comparisonSearch = elements.comparisonSearch.value.trim(); renderComparisonResults(); });
    elements.comparisonMatchFilter.addEventListener("change", () => { state.comparisonMatchFilter = elements.comparisonMatchFilter.value; renderComparisonResults(); });
    elements.clearComparison.addEventListener("click", clearComparisonResults);
    elements.comparisonCsv.addEventListener("click", exportComparisonCsv);
    elements.comparisonXlsx.addEventListener("click", exportComparisonXlsx);
    document.querySelector(".comparison-table thead").addEventListener("click", changeComparisonSort);
    document.querySelector(".filter-group").addEventListener("click", changeFilter);
    document.querySelector("thead").addEventListener("click", changeSort);
    elements.closeDrawer.addEventListener("click", closeDetails);
    elements.drawerBackdrop.addEventListener("click", closeDetails);
    document.addEventListener("keydown", (event) => { if (event.key === "Escape" && elements.drawer.classList.contains("open")) closeDetails(); });
  }

  if (typeof module !== "undefined" && module.exports) {
    module.exports = Object.freeze({
      PAGE_SIZE,
      DETAIL_CONCURRENCY,
      DEFAULT_INVENTORY_PAGE_SIZE,
      INVENTORY_PAGE_SIZES,
      AppError,
      validateHost,
      extractRecords,
      EXCLUDED_LOG_SOURCE_TYPES,
      COLLECTION_METHODS,
      COLLECTION_TYPE_PREFIX_RULES,
      API_LOG_SOURCE_TYPES,
      SYSLOG_LOG_SOURCE_TYPES,
      FLAT_FILE_LOG_SOURCE_TYPES,
      MS_EVENT_LOG_SOURCE_TYPES,
      UDLA_LOG_SOURCE_TYPES,
      OPEN_COLLECTOR_LOG_SOURCE_TYPES,
      classifyCollectionMethod,
      extractLastLogDate,
      parseLastLogTimestamp,
      extractAllIdentifiers,
      extractIdentifiers,
      fetchJson,
      discoverLogSources,
      loadDetails,
      summaryFor,
      searchableText,
      sourceMatchesAdvancedFilters,
      inventoryCounts,
      paginateRecords,
      groupDetailFailures,
      partitionSources,
      exclusionReason,
      protectSpreadsheetValue,
      csvCell,
      buildCsv,
      inventoryExportRows,
      validateSubmittedAsset,
      parseCsvText,
      validateComparisonRows,
      parseComparisonFile,
      compareSubmittedAssets,
      filterAndSortComparisonRows,
      comparisonExportRows,
      createEmptyAdvancedFilters,
      renderObject,
      setBearerTokenForTest(token) { bearerToken = token; },
      clearBearerTokenForTest() { bearerToken = ""; }
    });
  }
}());
