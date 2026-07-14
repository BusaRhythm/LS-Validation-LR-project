# LogRhythm Log Source Explorer (Unofficial Utility)

> This is an unofficial, independent community utility. It is not an official
> LogRhythm or Exabeam product and is not endorsed, owned, partnered with, or
> supported by LogRhythm or Exabeam.

LogRhythm Log Source Explorer is a portable community-built utility designed
to simplify Log Source inventory, validation, and coverage assessment in
LogRhythm SIEM environments.

The application connects to the LogRhythm Platform Manager Admin API, retrieves
the configured Log Sources and their available details, and presents them in a
searchable, filterable, sortable, and exportable inventory.

It uses vanilla HTML, CSS, JavaScript, and a restricted local Windows PowerShell
proxy. It requires no installation, Administrator privileges, npm, compilation,
Python, database, or external backend service.

## Who is this tool for?

This utility is primarily intended for:

- SIEM administrators
- SOC engineers and analysts
- Cybersecurity integration teams
- Log management teams
- Security teams performing SIEM health checks
- Teams conducting asset coverage and integration gap assessments

## Why this tool exists

Reviewing large numbers of Log Sources manually through Deployment Manager can
be time-consuming, especially when validating statuses, Log Source Types,
collection methods, identifiers, hosts, and integration coverage.

This utility helps security teams:

- Build a clear operational Log Source inventory
- Separate operational sources from internal LogRhythm system sources
- Review Active, Retired, and Unknown records
- Inspect IP addresses, FQDNs, and other Log Source identifiers
- Review the Collection Method derived from the Log Source Type
- Search, filter, sort, paginate, and export inventory data
- Identify failed detail requests without losing successful results
- Reduce the manual effort required during SIEM validation and health checks

## Comparative Mode

Comparative Mode provides a simple asset-to-SIEM coverage comparison.

The user uploads a TXT, CSV, or XLSX file containing one IP address or FQDN per
row. The application compares each valid submitted row against the loaded
LogRhythm inventory using the Log Source Host field and all identifiers
returned by the API.

The results help identify:

- Assets already integrated into LogRhythm
- Assets with no matching Log Source
- The matching Log Source Name
- The matching Log Source Type
- Invalid submitted rows
- Assets that may require new SIEM integration or further investigation

If one submitted asset matches multiple Log Sources, the application displays
one result row for each matching Log Source. Submitted rows that do not match
any Log Source are clearly shown as unmatched.

The objective is to make basic SIEM gap analysis faster by showing the
difference between the assets expected to be monitored and the assets currently
integrated into LogRhythm.

## Start the application

1. Keep all project files together in the same folder.
2. Double-click **`Start.cmd`**. This is the normal launch method.
3. A PowerShell window starts a server bound only to IPv4 loopback. It prefers `127.0.0.1:8090` and opens `http://localhost:8090` in the default browser. If port `8090` is unavailable, it automatically uses port `8899` instead.
4. Enter the Platform Manager FQDN, IPv4 address, or `localhost` without `https://`, a port, or a path.
5. Enter a Bearer Token and select **Connect and Load**.
6. Search, filter, or sort the inventory. Select a row or **View Details** to inspect every field returned by the detail endpoint.

Do not open `index.html` directly. The browser interface now requires the local PowerShell server and restricted API proxy.

`Start.cmd` runs Windows PowerShell with `-NoProfile` and a process-only execution-policy bypass. It does not change the system or user execution policy.

To stop the application, return to its PowerShell window and press **Ctrl+C**. Closing the PowerShell window also stops the local server.

If port `8090` is occupied, blocked, or reserved by Windows, the server automatically tries port `8899`. If neither port can be opened, the launcher reports the reason for each port and does not start the application.

## Platform Manager addresses

HTTPS and Platform Manager port `8501` are fixed. Valid inputs include:

- An FQDN such as `pm.example.com` of the Platform Manager
- A documentation-only IPv4 example such as `10.X.X.X`
- `localhost`
- `127.0.0.1`

`localhost` and `127.0.0.1` are useful when this tool is running directly on the Platform Manager host.

The PowerShell proxy accepts an untrusted or self-signed Platform Manager certificate only for the restricted outbound HTTPS connection created by this script to the fixed LogRhythm API host, port, and allowlisted paths. It does not install a certificate, affect the browser-facing loopback server, or change certificate validation globally for PowerShell, Windows, the browser, or other applications.

## Architecture and security

```text
Browser -> local PowerShell server -> LogRhythm Admin API
```

The local server:

- Listens only on IPv4 loopback, preferring `127.0.0.1:8090` and falling back to `127.0.0.1:8899`
- Serves `index.html`, `styles.css`, `app.js`, and the locally bundled `xlsx.full.min.js`
- Accepts same-origin `POST /proxy` requests only through `localhost` or `127.0.0.1` on the port selected at startup
- Rejects unexpected local hosts, browser origins, methods, content types, schemes, ports, and API paths
- Can proxy only the log source list endpoint and numeric log source detail endpoints
- Never places the token in a URL

The Bearer Token is held only in browser-tab and PowerShell process memory while requests are active. It is never written to disk, console output, logs, browser storage, cookies, or configuration files.

### Before publishing or sharing

- Never commit, paste, upload, or share a Bearer Token. If a token is accidentally exposed, revoke or rotate it immediately and remove it from repository history before publication.
- Do not commit inventory exports, comparison uploads, customer data, Platform Manager addresses, credentials, private certificates, or diagnostic logs from a real environment.
- Review staged files before every commit. The included `.gitignore` blocks common exports, uploads, secrets, certificates, logs, and temporary files, but it is not a substitute for reviewing the staged diff.
- Keep example hosts and addresses fictitious or within reserved documentation ranges.

## API workflow

The proxy sends authenticated `GET` requests to:

- `https://{host}:8501/lr-admin-api/logsources/?offset={offset}&count=1000&recordStatus=all`
- `https://{host}:8501/lr-admin-api/logsources/{numeric-id}`

The browser sends the host, token, and requested restricted path to the local proxy in a JSON `POST` body. List requests begin at offset `0` and increase by `1000` until a page contains fewer than `1000` records. Details are then loaded with no more than five requests in flight. An individual detail error remains attached to that source and does not stop the rest of the import.

The proxy returns structured JSON errors for invalid hosts, refused connections, timeouts, HTTP 401/403, HTTP 404, invalid JSON, and other upstream failures. The browser displays those messages directly.

## Inventory and Comparative Mode

The Inventory view keeps operational Log Sources separate from exact matches in the centralized **Excluded / Internal Log Sources** type list. Counts always show operational, excluded, and total discovered records. Search, status filters, Advanced Filters, Collection Method classification, corrected Last Log Date extraction, identifiers, detail-error retry, and exports are processed locally after the inventory is loaded.

Both inventory tables use independent client-side pagination. The default is 100 rows per page, with 50, 100, 250, 500, 1000, and All options plus First, Previous, Next, and Last controls. Search and filters are applied before pagination and changing a filter or sort returns both tables to page 1. Selecting a page or page size never requests API data. Inventory CSV exports include every currently filtered record across all pages, not only the rendered page.

Collection Method is determined only from the resolved Log Source Type name. Official category prefixes and centralized exact mappings are applied in this order: Microsoft Event Log, UDLA, API, Flat File, Syslog, and Open Collector; unrecognized types remain Unknown. Arbitrary API configuration, paths, protocols, hosts, ports, and identifiers are not scanned for classification.

**Export Visible CSV** exports all currently filtered operational rows across every client-side page. The excluded section has its own filtered-row CSV export. CSV files use UTF-8 with a BOM, quote special characters, and protect cells beginning with `=`, `+`, `-`, or `@` against spreadsheet formula injection.

Comparative Mode accepts:

- TXT with one IPv4 address or FQDN per line
- CSV with one column and an optional recognized header
- XLSX using the first worksheet, one column, and a required header row

Uploads remain in browser memory. Matching is exact after normalization and checks the Log Source Host plus every identifier returned by the detail API, including identifiers beyond the eight displayed inventory columns. Excluded/Internal Log Sources participate only when the user enables the comparison option. Visible comparison rows can be exported to CSV or a real XLSX workbook.

Comparison processes every valid submitted row independently in original file order, including repeated IP addresses or FQDNs. Results preserve the submitted spelling, and a row that matches multiple Log Sources produces one result for each matching record. Invalid rows remain separate in the validation summary and do not participate in comparison.

## Bundled third-party software

The only locally bundled third-party runtime library is:

| Component | Version | Local file | License | Authoritative source |
| --- | --- | --- | --- | --- |
| SheetJS Community Edition | 0.20.3 | `xlsx.full.min.js` | Apache License 2.0 | [SheetJS standalone browser distribution](https://docs.sheetjs.com/docs/getting-started/installation/standalone/) |

SheetJS is vendored locally for offline XLSX reading and writing; no CDN is contacted at runtime. SheetJS Community Edition is Copyright (C) 2012-present SheetJS LLC. The complete Apache 2.0 text and SheetJS attribution are retained in `SHEETJS-LICENSE.txt`, consistent with the [SheetJS license and attribution requirements](https://docs.sheetjs.com/docs/miscellany/license/).

The bundled `xlsx.full.min.js` reports version `0.20.3`. Its audited SHA-256 digest is `CC015130AA8521E7F088F88898EBA949CCDCBFB38DF0BD129B44B7273C3A6F41`.

## Files

- `Start.cmd` - normal launcher with a process-only execution-policy bypass
- `Start.ps1` - loopback static server and restricted LogRhythm API proxy
- `index.html` - accessible application structure
- `styles.css` - responsive security-tool interface
- `app.js` - API workflow, cancellation, filtering, sorting, and safe rendering
- `xlsx.full.min.js` - locally bundled SheetJS CE 0.20.3 browser library for XLSX import/export
- `SHEETJS-LICENSE.txt` - Apache 2.0 license and SheetJS notices
- `README.md` - launch, security, and API documentation
