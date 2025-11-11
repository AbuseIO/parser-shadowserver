#!/usr/bin/env php
<?php
/**
 * Shadowserver config vs reports.json checker
 *
 * Compares local parser config feeds/fields in vendor/abuseio/parser-shadowserver/config/Shadowserver.php
 * against the official Shadowserver report schema at reports.json.
 *
 * Usage:
 *   php vendor/abuseio/parser-shadowserver/check-schema.php [--json <url-or-path>] [--strict] [--fields]
 *
 * Defaults:
 *   --json defaults to the raw GitHub URL for reports.json
 *   --strict causes non-matching fields to exit non-zero (default: non-zero on missing feeds)
 *   --fields prints detailed per-feed field differences (hidden by default)
 */

declare(strict_types=1);

function stderr(string $msg): void { fwrite(STDERR, $msg."\n"); }
function stdout(string $msg): void { fwrite(STDOUT, $msg."\n"); }

function toRawGithubUrl(string $url): string {
    // Convert GitHub blob URL to raw URL if necessary
    $pattern = '#^https?://github.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)$#';
    if (preg_match($pattern, $url, $m)) {
        return "https://raw.githubusercontent.com/{$m[1]}/{$m[2]}/{$m[3]}/{$m[4]}";
    }
    return $url;
}

function loadJsonSchema(string $pathOrUrl): array {
    $pathOrUrl = toRawGithubUrl($pathOrUrl);
    $ctx = stream_context_create([
        'http' => [
            'timeout' => 20,
            'header'  => "User-Agent: AbuseIO-Shadowserver-Config-Checker\r\n",
        ],
        'https' => [
            'timeout' => 20,
            'header'  => "User-Agent: AbuseIO-Shadowserver-Config-Checker\r\n",
        ],
    ]);
    $data = @file_get_contents($pathOrUrl, false, $ctx);
    if ($data === false) {
        // Try as local file
        if (!is_file($pathOrUrl)) {
            throw new RuntimeException("Unable to load schema from URL or file: {$pathOrUrl}");
        }
        $data = file_get_contents($pathOrUrl);
    }
    $json = json_decode($data, true);
    if (!is_array($json)) {
        throw new RuntimeException("Schema did not parse as JSON from: {$pathOrUrl}");
    }
    return $json;
}

/**
 * Attempt to derive a mapping of report name => fields array from the schema.
 */
function extractReportDefinitions(array $schema): array {
    $defs = [];

    // Case 1: Top-level keyed by report name
    // e.g. { "scan_vnc": { "columns": ["ip", ...] } }
    $topKeys = array_keys($schema);
    $hasNonNumericKeys = array_reduce($topKeys, function ($carry, $k) { return $carry || !is_int($k); }, false);
    if ($hasNonNumericKeys) {
        foreach ($schema as $name => $entry) {
            if (!is_array($entry)) { continue; }
            $fields = $entry['columns'] ?? $entry['fields'] ?? null;
            if (is_array($fields)) {
                $defs[$name] = array_values(array_unique(array_map('strval', $fields)));
            }
        }
        if (!empty($defs)) return $defs;
    }

    // Case 2: Array under a key 'reports'
    // e.g. { "reports": [ { "name": "scan_vnc", "columns": [...] }, ... ] }
    if (isset($schema['reports']) && is_array($schema['reports'])) {
        foreach ($schema['reports'] as $entry) {
            if (!is_array($entry)) { continue; }
            $name   = $entry['name'] ?? $entry['report'] ?? null;
            $fields = $entry['columns'] ?? $entry['fields'] ?? null;
            if (is_string($name) && is_array($fields)) {
                $defs[$name] = array_values(array_unique(array_map('strval', $fields)));
            }
        }
        if (!empty($defs)) return $defs;
    }

    // Case 3: List of reports at top-level
    // e.g. [ { "name": "scan_vnc", "columns": [...] }, ... ]
    if (array_values($schema) === $schema) { // numerically indexed
        foreach ($schema as $entry) {
            if (!is_array($entry)) { continue; }
            $name   = $entry['name'] ?? $entry['report'] ?? null;
            $fields = $entry['columns'] ?? $entry['fields'] ?? null;
            if (is_string($name) && is_array($fields)) {
                $defs[$name] = array_values(array_unique(array_map('strval', $fields)));
            }
        }
        if (!empty($defs)) return $defs;
    }

    return $defs; // possibly empty
}

/**
 * Extract classification info (taxonomy, type) for each report, keyed by report name.
 * Tries several schema layouts and key variants for robustness.
 */
function extractClassificationMap(array $schema): array {
    $map = [];

    // Helper to resolve taxonomy/type from an entry
    $getClass = function(array $entry): array {
        $taxonomy = null;
        $type = null;
        // Common representation: dotted keys
        if (isset($entry['classification.taxonomy'])) {
            $taxonomy = $entry['classification.taxonomy'];
        }
        if (isset($entry['classification.type'])) {
            $type = $entry['classification.type'];
        }
        // Alternative: nested object
        if (($taxonomy === null || $type === null) && isset($entry['classification']) && is_array($entry['classification'])) {
            $taxonomy = $taxonomy ?? ($entry['classification']['taxonomy'] ?? null);
            $type     = $type     ?? ($entry['classification']['type'] ?? null);
        }
        // Fallbacks seen in some schemas
        if ($taxonomy === null) { $taxonomy = $entry['taxonomy'] ?? ($entry['class'] ?? null); }
        if ($type === null) { $type = $entry['type'] ?? null; }
        return ['taxonomy' => $taxonomy, 'type' => $type];
    };

    // Case 1: Top-level keyed by report name
    $topKeys = array_keys($schema);
    $hasNonNumericKeys = array_reduce($topKeys, function ($carry, $k) { return $carry || !is_int($k); }, false);
    if ($hasNonNumericKeys) {
        foreach ($schema as $name => $entry) {
            if (!is_array($entry)) { continue; }
            $map[$name] = $getClass($entry);
        }
        if (!empty($map)) return $map;
    }

    // Case 2: Array under a key 'reports'
    if (isset($schema['reports']) && is_array($schema['reports'])) {
        foreach ($schema['reports'] as $entry) {
            if (!is_array($entry)) { continue; }
            $name = $entry['name'] ?? $entry['report'] ?? null;
            if (!is_string($name)) { continue; }
            $map[$name] = $getClass($entry);
        }
        if (!empty($map)) return $map;
    }

    // Case 3: List of reports at top-level
    if (array_values($schema) === $schema) { // numerically indexed
        foreach ($schema as $entry) {
            if (!is_array($entry)) { continue; }
            $name = $entry['name'] ?? $entry['report'] ?? null;
            if (!is_string($name)) { continue; }
            $map[$name] = $getClass($entry);
        }
        if (!empty($map)) return $map;
    }

    return $map;
}

function parseArgs(array $argv): array {
    $args = [
        'json'   => 'https://raw.githubusercontent.com/The-Shadowserver-Foundation/report_schema/main/reports.json',
        'strict' => false,
        'fields' => false,
        'config_example' => false,
    ];
    for ($i = 1; $i < count($argv); $i++) {
        $a = $argv[$i];
        if ($a === '--json' && isset($argv[$i+1])) {
            $args['json'] = $argv[++$i];
        } elseif ($a === '--strict') {
            $args['strict'] = true;
        } elseif ($a === '--fields') {
            $args['fields'] = true;
        } elseif ($a === '--config-example') {
            $args['config_example'] = true;
        } elseif ($a === '--help' || $a === '-h') {
            stdout("Usage: {$argv[0]} [--json <url-or-path>] [--strict] [--fields] [--config-example]");
            exit(0);
        } else {
            stderr("Unknown argument: {$a}");
            stdout("Usage: {$argv[0]} [--json <url-or-path>] [--strict] [--fields] [--config-example]");
            exit(2);
        }
    }
    return $args;
}

function main(array $argv): int {
    $args = parseArgs($argv);

    $configPath = __DIR__ . '/config/Shadowserver.php';
    if (!is_file($configPath)) {
        stderr('Unable to locate parser config: ' . $configPath);
        return 2;
    }
    $cfg = require $configPath;
    $feeds = $cfg['feeds'] ?? [];
    if (!is_array($feeds) || empty($feeds)) {
        stderr('No feeds found in local parser config.');
    }

    try {
        $schema = loadJsonSchema($args['json']);
    } catch (\Throwable $e) {
        stderr('Failed to load schema: ' . $e->getMessage());
        return 2;
    }

    $defs = extractReportDefinitions($schema);
    $classMap = extractClassificationMap($schema);
    if (empty($defs)) {
        stderr('Could not extract report definitions from schema JSON.');
        return 2;
    }

    $missingFeeds = [];
    $schemaOnlyFeeds = [];
    $fieldMismatches = [];

    foreach ($feeds as $feedName => $feedCfg) {
        // Only use declared 'fields' for mismatch reporting.
        // If a feed defines a 'filters' list, those are intentionally ignored
        // and should not cause mismatch reports.
        $localFieldsRaw = [];
        if (isset($feedCfg['fields']) && is_array($feedCfg['fields'])) {
            $localFieldsRaw = array_merge($localFieldsRaw, $feedCfg['fields']);
        }
        $localFields = array_values(array_unique(array_map('strval', $localFieldsRaw)));

        // Normalized list of locally-declared filters to ignore in diffs
        $localFilters = [];
        if (isset($feedCfg['filters']) && is_array($feedCfg['filters'])) {
            $localFilters = array_values(array_unique(array_map('strval', $feedCfg['filters'])));
        }
        if (!array_key_exists($feedName, $defs)) {
            $missingFeeds[] = $feedName;
            continue;
        }
        $remoteFields = array_values(array_unique(array_map('strval', $defs[$feedName])));

        // Compute differences
        $localMinusRemote = array_values(array_diff($localFields, $remoteFields));
        // Exclude any locally-declared filters from remote-only mismatches
        $remoteMinusLocal = array_values(array_diff($remoteFields, $localFields, $localFilters));

        if (!empty($localMinusRemote) || !empty($remoteMinusLocal)) {
            $fieldMismatches[$feedName] = [
                'local_only'  => $localMinusRemote,
                'remote_only' => $remoteMinusLocal,
            ];
        }
    }

    // Also compute feeds present remotely but missing locally
    $localFeedNames  = array_keys($feeds);
    $remoteFeedNames = array_keys($defs);
    $schemaOnlyFeeds = array_values(array_diff($remoteFeedNames, $localFeedNames));

    // Output summary
    stdout('Shadowserver parser config vs reports.json');
    stdout('Schema source: ' . $args['json']);
    stdout('Local feeds: ' . count($feeds) . '; Schema reports: ' . count($defs));
    stdout('');

    if (!empty($missingFeeds)) {
        stdout('Present in config but not in Shadowserver schema (this is fine, just legacy supported):');
        foreach ($missingFeeds as $name) {
            stdout("  - {$name}");
        }
        stdout('');
    }

    if (!empty($schemaOnlyFeeds)) {
        stdout('Present in Shadowserver schema but missing locally:');
        foreach ($schemaOnlyFeeds as $name) {
            $tax = $classMap[$name]['taxonomy'] ?? 'unknown';
            $typ = $classMap[$name]['type'] ?? 'unknown';
            $suffix = ' [' . $tax . ' ' . $typ . ']';
            stdout("  - {$name}{$suffix}");
        }
        stdout('');
    }

    if ($args['fields'] && !empty($fieldMismatches)) {
        stdout('Field mismatches:');
        foreach ($fieldMismatches as $name => $diffs) {
            stdout("  - {$name}");
            if (!empty($diffs['local_only'])) {
                stdout('      local only:  ' . implode(', ', $diffs['local_only']));
            }
            if (!empty($diffs['remote_only'])) {
                //stdout('      remote only: ' . implode(', ', $diffs['remote_only']));
		foreach($diffs['remote_only'] as $diff) {
                    echo "                 '$diff',".PHP_EOL;
                }
            }
        }
        stdout('');
    }

    // Suggestion output for missing locally feeds (optional)
    if ($args['config_example'] && !empty($schemaOnlyFeeds)) {
        $standardFilters = ['asn','geo','region','city','naics','sic'];
        $whitelistScanFields = ['ip','timestamp','port','protocol'];

        $formatPhpList = function(array $items, int $indentSpaces = 17): string {
            $indent = str_repeat(' ', $indentSpaces);
            $lines = [];
            foreach ($items as $it) {
                $lines[] = $indent . "'" . $it . "',";
            }
            return implode("\n", $lines);
        };

        stdout('Suggested config additions (copy into vendor/abuseio/parser-shadowserver/config/Shadowserver.php):');
        foreach ($schemaOnlyFeeds as $name) {
            $remoteFields = $defs[$name] ?? [];

            $isScan = false;
            $service = null;
            if (preg_match('/^scan6?_([A-Za-z0-9_\-]+)/', $name, $m)) {
                $isScan = true;
                $service = strtoupper(str_replace('-', '_', $m[1]));
            }

            if ($isScan) {
                $class = 'OPEN_' . $service;
                $type  = 'INFO';
                // Filter fields to a minimal, consistent set seen in existing scan_* feeds
                $fieldsFiltered = array_values(array_intersect($remoteFields, $whitelistScanFields));
                // If schema lacks typical names, fall back to using whatever it provides
                if (empty($fieldsFiltered)) {
                    $fieldsFiltered = $remoteFields;
                }
                $filters = $standardFilters;
            } else {
                $class = '???';
                $type  = '???';
                $fieldsFiltered = $remoteFields; // keep schema fields for non-scan feeds
                $filters = []; // unknown; avoid guessing
            }

            // Format PHP stanza
            stdout("  '{$name}' => [");
            stdout("             'class'     => '{$class}',");
            stdout("             'type'      => '{$type}',");
            stdout("             'enabled'   => true,");
            stdout("             'fields'    => [");
            if (!empty($fieldsFiltered)) {
                stdout($formatPhpList($fieldsFiltered));
            }
            stdout("             ],");
            stdout("             'filters'   => [");
            if (!empty($filters)) {
                stdout($formatPhpList($filters));
            }
            stdout("             ],");
            stdout("         ],");
        }
        stdout('');
        stdout('Note: scan_* feeds default to class OPEN_$SERVICE and type INFO.');
        stdout('      Non-scan feeds leave class/type as ??? for now.');
        stdout('      Only suggestions for NEW elements are printed; existing items are untouched.');
        stdout('');
    }

    $fail = 0;
    if (!empty($missingFeeds) || !empty($schemaOnlyFeeds)) { $fail = 1; }
    if ($args['strict'] && !empty($fieldMismatches)) { $fail = 1; }

    if ($fail) {
        stderr('Config does not match schema (see differences above).');
        return 1;
    }

    stdout('Config matches schema (no feed discrepancies' . ($args['strict'] ? ', no field mismatches' : ' (field differences ignored)') . ').');
    return 0;
}

exit(main($argv));
