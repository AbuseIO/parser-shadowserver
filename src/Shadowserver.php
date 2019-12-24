<?php

namespace AbuseIO\Parsers;

use AbuseIO\Models\Incident;
use Ddeboer\DataImport\Reader;
use SplFileObject;
use Madnest\Madzipper\Madzipper;

/**
 * Class Shadowserver
 * @package AbuseIO\Parsers
 */
class Shadowserver extends Parser
{
    /**
     * Create a new Shadowserver instance
     *
     * @param \PhpMimeMailParser\Parser $parsedMail phpMimeParser object
     * @param array $arfMail array with ARF detected results
     */
    public function __construct($parsedMail, $arfMail)
    {
        parent::__construct($parsedMail, $arfMail, $this);
    }

    /**
     * Parse attachments
     * @return array    Returns array with failed or success data
     *                  (See parser-common/src/Parser.php) for more info.
     */
    public function parse()
    {
        // Validate user based regex
        try {
            preg_match(
                config("{$this->configBase}.parser.file_regex"),
                '',
                $matches
            );

        } catch (\Exception $e) {
            $this->warningCount++;

            return $this->failed('Configuration error in the regular expression');
        }

        foreach ($this->parsedMail->getAttachments() as $attachment) {
            if (strpos($attachment->filename, '.zip') !== false
                && ($attachment->contentType == 'application/octet-stream'
                    || $attachment->contentType == 'application/zip'
                )
            ) {


                if (!$this->createWorkingDir()) {
                    return $this->failed(
                        "Unable to create working directory"
                    );
                }

                file_put_contents($this->tempPath . $attachment->filename, $attachment->getContent());

                $zip = new Madzipper;
                $zip->make($this->tempPath . $attachment->filename);
                $zip->extractTo($this->tempPath);

                foreach ($zip->listFiles() as $index => $compressedFile) {
                    if (strpos($compressedFile, '.csv') !== false) {
                        // For each CSV file we find, we are going to do magic (however they usually only send 1 zip)
                        if (preg_match(
                            config("{$this->configBase}.parser.file_regex"),
                            $compressedFile,
                            $matches
                        )) {
                            $this->feedName = $matches[1];

                            // If feed is known and enabled, validate data and save report
                            if ($this->isKnownFeed() && $this->isEnabledFeed()) {
                                $csvReports = new Reader\CsvReader(
                                    new SplFileObject($this->tempPath . $compressedFile)
                                );
                                $csvReports->setHeaderRowNumber(0);

                                foreach ($csvReports as $report) {

                                    // Handle field mappings first
                                    $aliasses = config("{$this->configBase}.feeds.{$this->feedName}.aliasses");
                                    if (is_array($aliasses)) {
                                        foreach ($aliasses as
                                                 $alias => $real) {
                                            if (array_key_exists($alias, $report)) {
                                                $report[$real] = $report[$alias];
                                                unset($report[$alias]);
                                            }
                                        }
                                    }
                                    /*
                                     * Emergency fix for major false positives from shadowserver feed
                                     * This only happens under very specific conditions and will be filtered out
                                     * as specific as possible.
                                     */
                                    if ($this->feedName == 'spam_url') {
                                        $urlFilter = '/([a-zA-Z]{3,5}.[a-zA-Z]{3,5}.com)/';
                                        if ($report['src_geo'] == 'RU' &&
                                            $report['url'] == "http://{$report['host']}" &&
                                            $report['src_asn'] == "8402" &&
                                            preg_match($urlFilter, $report['host'], $filterMatches)
                                        ) {
                                            continue;
                                        }
                                    }

                                    /*
                                     * Legacy 3.x fix for migrations.
                                     *
                                     * This resolves shadowserver errors where the CSV was send in duplicate resulting
                                     * in the header fields being used as data. If the header is detected the row can
                                     * be skipped safely
                                     */
                                    if ($report['ip'] === 'ip') {
                                        continue;
                                    }

                                    // Sanity check
                                    if ($this->hasRequiredFields($report) === true) {
                                        // incident has all requirements met, filter and add!
                                        $report = $this->applyFilters($report);

                                        $incident = new Incident();
                                        $incident->source = config("{$this->configBase}.parser.name");
                                        $incident->source_id = false;
                                        $incident->ip = $report['ip'];
                                        $incident->domain = false;
                                        $incident->class =
                                            config("{$this->configBase}.feeds.{$this->feedName}.class");
                                        $incident->type =
                                            config("{$this->configBase}.feeds.{$this->feedName}.type");
                                        $incident->timestamp = strtotime($report['timestamp']);
                                        $incident->information = json_encode($report);

                                        // some rows have a domain, which is an optional column we want to register
                                        switch ($this->feedName) {
                                            case "spam_url":
                                                if (isset($report['url'])) {
                                                    $incident->domain = getDomain($report['url']);
                                                }
                                                break;
                                            case "ssl_scan":
                                                if (isset($report['subject_common_name'])) {

                                                    /*
                                                     * Common name does not add http://, but that is required for
                                                     * the domain helper check so lets add it manually
                                                     */
                                                    $testurl = "http://{$report['subject_common_name']}";

                                                    $incident->domain = getDomain($testurl);
                                                }
                                                break;
                                            case "compromised_website":
                                                if (isset($report['http_host'])) {
                                                    $incident->domain = getDomain($report['http_host']);
                                                }
                                                break;
                                        }

                                        $this->incidents[] = $incident;

                                    } //End hasRequired fields
                                } // End foreach report loop
                            } // End isKnown & isEnabled
                        } else { // Pregmatch failed to get feedName from attachment
                            $this->warningCount++;
                        }
                    } else { // Attached file is not a CSV within a ZIP file
                        $this->warningCount++;
                    }
                } // End each file in ZIP attachment loop
            } // End if not a ZIP attachment
        } // End foreach attachment loop

        return $this->success();
    }
}
