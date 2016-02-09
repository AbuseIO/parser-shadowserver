<?php

namespace AbuseIO\Parsers;

use AbuseIO\Models\Incident;
use Chumper\Zipper\Zipper;
use Ddeboer\DataImport\Reader;
use SplFileObject;

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
        foreach ($this->parsedMail->getAttachments() as $attachment) {
            if (strpos($attachment->filename, '.zip') !== false
                && $attachment->contentType == 'application/octet-stream'
            ) {
                $zip = new Zipper;

                if (!$this->createWorkingDir()) {
                    return $this->failed(
                        "Unable to create working directory"
                    );
                }

                file_put_contents($this->tempPath . $attachment->filename, $attachment->getContent());

                $zip->zip($this->tempPath . $attachment->filename);
                $zip->extractTo($this->tempPath);

                foreach ($zip->listFiles() as $index => $compressedFile) {
                    if (strpos($compressedFile, '.csv') !== false) {
                        // For each CSV file we find, we are going to do magic (however they usually only send 1 zip)
                        if (preg_match(
                            "~(?:\d{4})-(?:\d{2})-(?:\d{2})-(.*)-[^\-]+-[^\-]+.csv~i",
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

                                    // Sanity check
                                    if ($this->hasRequiredFields($report) === true) {
                                        // incident has all requirements met, filter and add!
                                        $report = $this->applyFilters($report);

                                        $incident = new Incident();
                                        $incident->source      = config("{$this->configBase}.parser.name");
                                        $incident->source_id   = false;
                                        $incident->ip          = $report['ip'];
                                        $incident->domain      = false;
                                        $incident->uri         = false;
                                        $incident->class       =
                                            config("{$this->configBase}.feeds.{$this->feedName}.class");
                                        $incident->type        =
                                            config("{$this->configBase}.feeds.{$this->feedName}.type");
                                        $incident->timestamp   = strtotime($report['timestamp']);
                                        $incident->information = json_encode($report);

                                        // some rows have a domain, which is an optional column we want to register
                                        switch ($this->feedName) {
                                            case "spam_url":
                                                if (isset($report['url'])) {
                                                    $urlInfo = parse_url($report['url']);

                                                    $incident->domain = $urlInfo['host'];
                                                    $incident->uri = $urlInfo['path'];
                                                }
                                                break;
                                            case "ssl_scan":
                                                if (isset($report['subject_common_name'])) {
                                                    if (preg_match(
                                                        "/[a-z0-9\-]{1,63}\.[a-z\.]{2,6}$/",
                                                        parse_url(
                                                            'http://'.$report['subject_common_name'],
                                                            PHP_URL_HOST
                                                        ),
                                                        $_domain_tld
                                                    )) {
                                                        $incident->domain = $_domain_tld[0];
                                                        $incident->uri = "/";
                                                    }
                                                }
                                                break;
                                            case "compromised_website":
                                                if (isset($report['http_host'])) {
                                                    $incident->domain = $report['http_host'];
                                                    $incident->uri = "/";
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
