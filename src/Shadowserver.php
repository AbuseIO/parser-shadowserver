<?php

namespace AbuseIO\Parsers;

use Chumper\Zipper\Zipper;
use Ddeboer\DataImport\Reader;
use Ddeboer\DataImport\Writer;
use Ddeboer\DataImport\Filter;
use SplFileObject;

class Shadowserver extends Parser
{
    /**
     * Create a new Shadowserver instance
     */
    public function __construct($parsedMail, $arfMail)
    {
        parent::__construct($parsedMail, $arfMail, $this);
    }

    /**
     * Parse attachments
     * @return Array    Returns array with failed or success data
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

                                    // Sanity check
                                    if ($this->hasRequiredFields($report) === true) {
                                        // Event has all requirements met, filter and add!
                                        $report = $this->applyFilters($report);

                                        $this->events[] = [
                                            'source'        => config("{$this->configBase}.parser.name"),
                                            'ip'            => $report['ip'],
                                            'domain'        => false,
                                            'uri'           => false,
                                            'class'         => config(
                                                "{$this->configBase}.feeds.{$this->feedName}.class"
                                            ),
                                            'type'          => config(
                                                "{$this->configBase}.feeds.{$this->feedName}.type"
                                            ),
                                            'timestamp'     => strtotime($report['timestamp']),
                                            'information'   => json_encode($report),
                                        ];

                                        // some rows have a domain, which is an optional column we want to register
                                        switch ($this->feedName) {
                                            case "spam_url":
                                                if (isset($report['url'])) {
                                                    $urlInfo = parse_url($report['url']);

                                                    $event['domain'] = $urlInfo['host'];
                                                    $event['uri'] = $urlInfo['path'];
                                                }
                                                break;
                                            case "ssl_scan":
                                                if (isset($report['subject_common_name'])) {
                                                    $event['domain'] = $report['subject_common_name'];
                                                    $event['uri'] = "/";
                                                }
                                                break;
                                            case "compromised_website":
                                                if (isset($report['http_host'])) {
                                                    $event['domain'] = $report['http_host'];
                                                    $event['uri'] = "/";
                                                }
                                                break;
                                            case "botnet_drone":
                                                if (isset($report['cc_dns']) && isset($report['url'])) {
                                                    $event['domain'] = $report['cc_dns'];
                                                    $event['uri'] = str_replace("//", "/", "/" . $report['url']);
                                                }
                                                break;
                                        }

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
