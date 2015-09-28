<?php

namespace AbuseIO\Parsers;

use Chumper\Zipper\Zipper;
use Ddeboer\DataImport\Reader;
use Ddeboer\DataImport\Writer;
use Ddeboer\DataImport\Filter;
use SplFileObject;
use Log;
use ReflectionClass;

class Shadowserver extends Parser
{
    public $parsedMail;
    public $arfMail;

    /**
     * Create a new Shadowserver instance
     */
    public function __construct($parsedMail, $arfMail)
    {
        $this->parsedMail = $parsedMail;
        $this->arfMail = $arfMail;
    }

    /**
     * Parse attachments
     * @return Array    Returns array with failed or success data
     *                  (See parser-common/src/Parser.php) for more info.
     */
    public function parse()
    {
        // Generalize the local config based on the parser class name.
        $reflect = new ReflectionClass($this);
        $this->configBase = 'parsers.' . $reflect->getShortName();

        Log::info(
            get_class($this). ': Received message from: '.
            $this->parsedMail->getHeader('from') . " with subject: '" .
            $this->parsedMail->getHeader('subject') . "' arrived at parser: " .
            config("{$this->configBase}.parser.name")
        );

        $events = [ ];

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
                        preg_match("~(?:\d{4})-(?:\d{2})-(?:\d{2})-(.*)-[^\-]+-[^\-]+.csv~i", $compressedFile, $feed);
                        $this->feedName = $feed[1];

                        if (!$this->isKnownFeed()) {
                            return $this->failed(
                                "Detected feed {$this->feedName} is unknown."
                            );
                        }

                        if (!$this->isEnabledFeed()) {
                            continue;
                        }

                        $csvReports = new Reader\CsvReader(new SplFileObject($this->tempPath . $compressedFile));
                        $csvReports->setHeaderRowNumber(0);

                        foreach ($csvReports as $report) {
                            if (!$this->hasRequiredFields($report)) {
                                return $this->failed(
                                    "Required field {$this->requiredField} is missing or the config is incorrect."
                                );
                            }

                            $report = $this->applyFilters($report);

                            $event = [
                                'source'        => config("{$this->configBase}.parser.name"),
                                'ip'            => $report['ip'],
                                'domain'        => false,
                                'uri'           => false,
                                'class'         => config("{$this->configBase}.feeds.{$this->feedName}.class"),
                                'type'          => config("{$this->configBase}.feeds.{$this->feedName}.type"),
                                'timestamp'     => strtotime($report['timestamp']),
                                'information'   => json_encode($report),
                            ];

                            // some rows have a domain, which is an optional column we want to register seperatly
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
                                        // TODO - Validate domain name if it actually exist within the domain backend
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

                            $events[] = $event;
                        }
                    }
                }
            }
        }

        return $this->success($events);
    }
}
