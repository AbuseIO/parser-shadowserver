<?php

namespace AbuseIO\Parsers;

use Chumper\Zipper\Zipper;
use Ddeboer\DataImport\Reader;
use Ddeboer\DataImport\Writer;
use Ddeboer\DataImport\Filter;
use Illuminate\Filesystem\Filesystem;
use SplFileObject;
use Uuid;
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
                $zip        = new Zipper;

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
                        $feedName = $feed[1];

                        // If this type of feed does not exist, throw error
                        if (!$this->isKnownFeed($feedName)) {
                            return $this->failed(
                                "Detected feed {$feedName} is unknown."
                            );
                        }

                        // If the feed is disabled, then continue on to the next feed or attachment
                        // its not a 'fail' in the sense we should start alerting as it was disabled
                        // by design or user configuration
                        if (!$this->isEnabledFeed($feedName)) {
                            continue;
                        }

                        $csvReader = new Reader\CsvReader(new SplFileObject($this->tempPath . $compressedFile));
                        $csvReader->setHeaderRowNumber(0);

                        foreach ($csvReader as $row) {
                            if (!$this->hasRequiredFields($feedName, $row)) {
                                return $this->failed(
                                    "Required field " . $this->requiredField
                                    . " is missing in the CSV or config is incorrect."
                                );
                            }

                            // Start marker - Move this into $this->hasFilteredFields
                            $filter_columns = array_filter(config("{$this->configBase}.feeds.{$feedName}.filters"));
                            foreach ($filter_columns as $column) {
                                if (!empty($row[$column])) {
                                    unset($row[$column]);
                                }
                            }

                            // No sense in adding empty fields, so we remove them
                            foreach ($row as $field => $value) {
                                if ($value == "") {
                                    unset($row[$field]);
                                }
                            }
                            // End marker

                            $event = [
                                'source'        => config("{$this->configBase}.parser.name"),
                                'ip'            => $row['ip'],
                                'domain'        => false,
                                'uri'           => false,
                                'class'         => config("{$this->configBase}.feeds.{$feedName}.class"),
                                'type'          => config("{$this->configBase}.feeds.{$feedName}.type"),
                                'timestamp'     => strtotime($row['timestamp']),
                                'information'   => json_encode($row),
                            ];

                            // some rows have a domain, which is an optional column we want to register seperatly
                            switch ($feedName) {
                                case "spam_url":
                                    if (isset($row['url'])) {
                                        $urlInfo = parse_url($row['url']);

                                        $event['domain'] = $urlInfo['host'];
                                        $event['uri'] = $urlInfo['path'];
                                    }
                                    break;
                                case "ssl_scan":
                                    if (isset($row['subject_common_name'])) {
                                        // TODO - Validate domain name if it actually exist within the domain backend
                                        $event['domain'] = $row['subject_common_name'];
                                        $event['uri'] = "/";
                                    }
                                    break;
                                case "compromised_website":
                                    if (isset($row['http_host'])) {
                                        $event['domain'] = $row['http_host'];
                                        $event['uri'] = "/";
                                    }
                                    break;
                                case "botnet_drone":
                                    if (isset($row['cc_dns']) && isset($row['url'])) {
                                        $event['domain'] = $row['cc_dns'];
                                        $event['uri'] = str_replace("//", "/", "/" . $row['url']);
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
