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
        $configBase = 'parsers.' . $reflect->getShortName();

        Log::info(
            get_class($this). ': Received message from: '.
            $this->parsedMail->getHeader('from') . " with subject: '" .
            $this->parsedMail->getHeader('subject') . "' arrived at parser: " .
            config("{$configBase}.parser.name")
        );

        $events = [ ];

        foreach ($this->parsedMail->getAttachments() as $attachment) {
            if (strpos($attachment->filename, '.zip') !== false
                && $attachment->contentType == 'application/octet-stream'
            ) {
                $zip        = new Zipper;
                $filesystem = new Filesystem;
                $tempUUID   = Uuid::generate(4);
                $tempPath   = "/tmp/${tempUUID}/";

                if (!$filesystem->makeDirectory($tempPath)) {
                    return $this->failed("Unable to create directory ${tempPath}");
                }

                file_put_contents($tempPath . $attachment->filename, $attachment->getContent());

                $zip->zip($tempPath . $attachment->filename);
                $zip->extractTo($tempPath);

                foreach ($zip->listFiles() as $index => $compressedFile) {
                    if (strpos($compressedFile, '.csv') !== false) {
                        // For each CSV file we find, we are going to do magic (however they usually only send 1 zip)
                        preg_match("~(?:\d{4})-(?:\d{2})-(?:\d{2})-(.*)-[^\-]+-[^\-]+.csv~i", $compressedFile, $feed);
                        $feedName = $feed[1];

                        // If this type of feed does not exist, throw error
                        if (empty(config("{$configBase}.feeds.{$feedName}"))) {
                            $filesystem->deleteDirectory($tempPath);
                            return $this->failed(
                                "Detected feed {$feedName} is unknown."
                            );
                        }

                        // If the feed is disabled, then continue on to the next feed or attachment
                        // its not a 'fail' in the sense we should start alerting as it was disabled
                        // by design or user configuration
                        if (config("{$configBase}.feeds.{$feedName}.enabled") !== true) {
                            continue;
                        }

                        $csvReader = new Reader\CsvReader(new SplFileObject($tempPath . $compressedFile));
                        $csvReader->setHeaderRowNumber(0);

                        foreach ($csvReader as $row) {
                            $csv_columns = array_filter(config("{$configBase}.feeds.{$feedName}.fields"));
                            if (count($csv_columns) > 0) {
                                foreach ($csv_columns as $column) {
                                    if (!isset($row[$column])) {
                                        return $this->failed(
                                            "Required field ${column} is missing in the CSV or config is incorrect."
                                        );
                                    }
                                }
                            }

                            $filter_columns = array_filter(config("{$configBase}.feeds.{$feedName}.filters"));
                            foreach ($filter_columns as $column) {
                                if (!empty($row[$column])) {
                                    unset($row[$column]);
                                }
                            }

                            $event = [
                                'source'        => config("{$configBase}.parser.name"),
                                'ip'            => $row['ip'],
                                'domain'        => false,
                                'uri'           => false,
                                'class'         => config("{$configBase}.feeds.{$feedName}.class"),
                                'type'          => config("{$configBase}.feeds.{$feedName}.type"),
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
                $filesystem->deleteDirectory($tempPath);
            }
        }

        return $this->success($events);
    }
}
