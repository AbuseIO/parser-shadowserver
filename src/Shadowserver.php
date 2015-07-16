<?php

namespace AbuseIO\Parsers;

use AbuseIO\Parsers\Parser;
use Chumper\Zipper\Zipper;
use Ddeboer\DataImport\Reader;
use Ddeboer\DataImport\Writer;
use Ddeboer\DataImport\Filter;
use SplFileObject;
use Illuminate\Filesystem\Filesystem;
use Uuid;
use Log;

class Shadowserver extends Parser
{

    public $parsedMail;
    public $arfMail;
    public $config;

    public function __construct($parsedMail, $arfMail, $config = false)
    {

        $this->configFile = __DIR__ . '/../config/' . basename(__FILE__);

        $this->parsedMail = $parsedMail;
        $this->arfMail = $arfMail;
        $this->config = $config;

    }

    /*
     * Returns with:
     * [
     * 'errorStatus' => $boolean required
     * 'errorMessage' => $string required if errorStatus is true
     * 'data' => $array required if errorStatus is false
     * ]
     */
    public function parse()
    {

        Log::info(
            get_class($this).': Received message from: '. $this->parsedMail->getHeader('from')
            . ' with subject: \'' . $this->parsedMail->getHeader('subject')
            . '\' arrived at parser: ' . $this->config['parser']['name']
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
                        // For each CSV file we find, we are going to do magic (however they useally only send 1 zip)
                        preg_match("~(?:\d{4})-(?:\d{2})-(?:\d{2})-(.*)-[^\-]+-[^\-]+.csv~i", $compressedFile, $feed);
                        $feed = $feed[1];

                        if (!isset($this->config['feeds'][$feed])) {
                            // Todo - Delete tempdir
                            return $this->failed("Detected feed ${feed} is unknown. No sense in trying to parse.");
                        } else {
                            $feedConfig = $this->config['feeds'][$feed];
                        }

                        if ($feedConfig['enabled'] !== true) {
                            // Todo - Delete tempdir
                            return $this->success(
                                "Detected feed ${feed} has been disabled by configuration. No sense in trying to parse."
                            );
                        }

                        $csvReader = new Reader\CsvReader(new SplFileObject($tempPath . $compressedFile));
                        $csvReader->setHeaderRowNumber(0);

                        foreach ($csvReader as $row) {
                            // Build a information blob with selected fields from config and check if those
                            // columns actually exist within the CSV

                            $infoBlob = [];

                            foreach ($feedConfig['fields'] as $column) {
                                if (!isset($row[$column])) {
                                    return $this->failed(
                                        "Required field ${column} is missing in the CSV or config is incorrect."
                                    );
                                } else {
                                    $infoBlob[$column] = $row[$column];
                                }
                            }

                            // Basic required columns that reside in every CSV

                            $requiredColumns = [
                                'ip',
                                'timestamp',
                            ];

                            foreach ($requiredColumns as $column) {
                                if (!isset($row[$column])) {
                                    return $this->failed(
                                        "Required field ${column} is missing in the CSV or config is incorrect."
                                    );
                                }
                            }

                            $event = [
                                'source'        => $this->config['parser']['name'],
                                'ip'            => $row['ip'],
                                'domain'        => false,
                                'class'         => $feedConfig['class'],
                                'type'          => $feedConfig['type'],
                                'timestamp'     => strtotime($row['timestamp']),
                                'information'   => json_encode($infoBlob),
                            ];

                            // some rows have a domain, which is an optional column we want to register seperatly
                            if ($feed == "spam_url") {
                                if (isset($row['url'])) {
                                    $urlInfo = parse_url($row['url']);

                                    $event['domain'] = $urlInfo['host'];
                                    $event['uri'] = $urlInfo['path'];
                                }
                            }

                            if ($feed == "ssl_scan") {
                                if (isset($row['subject_common_name'])) {
                                    // TODO - Validate domain name if it actually exist within the domain backend
                                    $event['domain'] = $row['subject_common_name'];
                                    $event['uri'] = "/";
                                }
                            }

                            if ($feed == "compromised_website") {
                                if (isset($row['http_host'])) {
                                    $event['domain'] = $row['http_host'];
                                    $event['uri'] = "/";
                                }
                            }

                            if ($feed == "botnet_drone") {
                                if (isset($row['cc_dns']) && isset($row['url'])) {
                                    $event['domain'] = $row['cc_dns'];
                                    $event['uri'] = str_replace("//", "/", "/" . $row['url']);
                                }
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
