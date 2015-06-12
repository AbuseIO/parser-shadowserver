<?php

namespace AbuseIO\Parsers;

Use AbuseIO\Parsers\Parser;
Use Log;

class Shadowserver extends Parser
{

    public $parsedMail;
    public $arfMail;
    public $config;

    public function __construct($parsedMail, $arfMail, $config = 'bart')
    {

        $this->configFile = __DIR__ . '/../config/' . basename(__FILE__);
        $this->parsedMail = $parsedMail;
        $this->arfMail = $arfMail;
        $this->config = $config;

        parent::__construct();

    }

    public function parse()
    {
        $parsedMail = $this->parsedMail;
        $arfMail = $this->arfMail;
        $config = $this->config;

        Log::info(get_class($this).': Received message from: '. $parsedMail->getHeader('from') . ' with subject: \'' . $parsedMail->getHeader('subject') . '\' arrived at parser: ' . $config['parser']['name']);


        /*
         * Returns with:
         * [
         * 'errorStatus' => $boolean required
         * 'errorMessage' => $string required if errorStatus is true
         * 'data' => $array required if errorStatus is false
         * ]
         */

        /* Legacy code:
        foreach ($message['attachments'] as $attachmentID => $attachment) {
            preg_match("~(?:\d{4})-(?:\d{2})-(?:\d{2})-(.*)-[^\-]+-[^\-]+.csv~i", $attachment, $feed);
            $feed = $feed[1];

            if (!isset($feeds[$feed])) {
                //Autodetect of classification failed - this is a config error!
                logger(LOG_ERR, __FUNCTION__ . " A configuration error was detected. An unconfigured feed ${feed} was selected for parsing");
                logger(LOG_WARNING, __FUNCTION__ . " FAILED message from ${source} subject ${message['subject']}");
                return false;
            } else if (in_array($feed, $feed_ignore)) {
                logger(LOG_INFO, __FUNCTION__ . " IGNORING message from ${source} subject ${message['subject']}");
                return true;
            }

            $class = $feeds[$feed]['class'];
            $type = $feeds[$feed]['type'];
            $fields = explode(" ", $feeds[$feed]['fields']);
            $reports = csv_to_array("${message['store']}/${attachmentID}/${attachment}");

            if (!is_array($reports)) {
                logger(LOG_ERR, __FUNCTION__ . " A parser error was detected. Will not try to continue to parse this e-mail");
                logger(LOG_WARNING, __FUNCTION__ . " FAILED message from ${source} subject ${message['subject']}");
                return false;
            }

            foreach ($reports as $id => $report) {
                $information = array();
                foreach ($fields as $field) {
                    if (!empty($report[$field])) {
                        $information[$field] = $report[$field];
                    }
                }

                $outReport = array(
                    'source' => $source,
                    'ip' => $report['ip'],
                    'class' => $class,
                    'type' => $type,
                    'timestamp' => strtotime($report['timestamp']),
                    'information' => $information
                );

                //These reports have a domain, which we want to register seperatly
                if ($feed == "spam_url") {
                    $url_info = parse_url($report['url']);

                    $outReport['domain'] = $url_info['host'];
                    $outReport['uri'] = $url_info['path'];
                }
                if ($feed == "ssl_scan") {
                    $outReport['domain'] = $report['subject_common_name'];
                    $outReport['uri'] = "/";
                }
                if ($feed == "compromised_website") {
                    $outReport['domain'] = $report['http_host'];
                    $outReport['uri'] = "/";
                }
                if ($feed == "botnet_drone") {
                    $outReport['domain'] = $report['cc_dns'];
                    $outReport['uri'] = str_replace("//", "/", "/" . $report['url']);
                }

                $reportID = reportAdd($outReport);
                if (!$reportID) return false;
                if (KEEP_EVIDENCE == true && $reportID !== true) {
                    evidenceLink($message['evidenceid'], $reportID);
                }

            }
        }
        */

        $events = [ ];

        return
            [
                'errorStatus'   => false,
                'errorMessage'  => 'test',
                'data'          => $events,
            ];

    }
}
