<?php
/**
 * VirusChecker scanner plugin to check file checksum against Comodo
 * @author Olle@Johansson.com
 */

class VCScanner_ComodoHash implements VCScanner
{
    const URL = 'http://camas.comodo.com/cgi-bin/submit';
    const GET = 1;
    const POST = 2;
    const HASH = 'SHA256';

    /**
     * Posts the MD5 hash of given file to VirusTotal and parses the resulting page to see if it is a known virus file.
     */
    public function scan($filename) {
        $hash = hash_file(VCScanner_ComodoHash::HASH, $filename);
	#$hash = '38549cfea4e1a97ca25680d24cf0e63cdae2c9b55988e8ffe7df1dba005b60a2';
        $data = $this->getUrl(
            VCScanner_ComodoHash::URL . '?file=' . $hash . '&iframe=', 
            VCScanner_ComodoHash::GET
        );
        if (!$data) {
            #throw new Exception("VirusTotal.com request didn't return any data!");
			return 0;
        }
        if ($this->parsePage($data)) {
            return 1;
        } else {
            return 0;
        }
    }

    /**
     * Parses the given string to see if a virus has been found.
     * @param string $data String to check for virus information.
     */
    private function parsePage($data) {
	$re = '<TABLE><TR><TH>Auto Analysis Verdict</TH></TR><TR bgcolor="([^"]+)"><TD>([^\<]*)</TD></TR></TABLE>';
        $matches = array();
        #print "data:\n$data\n";
        if (preg_match("#$re#", $data, $matches)) {
            #print "Matches: " . print_r($matches, true);
            $verdict = trim($matches[2]);
            if ($verdict == "Suspicious+") {
                return true;
            }
        }
        return false;
    }

    /**
     * Gets the content of the $url using CURL.
     * @param string $url URL to download.
     * @param int HTTP method to use.
     * @param array $params List of POST parameters to send.
     */
    private function getUrl($url, $method=VCScanner_ComodoHash::GET, $params=array()) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1); 
        curl_setopt($ch, CURLINFO_HEADER_OUT, true); 
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        if ($method === VCScanner_ComodoHash::POST) {
            curl_setopt($ch, CURLOPT_POST, true);
            $encoded_params = $this->encodeUrlParams($params);
            #print "params: $encoded_params\n";
            curl_setopt($ch, CURLOPT_POSTFIELDS, $encoded_params);
        }
        $output = curl_exec($ch);
        #print "HTTP Status: " . curl_getinfo($ch, CURLINFO_HTTP_CODE) . "\n";
        #print "HEADERS:\n" . curl_getinfo($ch, CURLINFO_HEADER_OUT) . "\n";
        curl_close($ch);
        return $output;
    }

    /**
     * Encodes $params array into URL paramaters.
     * @param array $params Associative array with key/value pairs to encode into URL paramaters.
     */
    private function encodeUrlParams($params) {
        $p = "";
        foreach ($params as $k => $v) {
            $p .= $p ? '&' : '';
            $p .= "$k=" . urlencode($v);
        }
        return $p;
    }
}

