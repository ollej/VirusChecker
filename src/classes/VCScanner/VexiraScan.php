<?php
/*
Copyright 2010 Olle Johansson. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are
permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice, this list of
      conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice, this list
      of conditions and the following disclaimer in the documentation and/or other materials
      provided with the distribution.
*/

/**
 * VirusChecker scanner plugin to check for viruses using Vexira Antivirus scanner..
 * @author Olle@Johansson.com
 */
class VCScanner_VexiraScan implements VCScanner
{
    /**
     * Runs clamscan on the given file.
     */
    public function scan($filename) {
        $output = array();
        $lastline = exec('/usr/share/vascan/vascan --action=skip -qq ' . escapeshellarg($filename) . ' 2> /dev/null', $output, $retval);
        $output = implode('', $output);
        #print "retval: $retval\nlastline: $lastline\noutput: $output\n";
        if ($retval === 0 || empty($output) || strpos($output, ' found: ') === false) {
            return 0;
        } else {
            return 1;
        }
    }
}
