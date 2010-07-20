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
 * VirusChecker scanner plugin to check for viruses using clamscan.
 * @author Olle@Johansson.com
 */
class VCScanner_ClamScan implements VCScanner
{
    /**
     * Runs clamscan on the given file.
     */
    public function scan($filename) {
        exec('clamscan --no-summary --infected --scan-archive=yes ' . escapeshellarg($filename), $output = array(), $retval);
        if ($retval === 0) {
            return 0;
        } else if ($retval === 1) {
            return 1;
        } else {
            throw new Exception("VirusChecker ClamScan encountered an error ($retval):\n" . implode('', $output));
        }
    }
}
