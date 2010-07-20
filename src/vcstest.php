<?php

include('classes/VirusChecker.php');
$filename = $argv[1];
print "Checking file for viruses: $filename\n";
$vc = new VirusChecker($filename, 'ClamScan,VirusTotalHash');
$retval = $vc->scan();
if ($retval) {
    print "Virus found\n";
} else {
    print "File is virus free!\n";
}

