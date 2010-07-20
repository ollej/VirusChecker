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

