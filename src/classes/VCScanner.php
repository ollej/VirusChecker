<?php
/**
 * VCScanner interface for VirusChecker scanner plugins.
 * @author Olle@Johansson.com
 */

interface VCScanner
{
    public function scan($filename);
}

