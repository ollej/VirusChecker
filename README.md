VirusChecker
============

A PHP virus checker class with plugins for external integrations.

License
-------
Released under the BSD 2-clause license.

Requirements
------------
 * PHP 5
 * ClamAV (to use the ClamScan plugin)
 * Curl PHP extension (to use the VirusTotalHash plugin)

Usage
-----
This is not a standalone script. It is a generic class that can easily be integrated into other systems.
Place the classes directory into your include path. Then just instantiate a class object with the path
to the file to check. The second parameter is a string with a comma-separated list of the plugins to
run.

    $vc = new VirusChecker('/path/to/file', 'ClamScan,VirusTotalHash');
    if ($vc->scan()) {
        print "Virus found\n";
    } else {
        print "File is virus free!\n";
    }

The second parameter can also be a config object, where the list of plugins is available in the
attribute "viruscheckers".

When the scan() method is called, all configured plugins will be called. If one of them reports
the file as a virus, the scan() method will return true.

Plugins
-------
It's possible to add new plugins to integrate other virus checkers. Just create a new file in
the VCScanner directory which contains a class with the same name as the file, but with 
"VCScanner_" prepended. The class must implement the VCScanner interface and should
contain a public method called "scan". This method will be called with the filename as the
only parameter, and if the method returns 1, the file is considered to be a virus.

    class VCScanner_PluginName implements VCScanner
    {
        public function scan($filename) {
            if (fileContainsVirus($filename)) {
                return 1;
            } else {
                return 0;
            }
        }
    }


VirusTotalHash Plugin
---------------------
This plugin generates an MD5 hash from the file and checks it on the VirustTotal.com Hash Search service.

ClamScan Plugin
---------------
Runs the "clamscan" command line program from the ClamAV package to check the virus against the latest
virus definition list.


vcstest.php script
------------------
The vcstest.php script is a simple script to test the VirusChecker class. It can also be used to
check for viruses in specific files.

Just run it from the command line and list all the files to check on the command line as arguments
to the script.

