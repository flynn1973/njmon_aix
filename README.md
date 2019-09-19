# njmon

The Code in this Repo is not in sync with the original njmon, and is not affilited with the original Author.
The NG (New Generation) Directory contains some Improvements/Changes which reflects my personal needs.

njmon is like nmon but collects a lot more performance and configuration data and outputs in JSON format 
ready for immediate uploading to a performance stats database for near real-time graphing by online graphing tools. 
There is a version of njmon for AIX and another njmon for Linux. 

- Uses the AIX libperfstat to extract the performance stats
- Roughly: 600 stats for AIX, an additional 55 for the Virtual I/O Server and a further 35, if running a VIOS Shared Storage Pool.

(C) Copyright 2018 Nigel Griffiths


[Official NJMON Site](http://nmon.sourceforge.net/pmwiki.php?n=Site.Njmon)

![](njmon.png)
