# njmon

The Code in this Repo is not compatible with the original njmon. I will try my best to cherrypick 
important changes from upstream.
The NG (New Generation) Directory contains a improved Version of the AIX specific njmon and related Tools.

## Modifications

injector:
- multithreaded server design
- receive message size before actual data to avoid corrupted/incomplete transfers
- better logging facility (slog)
- close socket after transfer to avoid hundreds of open connections.

njmon:
- send message size before data
- close socket after transfer
- free all allocated memory to avoid paging space kills and machine crashes

njmon is like nmon but collects a lot more performance and configuration data and outputs in JSON format 
ready for immediate uploading to a performance stats database for near real-time graphing by online graphing tools. 
There is a version of njmon for AIX and another njmon for Linux. 

- Uses the AIX libperfstat to extract the performance stats
- Roughly: 600 stats for AIX, an additional 55 for the Virtual I/O Server and a further 35, if running a VIOS Shared Storage Pool.

(C) Copyright 2018 Nigel Griffiths


[Official NJMON Site](http://nmon.sourceforge.net/pmwiki.php?n=Site.Njmon)

![](njmon.png)
