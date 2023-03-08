This is a fork of https://notabug.org/alyssa/groupme-purple . I added some
icons, fixed the timestamps on messages so they displayed properly, and
generally just changed stuff till it worked. I'm using it actively right now,
so hit me up if there's a bug and I'll try to fix it.

To use it, just go to dev.groupme.com, log in with your groupme creds, and
get your access token from the top right of the page. That's going to be your
password when you use this pidgin plugin.

Works well enough for me :)

## Get It To Work on Windows

Visit the "Release" page to get the following files:
  - Put `libjson-glib-1.0.dll` in `C:\Program Files (x86)\Pidgin`
  - Put `libgroupme.dll` in `C:\Program Files (x86)\Pidgin\plugins`
  - Put `groupme16.png` in `C:\Program Files (x86)\Pidgin\pixmaps\pidgin\protocols\16\groupme.png`
  - Put `groupme22.png` in `C:\Program Files (x86)\Pidgin\pixmaps\pidgin\protocols\22\groupme.png`
  - Put `groupme48.png` in `C:\Program Files (x86)\Pidgin\pixmaps\pidgin\protocols\48\groupme.png`


## Get It To Work On Linux

For Linux, just make sure you have the development files for purple/pidgin installed, and run make; sudo make install :)

## Acknowledgements

Thanks to the legendary Alyssa Rosenzweig for writing this in the first place.
I never would have figured it out.

Thanks to the [facebook plugin][fp] author for the Windows json-glib DLL and
instructions for how to compile against json-glib :)

[fp]: https://github.com/dequis/purple-facebook/wiki/Installing-on-Windows
