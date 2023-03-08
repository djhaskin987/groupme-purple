This is a fork of https://notabug.org/alyssa/groupme-purple . I added some
icons, fixed the timestamps on messages so they displayed properly, and
generally just changed stuff till it worked. I'm using it actively right now,
so hit me up if there's a bug and I'll try to fix it.

To use it, just go to dev.groupme.com, log in with your groupme creds, and
get your access token from the top right of the page. That's going to be your
password when you use this pidgin plugin.

Works well enough for me :)

## Get It To Work on Windows

Download the DLL from the "Releases" page. 

Then follow the same directions as is used for the [Facebook Plugin][fp]:


> Download and extract glib:
> - Download: [glib-dev_2.28.8-1_win32.zip][dl3]
> - Download: [gettext-runtime-dev_0.18.1.1-2_win32.zip][dl4]
> - Download: [zlib-dev_1.2.5-2_win32.zip][dl5]
> - Extract all zips to `$PIDGIN_DEV_ROOT/win32-dev/glib-2.28.8`
> 
> Download and extract json-glib:
> - Download: [json-glib-0.14.tar.gz][dl6]
> - Extract to `$PIDGIN_DEV_ROOT/win32-dev/json-glib-0.14`
> 
> Compile the plugin:
> 
>     $ cd $PIDGIN_DEV_ROOT/purple-facebook #-<version>
>     $ ./update  # not required for dist tarballs
>     $ make -f Makefile.mingw install
>     $ cp win32-install-dir/plugins/libfacebook.dll C:/Program Files/Pidgin/plugins  # alternatively: Program Files (x86)

[fp]: https://github.com/dequis/purple-facebook/wiki/Installing-on-Windows
[dl3]: http://ftp.gnome.org/pub/gnome/binaries/win32/glib/2.28/glib-dev_2.28.8-1_win32.zip
[dl4]: http://ftp.gnome.org/pub/gnome/binaries/win32/dependencies/gettext-runtime-dev_0.18.1.1-2_win32.zip
[dl5]: http://ftp.gnome.org/pub/gnome/binaries/win32/dependencies/zlib-dev_1.2.5-2_win32.zip
[dl6]: https://github.com/jgeboski/purple-facebook/releases/download/downloads/json-glib-0.14.tar.gz
