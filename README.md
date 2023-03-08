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


> 1. Download [libjson-glib-1.0.dll][dl1] to `C:\Program Files\Pidgin`
> 2. Download [libfacebook.dll][dl2] to `C:\Program Files\Pidgin\plugins` (note: new url as of 2019)
> 3. See: [Basic Usage](Home#basic-usage)
> 
> Notes:
>   - `Program Files` will be `Program Files (x86)` on 64-bit Windows.
>   - The `libfacebook.dll` above is an [automated][l1] build.
> 
[fp]: https://github.com/dequis/purple-facebook/wiki/Installing-on-Windows
[dl1]: https://github.com/dequis/purple-facebook/releases/download/downloads/libjson-glib-1.0.dll
[dl2]: https://dequis.org/libfacebook.dll
[l1]: https://travis-ci.org/dequis/purple-facebook
