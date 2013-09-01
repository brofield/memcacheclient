set VERSION=2.1

set SEVENZIP="C:\Program Files\7-Zip\7z.exe"

FOR /F "tokens=*" %%G IN ('DIR /AD /B /S lib*') DO (
    DEL /S /Q "%%G"
    RD "%%G"
)
FOR /F "tokens=*" %%G IN ('DIR /AD /B /S _upgrade*') DO (
    DEL /S /Q "%%G"
    RD "%%G"
)
FOR /F "tokens=*" %%G IN ('DIR /AD /B /S Debug*') DO (
    DEL /S /Q "%%G"
    RD "%%G"
)
FOR /F "tokens=*" %%G IN ('DIR /AD /B /S Release*') DO (
    DEL /S /Q "%%G"
    RD "%%G"
)
DEL /Q "memcacheclient.ncb"
ATTRIB -H "memcacheclient.suo*"
DEL /Q "memcacheclient.suo*" 
DEL /Q "memcacheclient.opt"
DEL /Q "*.sln.old" "*.vcproj.*.user" "*.vcproj.*.old" "upgradelog.xml"
START "Generate documentation" /WAIT memcacheclient.doxy
cd ..
del memcacheclient-%VERSION%.zip
%SEVENZIP% a -tzip -r- -x!memcacheclient\.svn memcacheclient-%VERSION%.zip memcacheclient\*
del memcacheclient-doc.zip
%SEVENZIP% a -tzip -r memcacheclient-doc.zip memcacheclient-doc\*
cd memcacheclient
