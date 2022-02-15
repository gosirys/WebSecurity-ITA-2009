# WebSecurity-ITA-2009
A training course I wrote on Web Security, Exploit Development and Source Code Auditing In January 2009.

Keep in mind that this course has never been updated and has remained untouched ever since it was completed 13 years ago, it is also written in Italian.

Whilst not all the material is still relevant today (RFI, LFI log poisoning), most of the other vulnerability classes presented still are. 

Publishing it as "Safe Keeping" for Memorabilia/Nostalgia days.


# Index

- [Web Security](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#web-security)
- [Indice](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#indice)
- [Prefaccia](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#prefaccia)
- [Vulnerabilità degli Include/Require](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#vulnerabilità-degli-include-require)
  - [Remote File Inclusion](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#remote-file-inclusion)
    - [Analisi di codice](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#analisi-di-codice)
    - [Sfruttare la falla](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#sfruttare-la-falla)
    - [Prevenzione](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#prevenzione)
  - [Local File Inclusion (LFI)](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#local-file-inclusion-lfi)
    - [Analisi di codice](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#analisi-di-codice)
    - [Sfruttare la falla](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#sfruttare-la-falla)
    - [Prevenzione](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#prevenzione)
- [Vulnerabilità di tipo SQL Injection](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#vulnerabilità-di-tipo-sql-injection)
  - [Union-based SQL Injection](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#union-based-sql-injection)
  - [Blind SQL Injection](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#blind-sql-injection)
  - [Live SQL Injection Auditing](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#live-sql-injection-auditing)
  - [Prevenzione](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#prevenzione)
- [Vulnerabilità legate al Logging](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#vulnerabilità-legate-al-logging)
  - [Authority Bypass via SQLi](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#authority-bypass-via-sqli)
    - [Prevenzione](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#prevenzione)
  - [Insecure Cookie Handling (ICH)](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#insecure-cookie-handling-ich)
    - [Prevenzione](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#prevenzione)
- [Arbitrary File Upload](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#arbitrary-file-upload)
  - [Analisi di codice](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#analisi-di-codice)
  - [Sfruttare la falla](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#sfruttare-la-falla)
    - [Content-type bypass](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#content-type-bypass)
    - [Nascondere codice PHP in una immagine valida](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#nascondere-codice-php-in-una-immagine-valida)
  - [Prevenzione](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#prevenzione)
- [Vulnerabilità di tipo Cross Site Scripting (XSS)](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#vulnerabilità-di-tipo-cross-site-scripting-xss)
  - [Permanent Cross-Site Scripting](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#permanent-cross-site-scripting)
  - [Reflected Cross-Site Scripting](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#reflected-cross-site-scripting)
  - [Exploiting XSS con Token Stealing](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#exploiting-xss-con-token-stealing)
  - [Prevenzione](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#prevenzione)
- [Remote Command Execution (RCE)](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#remote-command-execution-rce)
  - [Analisi di codice](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#analisi-di-codice)
    - [Caso "Diretto" di RCE](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#caso-diretto-di-rce)
    - [Casi "Indiretti" di RCE](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#casi-indiretti-di-rce)
  - [Sfruttare la falla](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#sfruttare-la-falla)
    - [Caso "Diretto" di RCE](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#caso-diretto-di-rce)
    - [Casi "Indiretti" di RCE](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#casi-indiretti-di-rce)
  - [Prevenzione](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#prevenzione)
    - [Caso "Diretto" di RCE](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#caso-diretto-di-rce)
    - [Casi "Indiretti" di RCE](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#casi-indiretti-di-rce)
- [Vari Exploit e Spiegazioni](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#vari-exploit-e-spiegazioni)
  - [LinPHA Photo Gallery RCE](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#linpha-photo-gallery-rce)
  - [phosheezy RCE](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#phosheezy-rce)
  - [PhotoStand RCE](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#photostand-rce)
  - [Da SQL Injection A RCE](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#da-sql-injection-a-rce)
- [Conclusione](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/#conclusione)
 
# Content

The content is available in the [Wiki](https://github.com/gosirys/WebSecurity-ITA-2009/wiki/) page.
